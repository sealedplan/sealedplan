"""The MCP adapter, driven end to end by the SDK's in-process client."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal, cast

import pytest
from mcp.client import Client
from mcp.shared.exceptions import MCPError
from mcp_types import (
    CallToolResult,
    ElicitRequestParams,
    ElicitResult,
    InputRequiredResult,
    RequestParamsMeta,
)

from sealedplan.actions import Context, action
from sealedplan.models import (
    Applied,
    Approval,
    ApprovalScope,
    Change,
    Compensation,
    Effect,
    Plan,
    Precondition,
    Principal,
    ResourceRef,
)
from sealedplan.policy import Decision, DefaultPolicy, PolicyContext, PolicyResult
from sealedplan.preconditions import ABSENT, Observation
from sealedplan.runtime import Runtime
from sealedplan.state import State
from sealedplan.store import SqliteStore
from sealedplan_mcp import EXTENSION_ID, create_server, tool_annotations

ISSUER = "https://idp.example.com"
AGENT = Principal(id="agent", issuer=ISSUER, kind="agent")
SERVICE = Principal(id="runtime", issuer=ISSUER, kind="service")
DANA = Principal(id="dana", issuer=ISSUER, kind="human")


@dataclass
class Flags:
    enabled: dict[str, bool] = field(default_factory=dict)
    revision: dict[str, int] = field(default_factory=dict)

    def set(self, name: str, on: bool) -> None:
        self.enabled[name] = on
        self.revision[name] = self.revision.get(name, 0) + 1


@action("flags.set", effect=Effect.REVERSIBLE, risk="low")
class SetFlag:
    """Turn a feature flag on or off."""

    def __init__(self, flags: Flags) -> None:
        self.flags = flags

    def plan(self, ctx: Context, name: str, enabled: bool) -> Plan:
        if name not in self.flags.enabled:
            raise ValueError(f"no flag named {name}")
        ref = ResourceRef(type="example/flag", id=f"flag://{name}")
        return ctx.plan(
            summary=f"Turn {name} {'on' if enabled else 'off'}",
            changes=[Change(resource=ref, op="update", after={"enabled": enabled})],
            preconditions=[
                Precondition(
                    id="flag-revision",
                    resource=ref,
                    kind="version",
                    expect=str(self.flags.revision[name]),
                    enforcement="check_then_act",
                )
            ],
            risk="high" if name.startswith("payments.") else None,
            compensation=Compensation(
                strategy="restore",
                summary=f"Restore {name}",
                params={"enabled": self.flags.enabled[name]},
            ),
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        name = resource.id.removeprefix("flag://")
        if name not in self.flags.enabled:
            return ABSENT
        return Observation(exists=True, version=str(self.flags.revision[name]))

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        self.flags.set(plan.params["name"], plan.params["enabled"])
        return ctx.applied(plan)

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        self.flags.set(plan.params["name"], plan.compensation.params["enabled"])


class DenyKillSwitch:
    """The default policy, except that the kill switch flag is never touched."""

    def evaluate(self, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult:
        if plan.params.get("name") == "kill_switch":
            return PolicyResult(Decision.DENY, ("the kill switch is off limits",), "deny-ks")
        return DefaultPolicy().evaluate(plan, effect, ctx)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def flags() -> Flags:
    f = Flags()
    for name in ("banner", "payments.provider", "kill_switch"):
        f.set(name, False)
    return f


@pytest.fixture
def rt(flags: Flags) -> Iterator[Runtime]:
    runtime = Runtime(SqliteStore(), SERVICE, policy=DenyKillSwitch())
    runtime.register(SetFlag(flags))
    yield runtime
    runtime.store.close()


def approve(
    rt: Runtime, plan_hash: str, decision: Literal["approve", "reject"] = "approve"
) -> None:
    """What `sealedplan approve` does: record a person's decision in the store."""
    now = rt.now()
    rt.submit_approval(
        Approval(
            approval_id=f"appr-{uuid.uuid4()}",
            plan_hash=plan_hash,
            decision=decision,
            approver=DANA,
            method="cli",
            scope=ApprovalScope(),
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
        )
    )


def ext(result: CallToolResult | InputRequiredResult) -> dict[str, Any]:
    assert result.meta is not None
    value: dict[str, Any] = result.meta[EXTENSION_ID]
    return value


def mode(**options: str) -> RequestParamsMeta:
    """Request ``_meta`` selecting an explicit-mode step (§12.5)."""
    return cast(RequestParamsMeta, {EXTENSION_ID: options})


def text(result: CallToolResult) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


def pending_hash(rt: Runtime) -> str:
    [record] = rt.store.list_plans([State.PENDING_APPROVAL])
    return record.plan.plan_hash


ARGS = {"name": "payments.provider", "enabled": True}

pytestmark = pytest.mark.anyio


async def test_declares_the_extension_and_tool_hints(rt: Runtime) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        caps = client.server_capabilities
        assert caps is not None
        assert caps.extensions is not None
        declared = caps.extensions[EXTENSION_ID]
        [tool] = (await client.list_tools()).tools
    assert declared["tools"]["flags_set"] == {
        "effect": "REVERSIBLE",
        "risk": "low",
        "plan_ttl_seconds": 1800,
    }
    assert set(declared["approval_modes"]) == {"out_of_band", "explicit"}
    assert tool.name == "flags_set"
    assert set(tool.input_schema["required"]) == {"name", "enabled"}
    assert tool.annotations is not None
    assert tool.annotations.destructive_hint is False
    assert tool.annotations.read_only_hint is False


def test_annotations_follow_the_effect() -> None:
    assert tool_annotations(Effect.READ_ONLY).read_only_hint is True
    assert tool_annotations(Effect.IRREVERSIBLE).destructive_hint is True
    assert tool_annotations(Effect.COMPENSATABLE).destructive_hint is True


async def test_auto_policy_applies_at_once(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        result = await client.call_tool("flags_set", {"name": "banner", "enabled": True})
    assert not result.is_error, text(result)
    assert ext(result)["state"] == "APPLIED"
    assert ext(result)["applied"]["outcome"] == "succeeded"
    assert flags.enabled["banner"] is True


async def test_waits_for_out_of_band_approval_then_applies(rt: Runtime, flags: Flags) -> None:
    prompts: list[str] = []

    async def person(context: Any, params: ElicitRequestParams) -> ElicitResult:
        prompts.append(params.message)
        if len(prompts) == 2:  # the person runs `sealedplan approve` on the second prompt
            approve(rt, pending_hash(rt))
        return ElicitResult(action="accept")  # never counts as an approval by itself

    async with Client(create_server(rt, agent=AGENT), elicitation_callback=person) as client:
        result = await client.call_tool("flags_set", ARGS)

    assert not result.is_error, text(result)
    assert ext(result)["state"] == "APPLIED"
    assert flags.enabled["payments.provider"] is True
    assert len(prompts) == 2
    assert "sealedplan approve" in prompts[0]
    assert "does not approve" in prompts[0]


async def test_client_without_elicitation_gets_state_only(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        first = await client.session.call_tool("flags_set", ARGS, allow_input_required=True)
        assert isinstance(first, InputRequiredResult)
        assert first.input_requests is None
        assert first.request_state is not None
        plan = ext(first)["plan"]
        assert plan["plan_hash"] == pending_hash(rt)

        again = await client.session.call_tool(
            "flags_set", ARGS, request_state=first.request_state, allow_input_required=True
        )
        assert isinstance(again, InputRequiredResult)
        assert flags.enabled["payments.provider"] is False

        approve(rt, plan["plan_hash"])
        done = await client.session.call_tool(
            "flags_set", ARGS, request_state=again.request_state, allow_input_required=True
        )
    assert isinstance(done, CallToolResult)
    assert not done.is_error, text(done)
    assert flags.enabled["payments.provider"] is True


async def test_drift_after_approval_writes_nothing(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        first = await client.session.call_tool("flags_set", ARGS, allow_input_required=True)
        assert isinstance(first, InputRequiredResult)
        approve(rt, pending_hash(rt))
        flags.set("payments.provider", False)  # someone touches the flag meanwhile
        result = await client.session.call_tool(
            "flags_set", ARGS, request_state=first.request_state, allow_input_required=True
        )
    assert isinstance(result, CallToolResult)
    assert result.is_error
    assert ext(result)["state"] == "DRIFTED"
    assert ext(result)["failed_preconditions"][0]["id"] == "flag-revision"
    assert flags.enabled["payments.provider"] is False


async def test_rejected_plan_is_a_tool_error(rt: Runtime) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        first = await client.session.call_tool("flags_set", ARGS, allow_input_required=True)
        assert isinstance(first, InputRequiredResult)
        approve(rt, pending_hash(rt), decision="reject")
        result = await client.session.call_tool(
            "flags_set", ARGS, request_state=first.request_state, allow_input_required=True
        )
    assert isinstance(result, CallToolResult)
    assert result.is_error
    assert ext(result)["state"] == "REJECTED"


async def test_denied_plan_carries_hash_and_reasons(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        result = await client.call_tool("flags_set", {"name": "kill_switch", "enabled": True})
    assert result.is_error
    assert ext(result)["state"] == "DENIED"
    assert ext(result)["reasons"] == ["the kill switch is off limits"]
    assert ext(result)["plan_hash"].startswith("sha256:")
    assert flags.enabled["kill_switch"] is False


async def test_provider_error_is_a_tool_error(rt: Runtime) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        result = await client.call_tool("flags_set", {"name": "nope", "enabled": True})
    assert result.is_error
    assert "no flag named nope" in text(result)


async def test_explicit_plan_then_apply(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        planned = await client.call_tool("flags_set", ARGS, meta=mode(mode="plan"))
        assert not planned.is_error, text(planned)
        plan = planned.structured_content
        assert plan["params"] == ARGS
        assert ext(planned)["state"] == "PENDING_APPROVAL"
        assert flags.enabled["payments.provider"] is False

        approve(rt, plan["plan_hash"])
        applied = await client.call_tool(
            "flags_set",
            ARGS,
            meta=mode(mode="apply", plan_hash=plan["plan_hash"]),
        )
    assert not applied.is_error, text(applied)
    assert ext(applied)["state"] == "APPLIED"
    assert flags.enabled["payments.provider"] is True


async def test_explicit_apply_refuses_different_arguments(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        planned = await client.call_tool("flags_set", ARGS, meta=mode(mode="plan"))
        plan_hash = planned.structured_content["plan_hash"]
        approve(rt, plan_hash)
        result = await client.call_tool(
            "flags_set",
            {"name": "payments.provider", "enabled": False},
            meta=mode(mode="apply", plan_hash=plan_hash),
        )
    assert result.is_error
    assert "do not match" in text(result)
    assert rt.store.get(plan_hash).state is State.APPROVED


async def test_explicit_apply_of_pending_plan_waits(rt: Runtime) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        planned = await client.call_tool("flags_set", ARGS, meta=mode(mode="plan"))
        result = await client.session.call_tool(
            "flags_set",
            ARGS,
            meta=mode(mode="apply", plan_hash=planned.structured_content["plan_hash"]),
            allow_input_required=True,
        )
    assert isinstance(result, InputRequiredResult)


async def test_tampered_request_state_is_rejected(rt: Runtime, flags: Flags) -> None:
    async with Client(create_server(rt, agent=AGENT)) as client:
        first = await client.session.call_tool("flags_set", ARGS, allow_input_required=True)
        assert isinstance(first, InputRequiredResult)
        plan_hash = pending_hash(rt)
        approve(rt, plan_hash)
        forged = json.dumps({"plan_hash": plan_hash, "expires_at": "2999-01-01T00:00:00+00:00"})
        with pytest.raises(MCPError):
            await client.session.call_tool(
                "flags_set", ARGS, request_state=forged, allow_input_required=True
            )
        # Valid state, different arguments: the SDK's binding refuses it as well.
        with pytest.raises(MCPError):
            await client.session.call_tool(
                "flags_set",
                {"name": "payments.provider", "enabled": False},
                request_state=first.request_state,
                allow_input_required=True,
            )
    assert flags.enabled["payments.provider"] is False
