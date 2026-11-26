"""The OpenAI Agents SDK adapter, driven through a real Runner with a scripted model."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import pytest
from agents import Agent, Model, ModelResponse, RunConfig, Runner, Usage
from agents.items import ToolCallOutputItem
from agents.result import RunResult
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
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
from sealedplan.store import SqliteStore
from sealedplan_openai_agents import (
    KEY_PREFIX,
    resolve_approvals,
    sealedplan_tool,
    sealedplan_tools,
)

ISSUER = "https://idp.example.com"
AGENT = Principal(id="agent", issuer=ISSUER, kind="agent")
SERVICE = Principal(id="runtime", issuer=ISSUER, kind="service")
DANA = Principal(id="dana", issuer=ISSUER, kind="human")
T0 = datetime(2026, 11, 9, 14, 0, tzinfo=UTC)
NO_TRACING = RunConfig(tracing_disabled=True)


@dataclass
class Flags:
    enabled: dict[str, bool] = field(default_factory=dict)
    revision: dict[str, int] = field(default_factory=dict)

    def set(self, name: str, on: bool) -> None:
        self.enabled[name] = on
        self.revision[name] = self.revision.get(name, 0) + 1


@action("flags.set", effect=Effect.REVERSIBLE, risk="low")
class SetFlag:
    def __init__(self, flags: Flags) -> None:
        self.flags = flags

    def plan(self, ctx: Context, name: str, enabled: bool) -> Plan:
        """Turn a feature flag on or off."""
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
        return Observation(
            exists=True,
            version=str(self.flags.revision[name]),
            state={"enabled": self.flags.enabled[name]},
        )

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        self.flags.set(plan.params["name"], plan.params["enabled"])
        return ctx.applied(plan)

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        self.flags.set(plan.params["name"], plan.compensation.params["enabled"])


class DenyKillSwitch:
    def evaluate(self, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult:
        if plan.params.get("name") == "kill_switch":
            return PolicyResult(Decision.DENY, ("the kill switch is off limits",), "deny-ks")
        return DefaultPolicy().evaluate(plan, effect, ctx)


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now


class Scripted(Model):
    """Calls flags_set once, then answers with text once the tool has returned."""

    def __init__(self, name: str, enabled: bool = True) -> None:
        self.args = json.dumps({"name": name, "enabled": enabled})

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        items = args[1] if len(args) > 1 else kwargs["input"]
        answered = isinstance(items, list) and any(
            isinstance(i, dict) and i.get("type") == "function_call_output" for i in items
        )
        if answered:
            text = ResponseOutputText(type="output_text", text="done", annotations=[])
            out: Any = ResponseOutputMessage(
                id="msg-1", type="message", role="assistant", status="completed", content=[text]
            )
        else:
            out = ResponseFunctionToolCall(
                type="function_call",
                id="fc-1",
                call_id="call-1",
                name="flags_set",
                arguments=self.args,
                status="completed",
            )
        return ModelResponse(output=[out], usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        raise NotImplementedError


@pytest.fixture
def flags() -> Flags:
    f = Flags()
    for name in ("banner", "payments.provider", "kill_switch"):
        f.set(name, False)
    return f


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def rt(flags: Flags, clock: Clock) -> Iterator[Runtime]:
    runtime = Runtime(SqliteStore(), SERVICE, policy=DenyKillSwitch(), clock=clock)
    runtime.register(SetFlag(flags))
    yield runtime
    runtime.store.close()


def agent(rt: Runtime, name: str, enabled: bool = True) -> Agent[Any]:
    return Agent(name="ops", model=Scripted(name, enabled), tools=sealedplan_tools(rt, agent=AGENT))


def run(a: Agent[Any], start: Any) -> RunResult:
    return asyncio.run(Runner.run(a, start, run_config=NO_TRACING))


def tool_output(result: RunResult) -> dict[str, Any]:
    (item,) = [i for i in result.new_items if isinstance(i, ToolCallOutputItem)]
    out: dict[str, Any] = json.loads(str(item.output))
    return out


def decide(rt: Runtime, plan_hash: str, decision: Literal["approve", "reject"] = "approve") -> None:
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


def test_auto_approved_change_applies_without_pausing(rt: Runtime, flags: Flags) -> None:
    result = run(agent(rt, "banner"), "turn the banner on")
    assert result.interruptions == []
    out = tool_output(result)
    assert out["state"] == "APPLIED"
    assert "applied" in out
    assert flags.enabled["banner"] is True


def test_risky_change_pauses_and_resumes_after_approval(rt: Runtime, flags: Flags) -> None:
    a = agent(rt, "payments.provider")
    result = run(a, "switch the payment provider")
    (item,) = result.interruptions
    assert item.call_id == "call-1"
    state = result.to_state()
    (waiting,) = resolve_approvals(rt, state)
    assert waiting["call_id"] == "call-1"
    assert waiting["state"] == "PENDING_APPROVAL"
    assert waiting["plan"]["plan_hash"] == waiting["plan_hash"]
    assert flags.enabled["payments.provider"] is False

    # Resuming before a person approves stops on the same call again.
    again = run(a, state)
    (item,) = again.interruptions
    assert item.call_id == "call-1"
    assert flags.enabled["payments.provider"] is False

    decide(rt, waiting["plan_hash"])
    state = again.to_state()
    assert resolve_approvals(rt, state) == []
    out = tool_output(run(a, state))
    assert out["state"] == "APPLIED"
    assert flags.enabled["payments.provider"] is True
    # The approval check and the tool used the same plan.
    assert len(rt.store.list_plans()) == 1


def test_approving_in_the_run_alone_writes_nothing(rt: Runtime, flags: Flags) -> None:
    a = agent(rt, "payments.provider")
    result = run(a, "switch the payment provider")
    state = result.to_state()
    state.approve(result.interruptions[0])  # bypasses the store
    out = tool_output(run(a, state))
    assert out["state"] == "PENDING_APPROVAL"
    assert out["error"] == "the run was approved, but the plan was not; nothing written"
    assert flags.enabled["payments.provider"] is False


def test_rejected_plan_rejects_the_call(rt: Runtime, flags: Flags) -> None:
    a = agent(rt, "payments.provider")
    result = run(a, "switch the payment provider")
    state = result.to_state()
    (waiting,) = resolve_approvals(rt, state)
    decide(rt, waiting["plan_hash"], "reject")
    assert resolve_approvals(rt, state) == []
    out = tool_output(run(a, state))
    assert out["state"] == "REJECTED"
    assert flags.enabled["payments.provider"] is False


def test_denied_by_policy(rt: Runtime, flags: Flags) -> None:
    result = run(agent(rt, "kill_switch"), "flip the kill switch")
    assert result.interruptions == []
    assert tool_output(result)["state"] == "DENIED"
    assert flags.revision["kill_switch"] == 1


def test_drift_after_approval_writes_nothing(rt: Runtime, flags: Flags) -> None:
    a = agent(rt, "payments.provider")
    state = run(a, "switch the payment provider").to_state()
    (waiting,) = resolve_approvals(rt, state)
    decide(rt, waiting["plan_hash"])
    flags.set("payments.provider", False)  # someone else touches it
    resolve_approvals(rt, state)
    out = tool_output(run(a, state))
    assert out["state"] == "DRIFTED"
    assert out["failed_preconditions"][0]["id"] == "flag-revision"
    assert flags.revision["payments.provider"] == 2


def test_plan_that_expires_while_paused_is_rejected(rt: Runtime, clock: Clock) -> None:
    a = agent(rt, "payments.provider")
    state = run(a, "switch the payment provider").to_state()
    clock.now += rt.plan_ttl
    assert resolve_approvals(rt, state) == []
    assert tool_output(run(a, state))["state"] == "EXPIRED"


def test_plan_is_keyed_by_the_call_id(rt: Runtime) -> None:
    run(agent(rt, "payments.provider"), "switch the payment provider")
    (record,) = rt.store.by_idempotency_key("flags.set", KEY_PREFIX + "call-1")
    assert record.plan.params == {"name": "payments.provider", "enabled": True}


def test_tool_schema_is_the_plan_signature(rt: Runtime) -> None:
    tool = sealedplan_tool(rt, "flags.set", agent=AGENT)
    assert tool.name == "flags_set"
    assert set(tool.params_json_schema["properties"]) == {"name", "enabled"}
    assert tool.strict_json_schema is True
    assert tool.description.startswith("Turn a feature flag on or off.")
