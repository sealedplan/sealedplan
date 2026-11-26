"""The LangGraph adapter, driven through a real graph with a checkpointer."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Command
from pydantic import BaseModel

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
from sealedplan_langgraph import INTERRUPT_KIND, sealedplan_tool, sealedplan_tools

ISSUER = "https://idp.example.com"
AGENT = Principal(id="agent", issuer=ISSUER, kind="agent")
SERVICE = Principal(id="runtime", issuer=ISSUER, kind="service")
DANA = Principal(id="dana", issuer=ISSUER, kind="human")
T0 = datetime(2026, 11, 9, 14, 0, tzinfo=UTC)


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


def graph(rt: Runtime, name: str, enabled: bool = True) -> CompiledStateGraph[Any]:
    """One scripted model turn that calls flags_set, then the tool node."""

    def model(state: MessagesState) -> dict[str, Any]:
        call = {"name": "flags_set", "args": {"name": name, "enabled": enabled}, "id": "call-1"}
        return {"messages": [AIMessage(content="", tool_calls=[call])]}

    builder = StateGraph(MessagesState)
    builder.add_node("model", model)
    builder.add_node("tools", ToolNode(sealedplan_tools(rt, agent=AGENT)))
    builder.add_edge(START, "model")
    builder.add_edge("model", "tools")
    builder.add_edge("tools", END)
    return builder.compile(checkpointer=InMemorySaver())


def config() -> Any:
    return {"configurable": {"thread_id": str(uuid.uuid4())}}


def tool_output(result: dict[str, Any]) -> dict[str, Any]:
    message = result["messages"][-1]
    assert isinstance(message, ToolMessage)
    out: dict[str, Any] = json.loads(str(message.content))
    return out


def pending(result: dict[str, Any]) -> dict[str, Any]:
    (item,) = result["__interrupt__"]
    value: dict[str, Any] = item.value
    return value


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
    result = graph(rt, "banner").invoke({"messages": []}, config())
    assert "__interrupt__" not in result
    out = tool_output(result)
    assert out["state"] == "APPLIED"
    assert "applied" in out
    assert flags.enabled["banner"] is True


def test_risky_change_pauses_with_the_plan_and_resumes_after_approval(
    rt: Runtime, flags: Flags
) -> None:
    g, cfg = graph(rt, "payments.provider"), config()
    value = pending(g.invoke({"messages": []}, cfg))
    assert value["kind"] == INTERRUPT_KIND
    assert value["state"] == "PENDING_APPROVAL"
    assert value["plan"]["plan_hash"] == value["plan_hash"]
    assert value["resume"] == {"plan_hash": value["plan_hash"]}
    assert flags.enabled["payments.provider"] is False

    # Resuming is not approving: the graph pauses again on the same plan.
    again = pending(g.invoke(Command(resume=value["resume"]), cfg))
    assert again["plan_hash"] == value["plan_hash"]
    assert flags.enabled["payments.provider"] is False

    decide(rt, value["plan_hash"])
    out = tool_output(g.invoke(Command(resume=value["resume"]), cfg))
    assert out["state"] == "APPLIED"
    assert flags.enabled["payments.provider"] is True
    # Every re-run of the node continued the same plan.
    assert len(rt.store.list_plans()) == 1


def test_resume_must_name_the_paused_plan(rt: Runtime, flags: Flags) -> None:
    g, cfg = graph(rt, "payments.provider"), config()
    value = pending(g.invoke({"messages": []}, cfg))
    decide(rt, value["plan_hash"])
    out = tool_output(g.invoke(Command(resume={"plan_hash": "sha256:" + "0" * 64}), cfg))
    assert out["error"] == "the resume value names a different plan"
    assert out["state"] == "APPROVED"
    assert flags.enabled["payments.provider"] is False


def test_rejected_plan_is_reported_and_not_applied(rt: Runtime, flags: Flags) -> None:
    g, cfg = graph(rt, "payments.provider"), config()
    value = pending(g.invoke({"messages": []}, cfg))
    decide(rt, value["plan_hash"], "reject")
    out = tool_output(g.invoke(Command(resume=value["resume"]), cfg))
    assert out["state"] == "REJECTED"
    assert flags.enabled["payments.provider"] is False


def test_denied_by_policy(rt: Runtime, flags: Flags) -> None:
    out = tool_output(graph(rt, "kill_switch").invoke({"messages": []}, config()))
    assert out["state"] == "DENIED"
    assert flags.revision["kill_switch"] == 1


def test_drift_after_approval_writes_nothing(rt: Runtime, flags: Flags) -> None:
    g, cfg = graph(rt, "payments.provider"), config()
    value = pending(g.invoke({"messages": []}, cfg))
    decide(rt, value["plan_hash"])
    flags.set("payments.provider", False)  # someone else touches it
    out = tool_output(g.invoke(Command(resume=value["resume"]), cfg))
    assert out["state"] == "DRIFTED"
    assert out["failed_preconditions"][0]["id"] == "flag-revision"
    assert flags.revision["payments.provider"] == 2


def test_plan_that_expires_while_paused(rt: Runtime, clock: Clock) -> None:
    g, cfg = graph(rt, "payments.provider"), config()
    value = pending(g.invoke({"messages": []}, cfg))
    clock.now += rt.plan_ttl
    out = tool_output(g.invoke(Command(resume=value["resume"]), cfg))
    assert out["state"] == "EXPIRED"


def test_tool_schema_hides_the_tool_call_id(rt: Runtime) -> None:
    tool = sealedplan_tool(rt, "flags.set", agent=AGENT)
    assert tool.name == "flags_set"
    schema = tool.tool_call_schema
    assert isinstance(schema, type)
    assert issubclass(schema, BaseModel)
    assert set(schema.model_json_schema()["properties"]) == {"name", "enabled"}
    assert tool.description.startswith("Turn a feature flag on or off.")
