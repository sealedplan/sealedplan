from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import pytest

from conftest import IDP, T0
from sealedplan.actions import (
    ApplyFailedError,
    CompensationConflictError,
    Context,
    PreconditionFailedError,
    action,
)
from sealedplan.models import (
    Applied,
    Approval,
    ApprovalScope,
    Change,
    Compensation,
    Effect,
    Parent,
    Plan,
    PlanError,
    Precondition,
    Principal,
    ResourceRef,
)
from sealedplan.preconditions import ABSENT, Observation, PreconditionResult
from sealedplan.runtime import (
    ApprovalError,
    Runtime,
    UnknownActionError,
    WrongStateError,
)
from sealedplan.state import State
from sealedplan.store import IdempotencyError, SqliteStore

AGENT = Principal(id="agent:bot", issuer=IDP, kind="agent")
ALICE = Principal(id="alice", issuer=IDP, kind="human")
BOB = Principal(id="bob", issuer=IDP, kind="human")
CAROL = Principal(id="carol", issuer=IDP, kind="human")
RUNTIME = Principal(id="runtime:test", issuer=IDP, kind="service")


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@dataclass
class Cell:
    value: int
    version: int = 1


@dataclass
class World:
    """A tiny versioned key-value system standing in for a real target."""

    cells: dict[str, Cell] = field(default_factory=dict)
    fail_next: str | None = None
    applies: int = 0
    compensations: list[str] = field(default_factory=list)

    def put(self, key: str, value: int) -> None:
        cell = self.cells.setdefault(key, Cell(value, 0))
        cell.value, cell.version = value, cell.version + 1


def _res(key: str) -> ResourceRef:
    return ResourceRef(type="test/Cell", id=f"test://{key}")


class _SetValue:
    plan_effect: Effect | None = None  # None: use the action's declared effect

    def __init__(self, world: World) -> None:
        self.world = world

    def plan(self, ctx: Context, key: str, value: int) -> Plan:
        cell = self.world.cells[key]
        return ctx.plan(
            effect=self.plan_effect,
            summary=f"Set {key} from {cell.value} to {value}",
            changes=[
                Change(
                    resource=_res(key),
                    op="update",
                    before={"value": cell.value},
                    after={"value": value},
                )
            ],
            preconditions=[
                Precondition(
                    id="cell-version",
                    resource=_res(key),
                    kind="version",
                    expect=str(cell.version),
                    enforcement="atomic",
                )
            ],
            compensation=Compensation(
                strategy="restore",
                summary=f"Set {key} back to {cell.value}",
                params={"key": key, "value": cell.value},
            ),
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        cell = self.world.cells.get(resource.id.removeprefix("test://"))
        if cell is None:
            return ABSENT
        return Observation(True, str(cell.version), {"value": cell.value})

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        self.world.applies += 1
        key, fail = plan.params["key"], self.world.fail_next
        self.world.fail_next = None
        if fail == "race":
            self.world.put(key, 999)
        if fail == "failed":
            raise ApplyFailedError("target said no")
        if fail == "timeout":
            raise TimeoutError("no response")
        pre = plan.preconditions[0]
        version = str(self.world.cells[key].version)
        if version != pre.expect:
            raise PreconditionFailedError([PreconditionResult(pre.id, False, pre.expect, version)])
        self.world.put(key, plan.params["value"])
        return ctx.applied(plan)

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        if self.world.fail_next == "conflict":
            raise CompensationConflictError("changed underneath")
        self.world.compensations.append(plan.params["key"])
        self.world.put(plan.compensation.params["key"], plan.compensation.params["value"])

    def reconcile(self, ctx: Context, plan: Plan, applied: Applied | None) -> State:
        cell = self.world.cells[plan.params["key"]]
        return State.APPLIED if cell.value == plan.params["value"] else State.FAILED


SetValueLow = action("test.set_low", effect=Effect.REVERSIBLE, risk="low")(
    type("SetValueLow", (_SetValue,), {})
)
SetValue = action("test.set", effect=Effect.REVERSIBLE, risk="medium")(
    type("SetValue", (_SetValue,), {})
)
SetValueCritical = action("test.set_critical", effect=Effect.REVERSIBLE, risk="critical")(
    type("SetValueCritical", (_SetValue,), {})
)


@action("test.send", effect=Effect.IRREVERSIBLE, risk="low")
class Send:
    def __init__(self, world: World) -> None:
        self.world = world

    def plan(self, ctx: Context, key: str) -> Plan:
        return ctx.plan(
            summary=f"Send {key}",
            changes=[Change(resource=_res(key), op="invoke")],
            preconditions=[
                Precondition(
                    id="new", resource=_res(key), kind="absent", enforcement="check_then_act"
                )
            ],
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        return (
            ABSENT
            if resource.id.removeprefix("test://") not in self.world.cells
            else Observation(True)
        )

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        self.world.put(plan.params["key"], 1)
        return ctx.applied(plan)


@dataclass
class Env:
    world: World
    clock: Clock
    store: SqliteStore
    rt: Runtime

    def propose(self, name: str = "test.set", key: str = "k", value: int = 5, **kw: Any) -> Plan:
        kw.setdefault("idempotency_key", f"req-{key}-{value}")
        params: dict[str, Any] = (
            {"key": key} if name == "test.send" else {"key": key, "value": value}
        )
        return self.rt.propose(name, params, agent=AGENT, sponsor=ALICE, **kw).plan

    def approve(self, plan: Plan, who: Principal = BOB, **kw: Any) -> State:
        return self.rt.submit_approval(approval(plan, who, **kw))

    def state(self, plan: Plan) -> State:
        return self.store.get(plan.plan_hash).state


def approval(
    plan: Plan,
    who: Principal = BOB,
    decision: str = "approve",
    minutes: int = 10,
    apply_by: list[Principal] | None = None,
    signed: bool = False,
) -> Approval:
    return Approval.model_validate(
        {
            "approval_id": f"appr-{who.id}-{plan.plan_hash[7:15]}",
            "plan_hash": plan.plan_hash,
            "decision": decision,
            "approver": who.to_obj(),
            "method": "cli",
            "scope": ApprovalScope(apply_by=apply_by).to_obj(),
            "issued_at": T0,
            "expires_at": T0 + timedelta(minutes=minutes),
            **({"signature": {"alg": "EdDSA", "kid": "k1", "value": "sig"}} if signed else {}),
        }
    )


def make_env(store: SqliteStore | None = None, world: World | None = None, **kw: Any) -> Env:
    world = world or World({"k": Cell(3), "a": Cell(1), "b": Cell(1), "c": Cell(1)})
    clock = Clock()
    store = store or SqliteStore()
    rt = Runtime(store, RUNTIME, clock=clock, **kw)
    rt.register(SetValueLow(world), SetValue(world), SetValueCritical(world), Send(world))
    return Env(world, clock, store, rt)


@pytest.fixture
def env() -> Env:
    return make_env()


# --- happy paths ----------------------------------------------------------------------


def test_auto_approved_plan_applies(env: Env) -> None:
    plan = env.propose("test.set_low")
    assert env.state(plan) is State.APPROVED
    result = env.rt.execute(plan.plan_hash)
    assert result.state is State.APPLIED
    assert env.world.cells["k"].value == 5
    assert result.applied is not None
    assert result.applied.observed is not None
    assert result.applied.observed["test://k"]["version"] == "2"
    assert [a.method for a in env.store.approvals(plan.plan_hash)] == ["policy"]
    assert env.store.verify_events()


def test_approval_flow(env: Env) -> None:
    plan = env.propose()
    assert env.state(plan) is State.PENDING_APPROVAL
    with pytest.raises(WrongStateError):
        env.rt.execute(plan.plan_hash)
    assert env.approve(plan) is State.APPROVED
    assert env.rt.execute(plan.plan_hash).state is State.APPLIED
    with pytest.raises(WrongStateError):
        env.rt.execute(plan.plan_hash)
    assert env.world.applies == 1


def test_reject_is_final(env: Env) -> None:
    plan = env.propose()
    assert env.approve(plan, decision="reject") is State.REJECTED
    with pytest.raises(WrongStateError):
        env.approve(plan, CAROL)


def test_two_person(env: Env) -> None:
    plan = env.propose("test.set_critical")
    assert env.approve(plan, BOB) is State.PENDING_APPROVAL
    assert env.approve(plan, ALICE) is State.APPROVED
    assert env.rt.execute(plan.plan_hash).state is State.APPLIED


def test_policy_none_denies(env: Env) -> None:
    env.rt.policy = None
    assert env.state(env.propose("test.set_low")) is State.DENIED


def test_irreversible_is_never_auto(env: Env) -> None:
    plan = env.propose("test.send", key="new")
    assert env.state(plan) is State.PENDING_APPROVAL


# --- approval rules ---------------------------------------------------------------------


def test_agent_cannot_self_approve(env: Env) -> None:
    plan = env.propose()
    with pytest.raises(ApprovalError, match="own plan"):
        env.approve(plan, AGENT)


def test_only_humans_approve_by_default(env: Env) -> None:
    plan = env.propose()
    with pytest.raises(ApprovalError, match="may not approve"):
        env.approve(plan, RUNTIME)


def test_untrusted_channel_needs_verified_signature(env: Env) -> None:
    plan = env.propose()
    with pytest.raises(ApprovalError, match="signed"):
        env.rt.submit_approval(approval(plan), trusted_channel=False)
    with pytest.raises(ApprovalError, match="did not verify"):
        env.rt.submit_approval(approval(plan, signed=True), trusted_channel=False)
    env.rt.verify_signature = lambda a: a.signature is not None and a.signature.kid == "k1"
    assert env.rt.submit_approval(approval(plan, signed=True), trusted_channel=False) is (
        State.APPROVED
    )


def test_apply_by_limits_who_applies(env: Env) -> None:
    plan = env.propose()
    env.approve(plan)
    with pytest.raises(ApprovalError, match="no valid approval"):
        env.rt.execute(plan.plan_hash, applier=CAROL)
    other = env.propose(key="a")
    env.approve(other, apply_by=[CAROL])
    assert env.rt.execute(other.plan_hash, applier=CAROL).state is State.APPLIED


def test_approval_does_not_carry_to_a_replan(env: Env) -> None:
    first = env.propose()
    env.approve(first)
    env.world.put("k", 4)
    assert env.rt.execute(first.plan_hash).state is State.DRIFTED
    second = env.propose(idempotency_key="req-k-5")
    assert second.plan_hash != first.plan_hash
    assert env.state(second) is State.PENDING_APPROVAL
    with pytest.raises(WrongStateError):
        env.rt.execute(second.plan_hash)


# --- expiry ---------------------------------------------------------------------------


def test_expired_plan_cannot_be_approved_or_applied(env: Env) -> None:
    plan = env.propose()
    env.clock.advance(minutes=31)
    with pytest.raises(ApprovalError, match="expired"):
        env.approve(plan, minutes=60)
    assert env.state(plan) is State.EXPIRED


def test_plan_expires_between_approval_and_apply(env: Env) -> None:
    plan = env.propose()
    env.approve(plan, minutes=60)
    env.clock.advance(minutes=30)
    assert env.rt.execute(plan.plan_hash).state is State.EXPIRED
    assert env.world.applies == 0


def test_approval_expires_before_plan(env: Env) -> None:
    plan = env.propose()
    env.approve(plan, minutes=5)
    env.clock.advance(minutes=6)
    assert env.rt.execute(plan.plan_hash).state is State.EXPIRED


def test_expire_due(env: Env) -> None:
    plan = env.propose()
    env.clock.advance(hours=1)
    assert env.rt.expire_due() == [plan.plan_hash]
    assert env.state(plan) is State.EXPIRED


# --- drift ------------------------------------------------------------------------------


def test_drift_before_apply_refuses(env: Env) -> None:
    plan = env.propose()
    env.approve(plan)
    env.world.put("k", 4)
    result = env.rt.execute(plan.plan_hash)
    assert result.state is State.DRIFTED
    assert [(d.id, d.expected, d.observed) for d in result.drift] == [("cell-version", "1", "2")]
    assert env.world.applies == 0
    assert env.world.cells["k"].value == 4
    event = env.store.events(plan.plan_hash)[-1]
    assert event.detail is not None
    assert event.detail["failed"][0]["observed"] == "2"


def test_atomic_precondition_rejected_by_target_is_drift(env: Env) -> None:
    plan = env.propose()
    env.approve(plan)
    env.world.fail_next = "race"
    result = env.rt.execute(plan.plan_hash)
    assert result.state is State.DRIFTED
    assert env.world.cells["k"].value == 999


# --- failures, unknown, recover ---------------------------------------------------------


def test_failed_apply(env: Env) -> None:
    plan = env.propose("test.set_low")
    env.world.fail_next = "failed"
    result = env.rt.execute(plan.plan_hash)
    assert result.state is State.FAILED
    assert result.applied is not None
    assert result.applied.outcome == "failed"


def test_unexpected_error_is_unknown_and_blocks_the_key(env: Env) -> None:
    plan = env.propose("test.set_low")
    env.world.fail_next = "timeout"
    assert env.rt.execute(plan.plan_hash).state is State.UNKNOWN
    env.clock.advance(minutes=1)
    again = env.propose("test.set_low")  # same key and params, new plan
    assert again.plan_hash != plan.plan_hash
    assert env.state(again) is State.APPROVED
    with pytest.raises(IdempotencyError):
        env.rt.execute(again.plan_hash)
    assert env.rt.reconcile(plan.plan_hash) is State.FAILED


def test_recover_moves_applying_to_unknown_and_reconciles(tmp_path: Any) -> None:
    db = tmp_path / "rt.db"
    first = make_env(SqliteStore(db))
    plan = first.propose("test.set_low")
    first.store.begin_apply(
        plan.plan_hash,
        [a.approval_id for a in first.store.approvals(plan.plan_hash)],
        AGENT,
        T0,
    )
    first.world.put("k", 5)  # the write landed, then the process died
    restarted = make_env(SqliteStore(db), world=first.world)
    assert restarted.rt.recover() == {plan.plan_hash: State.APPLIED}
    assert restarted.world.applies == 0
    applied = restarted.store.applied(plan.plan_hash)
    assert applied is not None
    assert applied.outcome == "succeeded"


def test_recover_mid_compensation_escalates(env: Env) -> None:
    plan = env.propose("test.set_low")
    env.rt.execute(plan.plan_hash)
    env.store.transition(plan.plan_hash, State.APPLIED, State.COMPENSATING, RUNTIME, T0)
    env.rt.recover()
    assert env.state(plan) is State.COMPENSATION_FAILED
    assert env.store.compensations(plan.plan_hash)[0].outcome == "unknown"


# --- compensation -----------------------------------------------------------------------


def test_compensate_restores(env: Env) -> None:
    plan = env.propose("test.set_low")
    env.rt.execute(plan.plan_hash)
    done = env.rt.compensate(plan.plan_hash)
    assert done.outcome == "succeeded"
    assert env.world.cells["k"].value == 3
    assert env.state(plan) is State.COMPENSATED


def test_compensation_conflict_when_changed_since_apply(env: Env) -> None:
    plan = env.propose("test.set_low")
    env.rt.execute(plan.plan_hash)
    env.world.put("k", 7)  # someone else's later change
    done = env.rt.compensate(plan.plan_hash)
    assert done.outcome == "conflict"
    assert env.world.cells["k"].value == 7
    assert env.world.compensations == []
    assert env.state(plan) is State.COMPENSATION_FAILED


def test_provider_reported_conflict(env: Env) -> None:
    plan = env.propose("test.set_low")
    env.rt.execute(plan.plan_hash)
    env.world.fail_next = "conflict"
    assert env.rt.compensate(plan.plan_hash).outcome == "conflict"


def test_irreversible_is_skipped(env: Env) -> None:
    plan = env.propose("test.send", key="new")
    env.approve(plan)
    env.rt.execute(plan.plan_hash)
    assert env.rt.compensate(plan.plan_hash).outcome == "skipped"
    assert env.state(plan) is State.APPLIED


def test_run_compensates_earlier_steps_in_reverse(env: Env) -> None:
    hashes = []
    for step, key in enumerate(["a", "b", "c"]):
        plan = env.propose(
            "test.set_low", key=key, value=9, parent=Parent(run_id="run-1", step=step)
        )
        hashes.append(plan.plan_hash)
    env.rt.execute(hashes[0])
    env.rt.execute(hashes[1])
    env.world.put("c", 2)
    assert env.rt.execute(hashes[2]).state is State.DRIFTED
    done = env.rt.compensate_run("run-1", failed_step=2)
    assert [c.trigger.failed_step for c in done if c.trigger] == [2, 2]
    assert env.world.compensations == ["b", "a"]
    assert [env.world.cells[k].value for k in "ab"] == [1, 1]


# --- provider checks ------------------------------------------------------------------


def test_unknown_action(env: Env) -> None:
    with pytest.raises(UnknownActionError):
        env.rt.propose("nope", {}, agent=AGENT, idempotency_key="x")


def test_provider_plan_must_describe_this_call(env: Env) -> None:
    @action("test.liar", effect=Effect.REVERSIBLE)
    class Liar(_SetValue):
        def plan(self, ctx: Context, key: str, value: int) -> Plan:
            lying = Context(**{**ctx.__dict__, "params": {"key": key, "value": value + 1}})
            return super().plan(lying, key, value + 1)

    env.rt.register(Liar(env.world))
    with pytest.raises(PlanError, match="different call"):
        env.rt.propose("test.liar", {"key": "k", "value": 5}, agent=AGENT, idempotency_key="x")


def test_plan_effect_cannot_exceed_action(env: Env) -> None:
    @action("test.understated", effect=Effect.READ_ONLY)
    class Understated(_SetValue):
        plan_effect = Effect.REVERSIBLE

    env.rt.register(Understated(env.world))
    with pytest.raises(PlanError, match="exceeds"):
        env.rt.propose(
            "test.understated", {"key": "k", "value": 5}, agent=AGENT, idempotency_key="x"
        )


def test_reversible_action_must_define_compensate() -> None:
    class NoUndo:
        def plan(self) -> None: ...
        def observe(self) -> None: ...
        def apply(self) -> None: ...

    with pytest.raises(TypeError, match="compensate"):
        action("x", effect=Effect.REVERSIBLE)(NoUndo)
