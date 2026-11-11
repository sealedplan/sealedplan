from __future__ import annotations

import itertools
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from conftest import IDP, T0, make_plan
from sealedplan.models import Applied, Approval, Compensated, Effect, Plan, PlanError, Principal
from sealedplan.policy import Decision, PolicyResult
from sealedplan.state import InvalidTransitionError, State
from sealedplan.store import (
    ApprovalUnusableError,
    IdempotencyError,
    NotFoundError,
    SqliteStore,
    StateConflictError,
    StoreError,
)

RUNTIME = Principal(id="runtime:test", issuer=IDP, kind="service")
BOB = Principal(id="bob", issuer=IDP, kind="human")
T1 = T0 + timedelta(minutes=1)
APPROVE = PolicyResult(Decision.APPROVE, ("test",), "sha256:" + "0" * 64)


def _approval(plan: Plan, approval_id: str = "appr-1") -> Approval:
    return Approval(
        approval_id=approval_id,
        plan_hash=plan.plan_hash,
        decision="approve",
        approver=BOB,
        method="cli",
        scope={"uses": 1},  # type: ignore[arg-type]
        issued_at=T1,
        expires_at=T1 + timedelta(minutes=10),
    )


def _approved(store: SqliteStore, plan: Plan, approval_id: str = "appr-1") -> None:
    store.create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)
    store.record_decision(plan.plan_hash, APPROVE, State.PENDING_APPROVAL, RUNTIME, T0)
    store.add_approval(_approval(plan, approval_id))
    store.transition(plan.plan_hash, State.PENDING_APPROVAL, State.APPROVED, RUNTIME, T1)


def _applied(plan: Plan) -> Applied:
    return Applied(
        applied_id="applied-1",
        plan_hash=plan.plan_hash,
        approval_ids=["appr-1"],
        outcome="succeeded",
        started_at=T1,
        finished_at=T1,
        principal=plan.principal.agent,
    )


@pytest.fixture
def store() -> SqliteStore:
    return SqliteStore()


def test_create_and_get(store: SqliteStore, plan: Plan) -> None:
    store.create_plan(plan, Effect.COMPENSATABLE, plan.principal.agent, T0)
    record = store.get(plan.plan_hash)
    assert record.plan == plan
    assert record.state is State.PLANNED
    assert record.effect is Effect.COMPENSATABLE
    assert record.decision is None
    assert store.find(plan.plan_hash.removeprefix("sha256:")[:12]).plan == plan
    with pytest.raises(StoreError, match="already exists"):
        store.create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)


def test_unknown_plan(store: SqliteStore) -> None:
    with pytest.raises(NotFoundError):
        store.get("sha256:" + "f" * 64)
    with pytest.raises(NotFoundError):
        store.find("ff")


def test_decision_is_recorded(store: SqliteStore, plan: Plan) -> None:
    store.create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)
    event = store.record_decision(plan.plan_hash, APPROVE, State.PENDING_APPROVAL, RUNTIME, T0)
    assert event.detail is not None
    assert event.detail["decision"] == "approve"
    record = store.get(plan.plan_hash)
    assert record.decision is Decision.APPROVE
    assert record.policy_digest == APPROVE.policy_digest
    assert [r.plan for r in store.list_plans([State.PENDING_APPROVAL])] == [plan]
    assert store.list_plans([State.APPROVED]) == []


def test_transition_is_compare_and_set(store: SqliteStore, plan: Plan) -> None:
    store.create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)
    store.transition(plan.plan_hash, State.PLANNED, State.DENIED, RUNTIME, T0)
    with pytest.raises(StateConflictError) as info:
        store.transition(plan.plan_hash, State.PLANNED, State.APPROVED, RUNTIME, T0)
    assert info.value.actual is State.DENIED
    with pytest.raises(InvalidTransitionError):
        store.transition(plan.plan_hash, State.DENIED, State.APPLYING, RUNTIME, T0)


def test_events_are_chained(store: SqliteStore, plan: Plan) -> None:
    _approved(store, plan)
    events = store.events(plan.plan_hash)
    assert [(e.from_, e.to) for e in events] == [
        (None, State.PLANNED),
        (State.PLANNED, State.PENDING_APPROVAL),
        (State.PENDING_APPROVAL, State.APPROVED),
    ]
    assert events[0].prev is None
    assert all(b.prev == a.digest() for a, b in itertools.pairwise(events))
    assert store.verify_events()


def test_tampered_event_is_detected(tmp_path: Path, plan: Plan) -> None:
    db = tmp_path / "s.db"
    _approved(SqliteStore(db), plan)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE events SET body = replace(body, 'bob', 'eve')")
        conn.execute("UPDATE events SET body = replace(body, 'runtime:test', 'runtime:x')")
    assert not SqliteStore(db).verify_events()


def test_tampered_plan_body_is_detected(tmp_path: Path, plan: Plan) -> None:
    db = tmp_path / "s.db"
    SqliteStore(db).create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE plans SET body = replace(body, '\"replicas\":6', '\"replicas\":60')")
    with pytest.raises(PlanError):
        SqliteStore(db).get(plan.plan_hash)


def test_another_instance_sees_approval(tmp_path: Path, plan: Plan) -> None:
    # §7.4: approval may arrive through a different runtime instance.
    db = tmp_path / "s.db"
    a, b = SqliteStore(db), SqliteStore(db)
    a.create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)
    b.add_approval(_approval(plan))
    assert [x.approval_id for x in a.approvals(plan.plan_hash)] == ["appr-1"]


def test_approval_for_unknown_plan_rejected(store: SqliteStore, plan: Plan) -> None:
    with pytest.raises(NotFoundError):
        store.add_approval(_approval(plan))


def test_begin_apply_consumes_approval(store: SqliteStore, plan: Plan) -> None:
    _approved(store, plan)
    store.begin_apply(plan.plan_hash, ["appr-1"], plan.principal.agent, T1)
    assert store.get(plan.plan_hash).state is State.APPLYING
    assert store.approvals(plan.plan_hash, unused_only=True) == []
    assert store.in_flight()[0].plan == plan


def test_begin_apply_rolls_back_on_bad_approval(store: SqliteStore, plan: Plan) -> None:
    _approved(store, plan)
    with pytest.raises(ApprovalUnusableError):
        store.begin_apply(plan.plan_hash, ["appr-1", "appr-missing"], plan.principal.agent, T1)
    assert store.get(plan.plan_hash).state is State.APPROVED
    assert len(store.approvals(plan.plan_hash, unused_only=True)) == 1


def test_begin_apply_requires_approved(store: SqliteStore, plan: Plan) -> None:
    store.create_plan(plan, Effect.REVERSIBLE, plan.principal.agent, T0)
    store.record_decision(plan.plan_hash, APPROVE, State.PENDING_APPROVAL, RUNTIME, T0)
    store.add_approval(_approval(plan))
    with pytest.raises(StateConflictError):
        store.begin_apply(plan.plan_hash, ["appr-1"], plan.principal.agent, T1)
    assert len(store.approvals(plan.plan_hash, unused_only=True)) == 1


def test_idempotency_key_blocks_second_apply(store: SqliteStore) -> None:
    first, second = make_plan(), make_plan(summary="same request, re-planned")
    _approved(store, first, "appr-1")
    _approved(store, second, "appr-2")
    store.begin_apply(first.plan_hash, ["appr-1"], first.principal.agent, T1)
    with pytest.raises(IdempotencyError) as info:
        store.begin_apply(second.plan_hash, ["appr-2"], second.principal.agent, T1)
    assert info.value.other_state is State.APPLYING


def test_failed_apply_frees_idempotency_key(store: SqliteStore) -> None:
    first, second = make_plan(), make_plan(summary="same request, re-planned")
    _approved(store, first, "appr-1")
    _approved(store, second, "appr-2")
    store.begin_apply(first.plan_hash, ["appr-1"], first.principal.agent, T1)
    failed = _applied(first).model_copy(update={"outcome": "failed", "error": "boom"})
    store.record_applied(failed, State.APPLYING, State.FAILED, RUNTIME, T1)
    store.begin_apply(second.plan_hash, ["appr-2"], second.principal.agent, T1)


def test_applied_and_compensated_records(store: SqliteStore, plan: Plan) -> None:
    _approved(store, plan)
    store.begin_apply(plan.plan_hash, ["appr-1"], plan.principal.agent, T1)
    store.record_applied(_applied(plan), State.APPLYING, State.APPLIED, RUNTIME, T1)
    assert store.applied(plan.plan_hash) == _applied(plan)
    store.transition(plan.plan_hash, State.APPLIED, State.COMPENSATING, RUNTIME, T1)
    compensated = Compensated(
        compensation_id="comp-1",
        applied_id="applied-1",
        plan_hash=plan.plan_hash,
        reason="manual",
        outcome="succeeded",
        started_at=T1,
        finished_at=T1,
    )
    store.record_compensated(compensated, State.COMPENSATING, State.COMPENSATED, RUNTIME, T1)
    assert store.compensations(plan.plan_hash) == [compensated]
    assert store.get(plan.plan_hash).state is State.COMPENSATED
    assert store.verify_events()


def test_concurrent_apply_has_one_winner(tmp_path: Path, plan: Plan) -> None:
    db = tmp_path / "s.db"
    _approved(SqliteStore(db), plan)
    stores = [SqliteStore(db) for _ in range(4)]
    barrier = threading.Barrier(len(stores))
    results: list[str] = []

    def attempt(s: SqliteStore) -> None:
        barrier.wait()
        try:
            s.begin_apply(plan.plan_hash, ["appr-1"], plan.principal.agent, T1)
            results.append("won")
        except (StateConflictError, ApprovalUnusableError):
            results.append("lost")

    threads = [threading.Thread(target=attempt, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["lost", "lost", "lost", "won"]
