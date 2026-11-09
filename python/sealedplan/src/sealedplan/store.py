"""Durable store on SQLite (SPEC §7.2, §7.4, §9.1, §11.7).

Every state change is a compare-and-set inside ``BEGIN IMMEDIATE``, so several runtime
instances can share one database file. Each change appends an event whose ``prev`` is
the digest of the previous event, which makes edits to the log detectable.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sealedplan.canonical import canonicalize
from sealedplan.models import (
    Applied,
    Approval,
    Compensated,
    Effect,
    Event,
    Plan,
    Principal,
    parse_plan,
)
from sealedplan.policy import Decision, PolicyResult
from sealedplan.state import IN_FLIGHT, State, check_transition

# A plan in one of these states has been, or may have been, applied. While one exists,
# no other plan with the same (action.name, idempotency_key) may start applying (§7.3, §9.1).
_APPLIED_OR_MAYBE = (
    State.APPLYING,
    State.UNKNOWN,
    State.APPLIED,
    State.COMPENSATING,
    State.COMPENSATED,
    State.COMPENSATION_FAILED,
)

# Placeholders only; the statement takes no caller-supplied text.
_SAME_KEY_SQL = (
    "SELECT plan_hash, state FROM plans WHERE action_name = ? AND idempotency_key = ?"  # noqa: S608
    " AND plan_hash != ? AND state IN (" + ",".join("?" * len(_APPLIED_OR_MAYBE)) + ") LIMIT 1"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS plans (
    plan_hash       TEXT PRIMARY KEY,
    action_name     TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    state           TEXT NOT NULL,
    effect          TEXT NOT NULL,
    decision        TEXT,
    policy_digest   TEXT,
    body            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS plans_idempotency ON plans (action_name, idempotency_key);
CREATE INDEX IF NOT EXISTS plans_state ON plans (state);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    plan_hash   TEXT NOT NULL REFERENCES plans (plan_hash),
    body        TEXT NOT NULL,
    used_at     TEXT
);
CREATE TABLE IF NOT EXISTS applied (
    applied_id TEXT PRIMARY KEY,
    plan_hash  TEXT NOT NULL UNIQUE REFERENCES plans (plan_hash),
    body       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS compensations (
    compensation_id TEXT PRIMARY KEY,
    plan_hash       TEXT NOT NULL REFERENCES plans (plan_hash),
    body            TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_hash TEXT NOT NULL REFERENCES plans (plan_hash),
    body      TEXT NOT NULL,
    digest    TEXT NOT NULL
);
"""


class StoreError(Exception):
    pass


class NotFoundError(StoreError):
    pass


class StateConflictError(StoreError):
    """The plan was not in the expected state; another instance got there first."""

    def __init__(self, plan_hash: str, expected: State, actual: State) -> None:
        super().__init__(f"plan {plan_hash} is {actual}, expected {expected}")
        self.expected = expected
        self.actual = actual


class ApprovalUnusableError(StoreError):
    pass


class IdempotencyError(StoreError):
    def __init__(self, other_plan_hash: str, other_state: State) -> None:
        super().__init__(
            f"plan {other_plan_hash} with the same idempotency key is {other_state} (§9.1)"
        )
        self.other_plan_hash = other_plan_hash
        self.other_state = other_state


@dataclass(frozen=True)
class PlanRecord:
    plan: Plan
    state: State
    effect: Effect
    decision: Decision | None
    policy_digest: str | None
    updated_at: str


def _json(obj: Any) -> str:
    return canonicalize(obj).decode("utf-8")


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class SqliteStore:
    def __init__(self, path: str | Path = ":memory:", *, timeout: float = 5.0) -> None:
        self._conn = sqlite3.connect(
            str(path), timeout=timeout, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    # --- events ------------------------------------------------------------------------

    def _append_event(
        self,
        conn: sqlite3.Connection,
        plan_hash: str,
        src: State | None,
        dst: State,
        actor: Principal,
        at: datetime,
        detail: dict[str, Any] | None,
    ) -> Event:
        row = conn.execute("SELECT digest FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        event = Event(
            event_id=f"evt-{uuid.uuid4()}",
            plan_hash=plan_hash,
            from_=src,
            to=dst,
            at=at,
            actor=actor,
            detail=detail,
            prev=row["digest"] if row else None,
        )
        conn.execute(
            "INSERT INTO events (plan_hash, body, digest) VALUES (?, ?, ?)",
            (plan_hash, _json(event.to_obj()), event.digest()),
        )
        return event

    def events(self, plan_hash: str | None = None) -> list[Event]:
        if plan_hash is None:
            rows = self._conn.execute("SELECT body FROM events ORDER BY seq").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT body FROM events WHERE plan_hash = ? ORDER BY seq", (plan_hash,)
            ).fetchall()
        return [Event.model_validate(json.loads(r["body"])) for r in rows]

    def verify_events(self) -> bool:
        """Check the event chain: each ``prev`` and stored digest matches (§11.7)."""
        prev: str | None = None
        for row in self._conn.execute("SELECT body, digest FROM events ORDER BY seq"):
            event = Event.model_validate(json.loads(row["body"]))
            if event.prev != prev or event.digest() != row["digest"]:
                return False
            prev = row["digest"]
        return True

    # --- plans -------------------------------------------------------------------------

    def create_plan(self, plan: Plan, effect: Effect, actor: Principal, at: datetime) -> Event:
        with self._tx() as conn:
            if conn.execute(
                "SELECT 1 FROM plans WHERE plan_hash = ?", (plan.plan_hash,)
            ).fetchone():
                raise StoreError(f"plan {plan.plan_hash} already exists")
            conn.execute(
                "INSERT INTO plans (plan_hash, action_name, idempotency_key, state, effect,"
                " body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    plan.plan_hash,
                    plan.action.name,
                    plan.idempotency_key,
                    State.PLANNED,
                    effect,
                    _json(plan.to_obj()),
                    _ts(plan.created_at),
                    _ts(at),
                ),
            )
            return self._append_event(conn, plan.plan_hash, None, State.PLANNED, actor, at, None)

    def get(self, plan_hash: str) -> PlanRecord:
        row = self._conn.execute("SELECT * FROM plans WHERE plan_hash = ?", (plan_hash,)).fetchone()
        if row is None:
            raise NotFoundError(f"no plan {plan_hash}")
        return self._record(row)

    def find(self, prefix: str) -> PlanRecord:
        """Look up a plan by a unique prefix of its hash (for humans at a CLI)."""
        if not prefix.startswith("sha256:"):
            prefix = "sha256:" + prefix
        rows = self._conn.execute(
            "SELECT * FROM plans WHERE substr(plan_hash, 1, ?) = ? LIMIT 2", (len(prefix), prefix)
        ).fetchall()
        if len(rows) != 1:
            raise NotFoundError(f"{len(rows) or 'no'} plans match {prefix}")
        return self._record(rows[0])

    def list_plans(self, states: Iterable[State] | None = None) -> list[PlanRecord]:
        if states is None:
            rows = self._conn.execute("SELECT * FROM plans ORDER BY created_at").fetchall()
        else:
            wanted = [str(s) for s in states]
            marks = ",".join("?" * len(wanted))
            rows = self._conn.execute(
                f"SELECT * FROM plans WHERE state IN ({marks}) ORDER BY created_at",  # noqa: S608
                wanted,
            ).fetchall()
        return [self._record(r) for r in rows]

    def in_flight(self) -> list[PlanRecord]:
        return self.list_plans(IN_FLIGHT)

    def _record(self, row: sqlite3.Row) -> PlanRecord:
        # parse_plan re-verifies the hash, so an edited plan body is caught on load.
        return PlanRecord(
            plan=parse_plan(row["body"]),
            state=State(row["state"]),
            effect=Effect(row["effect"]),
            decision=Decision(row["decision"]) if row["decision"] else None,
            policy_digest=row["policy_digest"],
            updated_at=row["updated_at"],
        )

    # --- transitions -------------------------------------------------------------------

    def _cas(
        self,
        conn: sqlite3.Connection,
        plan_hash: str,
        src: State,
        dst: State,
        actor: Principal,
        at: datetime,
        detail: dict[str, Any] | None,
    ) -> Event:
        check_transition(src, dst)
        cur = conn.execute(
            "UPDATE plans SET state = ?, updated_at = ? WHERE plan_hash = ? AND state = ?",
            (dst, _ts(at), plan_hash, src),
        )
        if cur.rowcount != 1:
            row = conn.execute(
                "SELECT state FROM plans WHERE plan_hash = ?", (plan_hash,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"no plan {plan_hash}")
            raise StateConflictError(plan_hash, src, State(row["state"]))
        return self._append_event(conn, plan_hash, src, dst, actor, at, detail)

    def transition(
        self,
        plan_hash: str,
        src: State,
        dst: State,
        actor: Principal,
        at: datetime,
        detail: dict[str, Any] | None = None,
    ) -> Event:
        with self._tx() as conn:
            return self._cas(conn, plan_hash, src, dst, actor, at, detail)

    def record_decision(
        self, plan_hash: str, result: PolicyResult, dst: State, actor: Principal, at: datetime
    ) -> Event:
        """Store the policy decision and move out of PLANNED in one step (§10.1)."""
        detail = {
            "decision": str(result.decision),
            "reasons": list(result.reasons),
            "policy_digest": result.policy_digest,
        }
        with self._tx() as conn:
            conn.execute(
                "UPDATE plans SET decision = ?, policy_digest = ? WHERE plan_hash = ?",
                (result.decision, result.policy_digest or None, plan_hash),
            )
            return self._cas(conn, plan_hash, State.PLANNED, dst, actor, at, detail)

    # --- approvals ---------------------------------------------------------------------

    def add_approval(self, approval: Approval) -> None:
        with self._tx() as conn:
            if not conn.execute(
                "SELECT 1 FROM plans WHERE plan_hash = ?", (approval.plan_hash,)
            ).fetchone():
                raise NotFoundError(f"no plan {approval.plan_hash}")
            try:
                conn.execute(
                    "INSERT INTO approvals (approval_id, plan_hash, body) VALUES (?, ?, ?)",
                    (approval.approval_id, approval.plan_hash, _json(approval.to_obj())),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"approval {approval.approval_id} already exists") from exc

    def approvals(self, plan_hash: str, *, unused_only: bool = False) -> list[Approval]:
        sql = "SELECT body FROM approvals WHERE plan_hash = ?"
        if unused_only:
            sql += " AND used_at IS NULL"
        rows = self._conn.execute(sql + " ORDER BY rowid", (plan_hash,)).fetchall()
        return [Approval.model_validate(json.loads(r["body"])) for r in rows]

    # --- apply -------------------------------------------------------------------------

    def begin_apply(
        self,
        plan_hash: str,
        approval_ids: Sequence[str],
        actor: Principal,
        at: datetime,
    ) -> Event:
        """APPROVED -> APPLYING, consuming the approvals and claiming the idempotency key.

        All of it happens in one transaction, so two instances racing to apply the same
        plan, or two plans with the same key, cannot both proceed.
        """
        with self._tx() as conn:
            row = conn.execute(
                "SELECT action_name, idempotency_key FROM plans WHERE plan_hash = ?",
                (plan_hash,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"no plan {plan_hash}")
            other = conn.execute(
                _SAME_KEY_SQL,
                (row["action_name"], row["idempotency_key"], plan_hash, *_APPLIED_OR_MAYBE),
            ).fetchone()
            if other is not None:
                raise IdempotencyError(other["plan_hash"], State(other["state"]))
            for approval_id in approval_ids:
                cur = conn.execute(
                    "UPDATE approvals SET used_at = ? WHERE approval_id = ? AND plan_hash = ?"
                    " AND used_at IS NULL",
                    (_ts(at), approval_id, plan_hash),
                )
                if cur.rowcount != 1:
                    raise ApprovalUnusableError(
                        f"approval {approval_id} is used or not for plan {plan_hash}"
                    )
            return self._cas(
                conn,
                plan_hash,
                State.APPROVED,
                State.APPLYING,
                actor,
                at,
                {"approval_ids": list(approval_ids)},
            )

    def record_applied(
        self,
        applied: Applied,
        src: State,
        dst: State,
        actor: Principal,
        at: datetime,
        detail: dict[str, Any] | None = None,
    ) -> Event:
        """Store (or replace, after reconcile) the Applied record and move the plan."""
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO applied (applied_id, plan_hash, body) VALUES (?, ?, ?)"
                " ON CONFLICT (plan_hash) DO UPDATE SET applied_id = excluded.applied_id,"
                " body = excluded.body",
                (applied.applied_id, applied.plan_hash, _json(applied.to_obj())),
            )
            return self._cas(conn, applied.plan_hash, src, dst, actor, at, detail)

    def applied(self, plan_hash: str) -> Applied | None:
        row = self._conn.execute(
            "SELECT body FROM applied WHERE plan_hash = ?", (plan_hash,)
        ).fetchone()
        return Applied.model_validate(json.loads(row["body"])) if row else None

    def record_compensated(
        self,
        compensated: Compensated,
        src: State | None,
        dst: State | None,
        actor: Principal,
        at: datetime,
    ) -> Event | None:
        """Store a compensation record; move the plan unless ``dst`` is None (``skipped``)."""
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO compensations (compensation_id, plan_hash, body) VALUES (?, ?, ?)",
                (
                    compensated.compensation_id,
                    compensated.plan_hash,
                    _json(compensated.to_obj()),
                ),
            )
            if src is None or dst is None:
                return None
            detail = {"outcome": compensated.outcome}
            return self._cas(conn, compensated.plan_hash, src, dst, actor, at, detail)

    def compensations(self, plan_hash: str) -> list[Compensated]:
        rows = self._conn.execute(
            "SELECT body FROM compensations WHERE plan_hash = ? ORDER BY rowid", (plan_hash,)
        ).fetchall()
        return [Compensated.model_validate(json.loads(r["body"])) for r in rows]
