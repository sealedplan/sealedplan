from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from conftest import T0
from sealedplan.models import Plan
from sealedplan.providers.sql import Table, UpdateRow
from sealedplan.runtime import Runtime
from sealedplan.state import State
from sealedplan.store import SqliteStore
from test_runtime import AGENT, ALICE, BOB, RUNTIME, Clock, approval

ROW_ID = "sql://crm/customers/1"


@dataclass
class Db:
    """A real SQLite file, with a switch to make the next commit fail."""

    path: Path
    commit_fails: str | None = None  # "before" or "after" the real commit
    before_update: Callable[[], None] | None = None

    def connect(self) -> Any:
        return _Conn(self, sqlite3.connect(self.path))

    def sql(self, statement: str, *params: Any) -> Any:
        with sqlite3.connect(self.path) as conn:
            return conn.execute(statement, params).fetchall()

    def row(self) -> tuple[Any, ...]:
        return tuple(self.sql("SELECT tier, credit_limit, version FROM customers WHERE id = 1")[0])


class _Cursor:
    def __init__(self, db: Db, cur: sqlite3.Cursor) -> None:
        self.db, self.cur = db, cur

    @property
    def rowcount(self) -> int:
        return self.cur.rowcount

    def execute(self, statement: str, params: Sequence[Any], /) -> object:
        if statement.startswith("UPDATE") and self.db.before_update:
            hook, self.db.before_update = self.db.before_update, None
            hook()
        return self.cur.execute(statement, params)

    def fetchone(self) -> Any:
        return self.cur.fetchone()


class _Conn:
    def __init__(self, db: Db, conn: sqlite3.Connection) -> None:
        self.db, self.conn = db, conn

    def cursor(self) -> _Cursor:
        return _Cursor(self.db, self.conn.cursor())

    def commit(self) -> None:
        when, self.db.commit_fails = self.db.commit_fails, None
        if when == "after":
            self.conn.commit()
        if when:
            raise sqlite3.OperationalError("connection lost during commit")
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def close(self) -> None:
        self.conn.close()


@dataclass
class SqlEnv:
    db: Db
    rt: Runtime
    store: SqliteStore

    def propose(self, **values: Any) -> Plan:
        params: dict[str, Any] = {
            "table": "customers",
            "key": 1,
            "values": values or {"tier": "gold"},
        }
        key = f"update-{sorted(params['values'].items())}"
        return self.rt.propose(
            "sql.update_row", params, agent=AGENT, sponsor=ALICE, idempotency_key=key
        ).plan

    def approved(self, **values: Any) -> Plan:
        plan = self.propose(**values)
        assert self.rt.submit_approval(approval(plan, BOB)) is State.APPROVED
        return plan

    def state(self, plan: Plan) -> State:
        return self.store.get(plan.plan_hash).state


CUSTOMERS = Table(key="id", version="version", columns=("tier", "credit_limit"))


@pytest.fixture
def sql(tmp_path: Path) -> SqlEnv:
    db = Db(tmp_path / "crm.db")
    db.sql(
        "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, tier TEXT,"
        " credit_limit INTEGER, version INTEGER NOT NULL)"
    )
    db.sql("INSERT INTO customers VALUES (1, 'Acme', 'silver', 1000, 4)")
    store = SqliteStore()
    rt = Runtime(store, RUNTIME, clock=Clock(T0))
    rt.register(UpdateRow(db.connect, "crm", {"customers": CUSTOMERS}))
    return SqlEnv(db, rt, store)


def someone_else_writes(db: Db) -> None:
    db.sql("UPDATE customers SET credit_limit = 5000, version = version + 1 WHERE id = 1")


# --- plan -----------------------------------------------------------------------------


def test_plan(sql: SqlEnv) -> None:
    plan = sql.propose(tier="gold")
    [change] = plan.changes
    assert (change.resource.id, change.before, change.after) == (
        ROW_ID,
        {"tier": "silver"},
        {"tier": "gold"},
    )
    [pre] = plan.preconditions
    assert (pre.kind, pre.expect, pre.enforcement) == ("version", "4", "atomic")
    assert plan.compensation is not None
    assert plan.compensation.params == {"values": {"tier": "silver"}}
    assert sql.db.row() == ("silver", 1000, 4)


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"table": "users", "key": 1, "values": {"tier": "x"}}, "not one this action may change"),
        ({"table": "customers", "key": 1, "values": {"name": "x"}}, "not one this action"),
        ({"table": "customers", "key": 1, "values": {}}, "at least one column"),
        ({"table": "customers", "key": 9, "values": {"tier": "x"}}, "no row"),
        ({"table": "customers", "key": 1, "values": {"credit_limit": 1.5}}, "float"),
    ],
)
def test_bad_requests(sql: SqlEnv, params: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        sql.rt.propose("sql.update_row", params, agent=AGENT, idempotency_key="x")


def test_identifiers_are_checked() -> None:
    with pytest.raises(ValueError, match="identifier"):
        Table(key="id; DROP TABLE x", version="version", columns=())


# --- apply ----------------------------------------------------------------------------


def test_apply(sql: SqlEnv) -> None:
    plan = sql.approved(tier="gold", credit_limit=2000)
    result = sql.rt.execute(plan.plan_hash)
    assert result.state is State.APPLIED
    assert sql.db.row() == ("gold", 2000, 5)


def test_drift_refuses_apply(sql: SqlEnv) -> None:
    plan = sql.approved()
    someone_else_writes(sql.db)
    result = sql.rt.execute(plan.plan_hash)
    assert result.state is State.DRIFTED
    assert [(d.expected, d.observed) for d in result.drift] == [("4", "5")]
    assert sql.db.row() == ("silver", 5000, 5)


def test_write_between_check_and_update_matches_no_row(sql: SqlEnv) -> None:
    plan = sql.approved()
    sql.db.before_update = lambda: someone_else_writes(sql.db)
    assert sql.rt.execute(plan.plan_hash).state is State.DRIFTED
    assert sql.db.row() == ("silver", 5000, 5)


def test_database_error_is_failed(sql: SqlEnv) -> None:
    plan = sql.approved()
    sql.db.sql(
        "CREATE TRIGGER no_gold BEFORE UPDATE ON customers WHEN NEW.tier = 'gold' "
        "BEGIN SELECT RAISE(ABORT, 'gold is closed'); END"
    )
    result = sql.rt.execute(plan.plan_hash)
    assert result.state is State.FAILED
    assert result.applied is not None
    assert "gold is closed" in (result.applied.error or "")
    assert sql.db.row() == ("silver", 1000, 4)


def test_commit_lost_before_write_reconciles_failed(sql: SqlEnv) -> None:
    plan = sql.approved()
    sql.db.commit_fails = "before"
    assert sql.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert sql.rt.reconcile(plan.plan_hash) is State.FAILED
    assert sql.db.row() == ("silver", 1000, 4)


def test_commit_lost_after_write_reconciles_applied(sql: SqlEnv) -> None:
    plan = sql.approved()
    sql.db.commit_fails = "after"
    assert sql.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert sql.rt.reconcile(plan.plan_hash) is State.APPLIED
    assert sql.db.row() == ("gold", 1000, 5)


# --- compensate -----------------------------------------------------------------------


def test_compensate(sql: SqlEnv) -> None:
    plan = sql.approved(tier="gold", credit_limit=2000)
    sql.rt.execute(plan.plan_hash)
    assert sql.rt.compensate(plan.plan_hash).outcome == "succeeded"
    assert sql.db.row() == ("silver", 1000, 6)
    assert sql.state(plan) is State.COMPENSATED


def test_compensate_does_not_overwrite_a_later_change(sql: SqlEnv) -> None:
    plan = sql.approved()
    sql.rt.execute(plan.plan_hash)
    someone_else_writes(sql.db)
    assert sql.rt.compensate(plan.plan_hash).outcome == "conflict"
    assert sql.db.row() == ("gold", 5000, 6)
