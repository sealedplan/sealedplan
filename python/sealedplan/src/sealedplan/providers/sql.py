"""Reference action: update one row in a SQL table that has a version column.

Works with any DB-API 2.0 driver (``sqlite3`` in the standard library, psycopg, ...).
Pass a function that opens a connection and the driver's placeholder (``?`` for
sqlite3, ``%s`` for psycopg).

Agents choose tables and columns only from the :class:`Table` allowlist given to the
action; identifiers never come from the agent, and values are always bound parameters.

The version column is the precondition, enforced by the database itself::

    UPDATE t SET ..., version = version + 1 WHERE id = ? AND version = ?

If another writer touched the row since the plan was made, no row matches and nothing
is written. Columns an action reads must hold integers, strings, booleans or NULL:
plans are canonical JSON, which has no floats (SPEC §6.2).

The action is REVERSIBLE: compensation writes the old values back under the same
version check. Triggers or cascades on the table can make that untrue; declare such
tables with a different action.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from typing import Any, Protocol

from sealedplan.actions import (
    ApplyFailedError,
    CompensationConflictError,
    Context,
    PreconditionFailedError,
    action,
)
from sealedplan.models import (
    Applied,
    BlastRadius,
    Change,
    Compensation,
    Effect,
    Plan,
    Precondition,
    ResourceRef,
)
from sealedplan.preconditions import ABSENT, Observation, PreconditionResult
from sealedplan.state import State

RESOURCE_TYPE = "sql/row"
PRECONDITION_ID = "row-version"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Cursor(Protocol):
    @property
    def rowcount(self) -> int: ...

    def execute(self, sql: str, parameters: Sequence[Any], /) -> object: ...

    def fetchone(self) -> Any: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class Table:
    """A table agents may update.

    ``columns`` are the columns an agent may change; they are also what ``observe``
    reports, so a change to any of them after apply blocks compensation.
    ``key_type`` turns the key back from its text form in a resource id.
    """

    key: str
    version: str
    columns: tuple[str, ...]
    key_type: Callable[[str], Any] = int

    def __post_init__(self) -> None:
        for name in (self.key, self.version, *self.columns):
            if not _IDENTIFIER.fullmatch(name):
                raise ValueError(f"not a plain SQL identifier: {name!r}")


def _q(name: str) -> str:
    return f'"{name}"'


def _scalar(column: str, value: object) -> object:
    if value is None or isinstance(value, str | int):  # bool is an int
        return value
    raise ValueError(
        f"column {column} holds {type(value).__name__}; plans carry only integers, "
        "strings, booleans and NULL"
    )


@action(
    "sql.update_row",
    effect=Effect.REVERSIBLE,
    risk="medium",
    version="1.0.0",
    provider="sealedplan-sql",
)
class UpdateRow:
    def __init__(
        self,
        connect: Callable[[], Connection],
        database: str,
        tables: Mapping[str, Table],
        *,
        placeholder: str = "?",
    ) -> None:
        for name in tables:
            if not _IDENTIFIER.fullmatch(name):
                raise ValueError(f"not a plain SQL identifier: {name!r}")
        self.connect = connect
        self.database = database
        self.tables = dict(tables)
        self.ph = placeholder

    # --- helpers ----------------------------------------------------------------------

    def _table(self, name: str) -> Table:
        try:
            return self.tables[name]
        except KeyError:
            raise ValueError(f"table {name!r} is not one this action may change") from None

    def _ref(self, table: str, key: object) -> ResourceRef:
        return ResourceRef(type=RESOURCE_TYPE, id=f"sql://{self.database}/{table}/{key}")

    def _locate(self, resource: ResourceRef) -> tuple[str, Any]:
        prefix = f"sql://{self.database}/"
        if resource.type != RESOURCE_TYPE or not resource.id.startswith(prefix):
            raise ValueError(f"not a row in {self.database}: {resource.id}")
        table, _, key = resource.id.removeprefix(prefix).partition("/")
        return table, self._table(table).key_type(key)

    def _read(self, table: str, key: object) -> tuple[int, dict[str, Any]] | None:
        """``(version, {column: value})`` for the allowlisted columns, or None."""
        spec = self._table(table)
        cols = ", ".join(_q(c) for c in (spec.version, *spec.columns))
        sql = f"SELECT {cols} FROM {_q(table)} WHERE {_q(spec.key)} = {self.ph}"  # noqa: S608
        with closing(self.connect()) as conn:
            cur = conn.cursor()
            cur.execute(sql, [key])
            row = cur.fetchone()
            conn.rollback()
        if row is None:
            return None
        version, *values = row
        return int(version), {c: _scalar(c, v) for c, v in zip(spec.columns, values, strict=True)}

    def _write(
        self, table: str, key: object, values: Mapping[str, Any], expect_version: int
    ) -> bool:
        """Conditional update. True if it committed; False if the version did not match.

        Errors before commit roll back and raise ApplyFailedError. An error from commit
        itself propagates: the write may or may not have landed.
        """
        spec = self._table(table)
        sets = ", ".join(f"{_q(c)} = {self.ph}" for c in values)
        sql = (
            f"UPDATE {_q(table)} SET {sets}, {_q(spec.version)} = {_q(spec.version)} + 1 "  # noqa: S608
            f"WHERE {_q(spec.key)} = {self.ph} AND {_q(spec.version)} = {self.ph}"
        )
        with closing(self.connect()) as conn:
            try:
                cur = conn.cursor()
                cur.execute(sql, [*values.values(), key, expect_version])
                matched = cur.rowcount
            except Exception as exc:
                conn.rollback()
                raise ApplyFailedError(f"{type(exc).__name__}: {exc}") from exc
            if matched != 1:
                conn.rollback()
                if matched > 1:
                    raise ApplyFailedError(f"key matched {matched} rows; is it the primary key?")
                return False
            conn.commit()
        return True

    @staticmethod
    def _expected_version(plan: Plan) -> int:
        pre = next(p for p in plan.preconditions if p.id == PRECONDITION_ID)
        return int(pre.expect or 0)

    # --- the action -------------------------------------------------------------------

    def plan(self, ctx: Context, table: str, key: Any, values: Mapping[str, Any]) -> Plan:
        spec = self._table(table)
        if not values:
            raise ValueError("values must name at least one column")
        for column, value in values.items():
            if column not in spec.columns:
                raise ValueError(f"column {column!r} of {table} is not one this action may change")
            _scalar(column, value)
        found = self._read(table, key)
        if found is None:
            raise ValueError(f"no row in {table} with {spec.key} = {key!r}")
        version, current = found
        before = {c: current[c] for c in values}
        ref = self._ref(table, key)
        return ctx.plan(
            summary=f"Set {', '.join(values)} on {table} row {spec.key}={key}",
            changes=[Change(resource=ref, op="update", before=before, after=dict(values))],
            preconditions=[
                Precondition(
                    id=PRECONDITION_ID,
                    resource=ref,
                    kind="version",
                    expect=str(version),
                    enforcement="atomic",
                )
            ],
            blast_radius=BlastRadius(resources=1, scopes=[f"sql://{self.database}/{table}"]),
            compensation=Compensation(
                strategy="restore",
                summary=f"Write back the previous values of {', '.join(values)}",
                params={"values": before},
            ),
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        found = self._read(*self._locate(resource))
        if found is None:
            return ABSENT
        version, state = found
        return Observation(True, str(version), state)

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        table, key = plan.params["table"], plan.params["key"]
        expected = self._expected_version(plan)
        if self._write(table, key, plan.params["values"], expected):
            return ctx.applied(plan, result={"version": expected + 1})
        found = self._read(table, key)
        observed = "absent" if found is None else str(found[0])
        raise PreconditionFailedError(
            [PreconditionResult(PRECONDITION_ID, False, str(expected), observed)]
        )

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        table, key = plan.params["table"], plan.params["key"]
        after_apply = self._expected_version(plan) + 1
        if not self._write(table, key, plan.compensation.params["values"], after_apply):
            raise CompensationConflictError("the row changed since apply")

    def reconcile(self, ctx: Context, plan: Plan, applied: Applied | None) -> State:
        """Decide an UNKNOWN apply (for example, a lost connection during commit)."""
        found = self._read(plan.params["table"], plan.params["key"])
        if found is None:
            return State.UNKNOWN
        version, current = found
        expected = self._expected_version(plan)
        if version == expected:
            return State.FAILED  # the version never moved, so the write did not land
        values = plan.params["values"]
        if version == expected + 1 and all(current[c] == v for c, v in values.items()):
            return State.APPLIED
        return State.UNKNOWN  # someone else wrote too; a human decides
