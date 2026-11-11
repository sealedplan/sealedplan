"""An agent that edits customer records, with a person approving every change.

Two processes share one plan store (a SQLite file):

- the agent (this script) proposes changes, then executes the ones a person approved;
- the person reviews and approves them with the ``sealedplan`` CLI.

Nothing else connects them. The agent never sees the approval step, and the person
never sees anything but the sealed plan.

Run the whole story at once::

    uv run python examples/sql_agent/crm_agent.py demo

or play both parts yourself, step by step: see README.md next to this file.
"""

from __future__ import annotations

import argparse
import shlex
import sqlite3
import sys
import tempfile
import uuid
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

from sealedplan import cli
from sealedplan.models import Principal
from sealedplan.providers.sql import Connection, Table, UpdateRow
from sealedplan.runtime import Runtime, SealedPlanError
from sealedplan.state import State
from sealedplan.store import SqliteStore, StoreError

ISSUER = "https://idp.example.com"
AGENT = Principal(id="crm-agent", issuer=ISSUER, kind="agent")
RUNTIME = Principal(id="crm-agent-runtime", issuer=ISSUER, kind="service")

# The only table and columns the agent may touch. Everything else is out of reach.
CUSTOMERS = Table(key="id", version="version", columns=("tier", "credit_limit"))

SCHEMA = """
CREATE TABLE customers (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    tier         TEXT NOT NULL,
    credit_limit INTEGER NOT NULL,
    version      INTEGER NOT NULL
);
INSERT INTO customers VALUES (1, 'Acme',   'silver', 1000, 1);
INSERT INTO customers VALUES (2, 'Globex', 'gold',   5000, 1);
"""


class Demo:
    """The two files the example works with: the business database and the plan store."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.crm = workdir / "crm.db"
        self.plans = workdir / "plans.db"

    def init(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.crm.unlink(missing_ok=True)
        self.plans.unlink(missing_ok=True)
        with closing(sqlite3.connect(self.crm)) as conn:
            conn.executescript(SCHEMA)
            conn.commit()
        SqliteStore(self.plans).close()
        print(f"created {self.crm} and an empty plan store {self.plans}")

    def connect(self) -> Connection:
        conn: Connection = sqlite3.connect(self.crm)
        return conn

    def runtime(self) -> Runtime:
        """What the agent process sets up: a runtime with the actions it may use."""
        if not self.plans.is_file():
            raise SystemExit(f"no plan store in {self.workdir}; run 'init' first")
        rt = Runtime(SqliteStore(self.plans), RUNTIME)
        rt.register(UpdateRow(self.connect, "crm", {"customers": CUSTOMERS}))
        return rt

    def rows(self) -> None:
        with closing(sqlite3.connect(self.crm)) as conn:
            rows = conn.execute("SELECT id, name, tier, credit_limit, version FROM customers")
            print("  id  name    tier    credit_limit  version")
            for row in rows:
                print("  {:<3} {:<7} {:<7} {:>12}  {:>7}".format(*row))

    # --- the agent's side ---------------------------------------------------------------

    def propose(self, customer: int, values: dict[str, Any]) -> str:
        proposal = self.runtime().propose(
            "sql.update_row",
            {"table": "customers", "key": customer, "values": values},
            agent=AGENT,
            idempotency_key=f"crm-{uuid.uuid4()}",  # one per request the agent makes
        )
        plan = proposal.plan
        print(f"agent proposed: {plan.summary}")
        print(f"  plan  {cli.short_hash(plan.plan_hash)}")
        print(f"  state {proposal.state} ({proposal.decision.decision} by policy)")
        return plan.plan_hash

    def execute(self, plan: str) -> State:
        rt = self.runtime()
        plan_hash = rt.store.find(plan).plan.plan_hash
        result = rt.execute(plan_hash)
        print(f"agent executed {cli.short_hash(plan_hash)}: {result.state}")
        for d in result.drift:
            print(f"  precondition {d.id}: approved at {d.expected}, now {d.observed}")
        if result.error:
            print(f"  error: {result.error}")
        return result.state

    def undo(self, plan: str) -> str:
        rt = self.runtime()
        plan_hash = rt.store.find(plan).plan.plan_hash
        outcome = rt.compensate(plan_hash).outcome
        print(f"agent compensated {cli.short_hash(plan_hash)}: {outcome}")
        return outcome

    # --- someone else -------------------------------------------------------------------

    def meddle(self, customer: int) -> None:
        """Another writer (a person, a batch job) edits the row behind the agent's back."""
        with closing(sqlite3.connect(self.crm)) as conn:
            conn.execute(
                "UPDATE customers SET credit_limit = credit_limit + 500, version = version + 1"
                " WHERE id = ?",
                (customer,),
            )
            conn.commit()
        print(f"someone else raised customer {customer}'s credit limit by 500")

    # --- the human's side, as shell commands --------------------------------------------

    def sealedplan(self, *args: str) -> int:
        """Run the ``sealedplan`` CLI, as the person would in their own terminal."""
        argv = ["--db", str(self.plans), *args]
        print(f"\n$ sealedplan {shlex.join(argv)}")
        return cli.main(argv)


def heading(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 74 - len(text)))


def demo(d: Demo) -> int:
    approve_as = ["--as", "bob", "--issuer", ISSUER, "--yes"]

    heading("1. Setup")
    d.init()
    d.rows()

    heading("2. The agent proposes a change. Nothing is written yet.")
    first = d.propose(1, {"tier": "gold", "credit_limit": 2000})
    d.rows()

    heading("3. A person reviews the sealed plan and approves it")
    d.sealedplan("list")
    # `approve` shows the full plan before recording anything (as `show` does).
    d.sealedplan("approve", cli.short_hash(first), *approve_as)

    heading("4. The agent executes exactly what was approved")
    d.execute(first)
    d.rows()

    heading("5. Drift: the row changes between approval and execution")
    second = d.propose(2, {"credit_limit": 9000})
    d.sealedplan("approve", cli.short_hash(second), *approve_as)
    d.meddle(2)
    d.execute(second)
    print("the approval was for the row as it was; nothing was written")
    d.rows()

    heading("6. Undo: compensate the first change")
    d.undo(first)
    d.rows()

    heading("7. The record")
    d.sealedplan("list", "--all")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dir",
        type=Path,
        help="where crm.db and plans.db live (default: ./sealedplan-demo; demo: a temp dir)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="run the whole story")
    sub.add_parser("init", help="create crm.db and an empty plan store")
    sub.add_parser("rows", help="print the customers table")
    p = sub.add_parser("propose", help="propose a change to one customer")
    p.add_argument("customer", type=int)
    p.add_argument("--tier")
    p.add_argument("--credit-limit", type=int)
    for name in ("execute", "undo"):
        sub.add_parser(name).add_argument("plan", help="plan hash or a unique prefix")
    sub.add_parser("meddle", help="change a row behind the agent's back").add_argument(
        "customer", type=int
    )
    args = parser.parse_args(argv)

    if args.command == "demo" and args.dir is None:
        with tempfile.TemporaryDirectory() as tmp:
            return demo(Demo(Path(tmp)))
    try:
        return run(Demo(args.dir or Path("sealedplan-demo")), args)
    except (SealedPlanError, StoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def run(d: Demo, args: argparse.Namespace) -> int:
    if args.command == "demo":
        return demo(d)
    if args.command == "init":
        d.init()
    elif args.command == "rows":
        d.rows()
    elif args.command == "propose":
        values = {"tier": args.tier, "credit_limit": args.credit_limit}
        d.propose(args.customer, {k: v for k, v in values.items() if v is not None})
    elif args.command == "execute":
        return 0 if d.execute(args.plan) is State.APPLIED else 1
    elif args.command == "undo":
        return 0 if d.undo(args.plan) == "succeeded" else 1
    elif args.command == "meddle":
        d.meddle(args.customer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
