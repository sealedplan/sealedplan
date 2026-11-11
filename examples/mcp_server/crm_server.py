"""An MCP server whose tool proposes a change, waits for a person, then applies it.

The server exposes the reference ``sql.update_row`` action on a small customer
database as one MCP tool, ``sql_update_row``. Calling it never writes directly: the
call returns ``input_required`` until a person approves the plan with the
``sealedplan`` CLI, and the client's retry then re-checks the row and applies.

Run the end-to-end demo (an MCP client in the same process plays the agent, and the
real CLI plays the person)::

    uv run python examples/mcp_server/crm_server.py demo

Or serve it over stdio for an MCP client, and approve from another terminal::

    uv run python examples/mcp_server/crm_server.py serve --dir /tmp/crm
    sealedplan --db /tmp/crm/plans.db list
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import anyio
from mcp.client import Client
from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, ElicitRequestParams, ElicitResult, RequestParamsMeta

from sealedplan import cli
from sealedplan.models import Principal
from sealedplan.providers.sql import Table, UpdateRow
from sealedplan.runtime import Runtime
from sealedplan.store import SqliteStore
from sealedplan_mcp import EXTENSION_ID, create_server

ISSUER = "https://idp.example.com"
AGENT = Principal(id="crm-agent", issuer=ISSUER, kind="agent")
RUNTIME = Principal(id="crm-runtime", issuer=ISSUER, kind="service")

SCHEMA = """
CREATE TABLE customers (
    id INTEGER PRIMARY KEY, name TEXT, tier TEXT, credit_limit INTEGER, version INTEGER
);
INSERT INTO customers VALUES (1, 'Acme',   'silver', 1000, 1);
INSERT INTO customers VALUES (2, 'Globex', 'gold',   5000, 1);
"""


def build(workdir: Path) -> MCPServer:
    """The CRM database, the plan store, and an MCP server over both."""
    workdir.mkdir(parents=True, exist_ok=True)
    crm = workdir / "crm.db"
    if not crm.exists():
        with sqlite3.connect(crm) as conn:
            conn.executescript(SCHEMA)
    rt = Runtime(SqliteStore(workdir / "plans.db"), RUNTIME)
    rt.register(
        UpdateRow(
            lambda: sqlite3.connect(crm),
            "crm",
            {"customers": Table(key="id", version="version", columns=("tier", "credit_limit"))},
        )
    )
    hint = f"sealedplan --db {workdir / 'plans.db'} approve {{short}} --as <you> --issuer <idp>"
    return create_server(rt, agent=AGENT, name="crm", approve_hint=hint)


def show(label: str, result: CallToolResult) -> None:
    state = (result.meta or {}).get(EXTENSION_ID, {}).get("state", "?")
    text = " ".join(getattr(c, "text", "") for c in result.content)
    print(f"  {label}: {state}{' (error)' if result.is_error else ''}\n    {text}")


async def demo(workdir: Path) -> int:
    plans = str(workdir / "plans.db")

    async def person(context: Any, params: ElicitRequestParams) -> ElicitResult:
        # What the MCP client shows the person while the plan waits.
        print(f"  client shows: {params.message}")
        short = params.message.split("(plan ")[1].split(")")[0]
        args = ["--db", plans, "approve", short, "--as", "dana", "--issuer", ISSUER, "--yes"]
        print(f"  dana runs: sealedplan {' '.join(args[2:])}")
        cli.main(args)
        return ElicitResult(action="accept")  # tells the client to retry; not an approval

    async with Client(build(workdir), elicitation_callback=person) as client:
        print("\n1. The agent calls the tool. It waits for Dana, then applies.")
        change = {"table": "customers", "key": 1, "values": {"tier": "gold"}}
        show("result", await client.call_tool("sql_update_row", change))

        print("\n2. An agent that knows the extension asks for the plan first.")
        raise_limit = {"table": "customers", "key": 2, "values": {"credit_limit": 9000}}
        planned = await client.call_tool("sql_update_row", raise_limit, meta=mode("plan"))
        show("plan", planned)
        plan_hash = cast(dict[str, Any], planned.structured_content)["plan_hash"]
        short = plan_hash.removeprefix("sha256:")[:12]
        cli.main(["--db", plans, "approve", short, "--as", "dana", "--issuer", ISSUER, "--yes"])

        print("\n3. Someone edits the row before the agent applies. Nothing is written.")
        with sqlite3.connect(workdir / "crm.db") as conn:
            conn.execute(
                "UPDATE customers SET credit_limit = 6000, version = version + 1 WHERE id = 2"
            )
        applied = await client.call_tool(
            "sql_update_row", raise_limit, meta=mode("apply", plan_hash=plan_hash)
        )
        show("apply", applied)

    with sqlite3.connect(workdir / "crm.db") as conn:
        rows = conn.execute("SELECT id, tier, credit_limit FROM customers ORDER BY id").fetchall()
    print(f"\ncustomers: {rows}")
    return 0


def mode(name: str, **extra: str) -> RequestParamsMeta:
    """Request ``_meta`` for explicit mode (SPEC §12.5)."""
    return cast(RequestParamsMeta, {EXTENSION_ID: {"mode": name, **extra}})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("command", choices=["demo", "serve"])
    parser.add_argument("--dir", type=Path, help="where crm.db and plans.db live")
    args = parser.parse_args(argv)
    if args.command == "serve":
        if args.dir is None:
            parser.error("serve needs --dir, so the approver can find plans.db")
        build(args.dir).run()
        return 0
    if args.dir is not None:
        return anyio.run(demo, args.dir)
    with tempfile.TemporaryDirectory() as tmp:
        return anyio.run(demo, Path(tmp))


if __name__ == "__main__":
    sys.exit(main())
