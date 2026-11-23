"""examples/agent_sdk is documentation; this keeps the parts that need no model running.

Skipped unless the optional group is installed: ``uv sync --group dev --group agent-sdk``.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from mcp.client import Client
from mcp_types import ElicitRequestParams, ElicitResult, RequestParamsMeta

from sealedplan_mcp import EXTENSION_ID

pytest.importorskip("claude_agent_sdk")

EXAMPLES = Path(__file__).resolve().parents[3] / "examples"
CHANGE = {"table": "customers", "key": 1, "values": {"tier": "gold"}}

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def load(relative: str) -> ModuleType:
    path = EXAMPLES / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def elicitation(message: str) -> dict[str, Any]:
    """The hook input Claude Code sends when the CRM server asks for input."""
    return {"hook_event_name": "Elicitation", "mcp_server_name": "crm", "message": message}


async def test_hook_waits_for_approval_then_the_retry_applies(tmp_path: Path) -> None:
    crm_server = load("mcp_server/crm_server.py")
    assistant = load("agent_sdk/crm_assistant.py")
    hook = assistant.ApprovalHook(tmp_path / "plans.db", "dana", wait=10)

    async def claude_code(context: Any, params: ElicitRequestParams) -> ElicitResult:
        # What Claude Code does with the server's prompt in an SDK session.
        out = await hook(elicitation(params.message), None, {"signal": None})
        return ElicitResult(action=out["hookSpecificOutput"]["action"])

    async with Client(crm_server.build(tmp_path), elicitation_callback=claude_code) as client:
        result = await client.call_tool("sql_update_row", CHANGE)

    assert (result.meta or {})[EXTENSION_ID]["state"] == "APPLIED"
    with sqlite3.connect(tmp_path / "crm.db") as conn:
        assert conn.execute("SELECT tier FROM customers WHERE id = 1").fetchone() == ("gold",)


async def test_hook_gives_up_once_per_plan(tmp_path: Path) -> None:
    crm_server = load("mcp_server/crm_server.py")
    assistant = load("agent_sdk/crm_assistant.py")
    hook = assistant.ApprovalHook(tmp_path / "plans.db", None, wait=0.2)
    plan_only = cast(RequestParamsMeta, {EXTENSION_ID: {"mode": "plan"}})
    async with Client(crm_server.build(tmp_path)) as client:
        planned = await client.call_tool("sql_update_row", CHANGE, meta=plan_only)
    short = cast(dict[str, Any], planned.structured_content)["plan_hash"][7:19]

    message = f"Approval needed: Set tier (plan {short}). Approve it, then continue."
    for _ in range(2):  # the second prompt for the same plan is cancelled at once
        out = await hook(elicitation(message), None, {"signal": None})
        assert out["hookSpecificOutput"]["action"] == "cancel"
    assert await hook({**elicitation(message), "mcp_server_name": "other"}, None, {}) == {}


def test_agent_gets_only_the_crm_tool(tmp_path: Path) -> None:
    assistant = load("agent_sdk/crm_assistant.py")
    options = assistant.options(tmp_path, assistant.ApprovalHook(tmp_path / "p.db", None, 1))
    assert options.tools == []
    assert options.allowed_tools == ["mcp__crm__sql_update_row"]
    assert options.mcp_servers["crm"]["args"][-3:] == ["serve", "--dir", str(tmp_path)]
