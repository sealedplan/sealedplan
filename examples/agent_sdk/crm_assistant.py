"""A Claude agent that edits a CRM through MCP, and a person who approves each change.

The agent runs on the Claude Agent SDK and has exactly one tool: ``sql_update_row``,
served by the MCP server in ``examples/mcp_server``. The tool never writes directly.
The call waits (``input_required``) until a person approves the plan with the
``sealedplan`` CLI, and the retry then re-checks the row and applies.

Claude Code shows that wait as an MCP elicitation, and in an SDK session nobody is there
to answer it. This script answers it with an ``Elicitation`` hook. The hook shows the
person what to approve and waits until the plan is no longer pending, then accepts.
Accepting only tells Claude Code to retry the call. The approval itself comes from the
plan store.

It needs the optional dependency group and a Claude login (or ``ANTHROPIC_API_KEY``),
and each run costs a few cents::

    uv sync --group agent-sdk
    uv run python examples/agent_sdk/crm_assistant.py --dir /tmp/crm

Approve from another terminal with the command the script prints, or add
``--approve-as dana`` and the script approves for you, as the other demos do.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal, cast

import anyio
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ElicitationHookSpecificOutput,
    HookContext,
    HookInput,
    HookJSONOutput,
    HookMatcher,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)

from sealedplan import cli
from sealedplan.state import State
from sealedplan.store import SqliteStore

SERVER = Path(__file__).resolve().parents[1] / "mcp_server" / "crm_server.py"
TOOL = "mcp__crm__sql_update_row"  # Claude Code names MCP tools mcp__<server>__<tool>
ISSUER = "https://idp.example.com"
PROMPT = "Upgrade customer 1 in the CRM to the gold tier."


class ApprovalHook:
    """Answers the CRM server's approval prompt once the plan leaves PENDING_APPROVAL."""

    def __init__(self, plans: Path, approve_as: str | None, wait: float) -> None:
        self.plans = plans
        self.approve_as = approve_as
        self.wait = wait
        self.deadlines: dict[str, float] = {}
        self._store: SqliteStore | None = None

    async def __call__(
        self, data: HookInput, tool_use_id: str | None, context: HookContext
    ) -> HookJSONOutput:
        event = cast(dict[str, Any], data)
        found = re.search(r"\(plan ([0-9a-f]+)\)", str(event.get("message", "")))
        if event.get("mcp_server_name") != "crm" or found is None:
            return {}  # not ours: Claude Code handles it as usual
        short = found.group(1)
        if short not in self.deadlines:
            # One deadline per plan: once it passes, later prompts for this plan are
            # cancelled at once, so the tool call fails instead of waiting again.
            self.deadlines[short] = time.monotonic() + self.wait
            print(f"\n  {event['message']}")
            if self.approve_as is not None:
                self.approve(short, self.approve_as)
        while time.monotonic() < self.deadlines[short]:
            state = self.store.find(short).state
            if state is not State.PENDING_APPROVAL:
                print(f"  plan {short} is now {state}; the agent retries the call\n")
                return answer("accept")  # retry; the server reads the decision itself
            await anyio.sleep(0.5)
        print(f"  plan {short} is still waiting; giving up\n")
        return answer("cancel")

    @property
    def store(self) -> SqliteStore:
        # Opened on first use: the server creates plans.db when it proposes the plan.
        if self._store is None:
            self._store = SqliteStore(self.plans)
        return self._store

    def approve(self, short: str, person: str) -> None:
        args = ["--db", str(self.plans), "approve", short, "--as", person]
        print(f"  {person} runs: sealedplan {' '.join(args[2:])}")
        cli.main([*args, "--issuer", ISSUER, "--yes"])


def answer(action: Literal["accept", "cancel"]) -> HookJSONOutput:
    output: ElicitationHookSpecificOutput = {"hookEventName": "Elicitation", "action": action}
    return {"hookSpecificOutput": output}


def options(workdir: Path, hook: ApprovalHook) -> ClaudeAgentOptions:
    """The agent may call the CRM tool and nothing else."""
    hooks = {"Elicitation": [HookMatcher(hooks=[hook], timeout=hook.wait + 30)]}
    return ClaudeAgentOptions(
        mcp_servers={
            "crm": {
                "command": sys.executable,
                "args": [str(SERVER), "serve", "--dir", str(workdir)],
            }
        },
        tools=[],  # no built-in tools: no shell, no file access
        allowed_tools=[TOOL],
        strict_mcp_config=True,  # ignore MCP servers from the user's own settings
        setting_sources=[],
        hooks=cast(Any, hooks),
        # input_required is part of MCP 2026-07-28. Claude Code's v2 MCP runtime speaks
        # it (and is the default); the older v1 runtime rejects the result.
        env={"MCP_SDK_GENERATION": "v2"},
        cwd=str(workdir),
        max_turns=8,
        max_budget_usd=0.25,
    )


async def run(prompt: str, workdir: Path, approve_as: str | None, wait: float) -> int:
    workdir.mkdir(parents=True, exist_ok=True)
    hook = ApprovalHook(workdir / "plans.db", approve_as, wait)
    if approve_as is None:
        print(f"Approve from another terminal:\n  sealedplan --db {hook.plans} list")
    print(f"\nyou: {prompt}")
    ok = False
    async for message in query(prompt=prompt, options=options(workdir, hook)):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(f"agent: {block.text}")
                elif isinstance(block, ToolUseBlock):
                    print(f"agent calls {block.name} {block.input}")
        elif isinstance(message, UserMessage) and isinstance(message.content, list):
            for block in message.content:
                if isinstance(block, ToolResultBlock):
                    flag = " (error)" if block.is_error else ""
                    print(f"tool result{flag}: {str(block.content)[:200]}")
        elif isinstance(message, ResultMessage):
            ok = message.subtype == "success" and not message.is_error
            cost = message.total_cost_usd or 0.0
            print(f"\n[{message.subtype}, {message.num_turns} turns, ${cost:.4f}]")
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("prompt", nargs="?", default=PROMPT, help="what to ask the agent")
    parser.add_argument("--dir", type=Path, help="where crm.db and plans.db live")
    parser.add_argument("--approve-as", help="approve each plan as this person, for a demo")
    parser.add_argument("--wait", type=float, default=300, help="seconds to wait for a person")
    args = parser.parse_args(argv)
    if args.dir is not None:
        return anyio.run(run, args.prompt, args.dir, args.approve_as, args.wait)
    with tempfile.TemporaryDirectory() as tmp:
        return anyio.run(run, args.prompt, Path(tmp), args.approve_as, args.wait)


if __name__ == "__main__":
    sys.exit(main())
