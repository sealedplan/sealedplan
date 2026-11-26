"""Gate LangGraph tools on sealedplan: the plan is the interrupt, resume needs its hash.

:func:`sealedplan_tool` turns a registered action into a LangChain tool for a LangGraph
agent (``ToolNode``, ``create_react_agent``). A call never changes the target system
directly. It builds a plan and runs policy:

- ``auto``: the plan is applied and the tool returns the outcome.
- ``deny``: the tool returns the denial; nothing is written.
- ``approve`` / ``two_person``: the graph pauses with :func:`langgraph.types.interrupt`,
  and the interrupt's value is the plan. A person approves the plan out of band, for
  example with the ``sealedplan`` CLI, and the application resumes the graph with
  ``Command(resume={"plan_hash": ...})``. The tool then drift-checks and applies.

The resume value only says *which* plan to continue. It is never an approval: approval
is read from the runtime's store (SPEC §12.4). A resume that names another plan is
refused, and one that arrives before approval pauses again.

LangGraph re-runs a node from the start when it resumes. One tool call therefore maps to
one plan: the idempotency key comes from the tool call's id, and a re-run finds the plan
the first run stored instead of proposing a new one.
"""

from __future__ import annotations

import inspect
import threading
import typing
import weakref
from collections.abc import Mapping, Sequence
from typing import Annotated, Any

from langchain_core.tools import BaseTool, InjectedToolCallId, StructuredTool
from langgraph.types import interrupt
from pydantic import create_model

from sealedplan.canonical import digest
from sealedplan.models import Parent, Principal
from sealedplan.policy import Decision
from sealedplan.runtime import Execution, Runtime
from sealedplan.state import State
from sealedplan.store import PlanRecord

__all__ = ["INTERRUPT_KIND", "run_action", "sealedplan_tool", "sealedplan_tools"]

INTERRUPT_KIND = "io.github.sealedplan/plan-apply"

# The SQLite store shares one connection; ToolNode may run tools on several threads.
# Runtime is an unhashable dataclass, so locks are keyed by id and dropped with it.
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock(runtime: Runtime) -> threading.Lock:
    with _locks_guard:
        key = id(runtime)
        if key not in _locks:
            _locks[key] = threading.Lock()
            weakref.finalize(runtime, _locks.pop, key, None)
        return _locks[key]


def run_action(
    runtime: Runtime,
    action_name: str,
    params: Mapping[str, Any],
    *,
    agent: Principal,
    idempotency_key: str,
    sponsor: Principal | None = None,
    parent: Parent | None = None,
) -> dict[str, Any]:
    """Plan, wait for approval through ``interrupt``, and apply. Call it inside a node.

    ``idempotency_key`` names this one call. A re-run with the same key and params
    continues the plan the first run stored, whatever its state.
    """
    with _lock(runtime):
        record = _existing(runtime, action_name, params, idempotency_key)
        if record is None:
            proposal = runtime.propose(
                action_name,
                params,
                agent=agent,
                idempotency_key=idempotency_key,
                sponsor=sponsor,
                parent=parent,
            )
            record = runtime.store.get(proposal.plan.plan_hash)
    plan_hash = record.plan.plan_hash

    # A plan that needs a person always pauses, so every run after the first one meets
    # the same interrupt and its resume value is checked, even if approval came first.
    while record.decision in (Decision.APPROVE, Decision.TWO_PERSON):
        if record.state is State.PENDING_APPROVAL and runtime.now() >= record.plan.expires_at:
            with _lock(runtime):
                runtime.expire_due()
                record = runtime.store.get(plan_hash)
            break
        answer = interrupt(_interrupt_value(record))
        if not isinstance(answer, Mapping) or answer.get("plan_hash") != plan_hash:
            return _outcome(record, error="the resume value names a different plan")
        with _lock(runtime):
            record = runtime.store.get(plan_hash)
        if record.state is not State.PENDING_APPROVAL:
            break

    if record.state is State.APPROVED:
        with _lock(runtime):
            execution = runtime.execute(plan_hash, applier=agent)
            record = runtime.store.get(plan_hash)
        return _outcome(record, execution)
    return _outcome(record)


def _existing(
    runtime: Runtime, action_name: str, params: Mapping[str, Any], key: str
) -> PlanRecord | None:
    wanted = digest(dict(params))
    same = [
        r
        for r in runtime.store.by_idempotency_key(action_name, key)
        if digest(r.plan.params) == wanted
    ]
    return same[-1] if same else None


def _interrupt_value(record: PlanRecord) -> dict[str, Any]:
    plan = record.plan
    return {
        "kind": INTERRUPT_KIND,
        "plan_hash": plan.plan_hash,
        "summary": plan.summary,
        "state": str(record.state),
        "expires_at": plan.expires_at.isoformat(),
        "plan": plan.to_obj(),
        "resume": {"plan_hash": plan.plan_hash},
    }


_MESSAGES = {
    State.APPLIED: "Applied",
    State.DRIFTED: "Not applied: the system changed since the plan was made. Nothing was "
    "written; call the tool again for a new plan",
    State.FAILED: "Not applied: the target system refused the change",
    State.UNKNOWN: "The change may or may not have happened; a person will reconcile it",
    State.DENIED: "Policy denied this change",
    State.REJECTED: "A person rejected this change",
    State.EXPIRED: "The plan expired before it was approved and applied",
}


def _outcome(
    record: PlanRecord, execution: Execution | None = None, *, error: str | None = None
) -> dict[str, Any]:
    """What the tool returns to the model: JSON-ready, never the raw exception."""
    plan = record.plan
    message = _MESSAGES.get(record.state, f"The plan is {record.state}")
    out: dict[str, Any] = {
        "state": str(record.state),
        "plan_hash": plan.plan_hash,
        "summary": plan.summary,
        "message": f"{message}: {plan.summary}",
    }
    if execution is not None:
        if execution.applied is not None:
            out["applied"] = execution.applied.to_obj()
        if execution.drift:
            out["failed_preconditions"] = [r.to_obj() for r in execution.drift]
        if execution.deviation:
            out["deviation"] = [d.to_obj() for d in execution.deviation]
        if execution.error:
            out["error"] = execution.error
    if error is not None:
        out["error"] = error
    return out


# --- tools ------------------------------------------------------------------------------


def sealedplan_tool(
    runtime: Runtime,
    action_name: str,
    *,
    agent: Principal,
    sponsor: Principal | None = None,
    name: str | None = None,
    description: str | None = None,
) -> BaseTool:
    """A LangChain tool for one registered action; its arguments are ``plan()``'s."""
    bound = runtime.actions()[action_name]
    hints = typing.get_type_hints(bound.plan, include_extras=True)
    fields: dict[str, Any] = {}
    for p in list(inspect.signature(bound.plan).parameters.values())[1:]:  # drop ctx
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            raise TypeError(f"{action_name}: plan() cannot take *args or **kwargs")
        default = ... if p.default is inspect.Parameter.empty else p.default
        fields[p.name] = (hints.get(p.name, Any), default)
    fields["tool_call_id"] = (Annotated[str, InjectedToolCallId], ...)
    schema = create_model(f"{action_name.replace('.', '_')}_args", **fields)

    def call(tool_call_id: str, **params: Any) -> dict[str, Any]:
        return run_action(
            runtime,
            action_name,
            params,
            agent=agent,
            sponsor=sponsor,
            idempotency_key=f"langgraph-{tool_call_id}",
        )

    owner = getattr(bound.plan, "__self__", None)
    doc = inspect.getdoc(bound.plan) or (owner and inspect.getdoc(type(owner))) or action_name
    return StructuredTool.from_function(
        func=call,
        name=name or action_name.replace(".", "_"),
        description=description or f"{doc}\n\nChanges go through plan, approval and drift check.",
        args_schema=schema,
    )


def sealedplan_tools(
    runtime: Runtime,
    *,
    agent: Principal,
    sponsor: Principal | None = None,
    actions: Sequence[str] | None = None,
) -> list[BaseTool]:
    """One tool per registered action (or per name in ``actions``)."""
    names = actions if actions is not None else list(runtime.actions())
    return [sealedplan_tool(runtime, n, agent=agent, sponsor=sponsor) for n in names]
