"""Gate OpenAI Agents SDK tools on sealedplan: the run pauses on the plan.

:func:`sealedplan_tool` turns a registered action into a ``FunctionTool``. A call never
changes the target system directly. It builds a plan and runs policy:

- ``auto``: the plan is applied and the tool returns the outcome.
- ``deny``: the tool returns the denial; nothing is written.
- ``approve`` / ``two_person``: the tool needs approval, so the run stops with a
  ``ToolApprovalItem`` in ``result.interruptions``. A person approves the plan out of
  band, for example with the ``sealedplan`` CLI. :func:`resolve_approvals` then copies
  the store's decisions onto the run state, and the application resumes the run.

The SDK's approval only lets the run continue. It is never the approval itself: the tool
reads approval from the runtime's store (SPEC §12.4), so a call approved in the run but
not in the store writes nothing.

One tool call maps to one plan: the idempotency key comes from the call's id, so the
approval check and the later invocation find the same plan.
"""

from __future__ import annotations

import inspect
import json
import threading
import typing
import weakref
from collections.abc import Mapping, Sequence
from typing import Any

from agents import FunctionTool, RunContextWrapper, RunState, Tool
from agents.tool_context import ToolContext
from pydantic import BaseModel, create_model

from sealedplan.canonical import digest
from sealedplan.models import Principal
from sealedplan.policy import Decision
from sealedplan.runtime import Execution, Runtime
from sealedplan.state import State
from sealedplan.store import PlanRecord

__all__ = ["KEY_PREFIX", "resolve_approvals", "sealedplan_tool", "sealedplan_tools"]

KEY_PREFIX = "openai-agents-"
"""Idempotency keys of plans made by these tools are this prefix plus the call id."""

_NEEDS_PERSON = (Decision.APPROVE, Decision.TWO_PERSON)

# The SQLite store shares one connection. Runtime is an unhashable dataclass, so locks
# are keyed by id and dropped with it.
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock(runtime: Runtime) -> threading.Lock:
    with _locks_guard:
        key = id(runtime)
        if key not in _locks:
            _locks[key] = threading.Lock()
            weakref.finalize(runtime, _locks.pop, key, None)
        return _locks[key]


def _find(
    runtime: Runtime, action_name: str, call_id: str, params: Mapping[str, Any] | None = None
) -> PlanRecord | None:
    """The latest plan for this call (and these params, if given)."""
    records = runtime.store.by_idempotency_key(action_name, KEY_PREFIX + call_id)
    if params is not None:
        wanted = digest(dict(params))
        records = [r for r in records if digest(r.plan.params) == wanted]
    return records[-1] if records else None


def _interrupt_value(record: PlanRecord, call_id: str) -> dict[str, Any]:
    plan = record.plan
    return {
        "call_id": call_id,
        "plan_hash": plan.plan_hash,
        "summary": plan.summary,
        "state": str(record.state),
        "expires_at": plan.expires_at.isoformat(),
        "plan": plan.to_obj(),
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


def _args_model(runtime: Runtime, action_name: str) -> type[BaseModel]:
    bound = runtime.actions()[action_name]
    hints = typing.get_type_hints(bound.plan, include_extras=True)
    fields: dict[str, Any] = {}
    for p in list(inspect.signature(bound.plan).parameters.values())[1:]:  # drop ctx
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            raise TypeError(f"{action_name}: plan() cannot take *args or **kwargs")
        default = ... if p.default is inspect.Parameter.empty else p.default
        fields[p.name] = (hints.get(p.name, Any), default)
    return create_model(f"{action_name.replace('.', '_')}_args", **fields)


def sealedplan_tool(
    runtime: Runtime,
    action_name: str,
    *,
    agent: Principal,
    sponsor: Principal | None = None,
    name: str | None = None,
    description: str | None = None,
) -> FunctionTool:
    """A function tool for one registered action; its arguments are ``plan()``'s."""
    bound = runtime.actions()[action_name]
    model = _args_model(runtime, action_name)

    def params_of(data: Mapping[str, Any]) -> dict[str, Any]:
        args = model.model_validate(data)
        return {k: getattr(args, k) for k in type(args).model_fields}

    def plan_for(call_id: str, params: dict[str, Any]) -> PlanRecord:
        with _lock(runtime):
            record = _find(runtime, action_name, call_id, params)
            if record is None:
                proposal = runtime.propose(
                    action_name,
                    params,
                    agent=agent,
                    idempotency_key=KEY_PREFIX + call_id,
                    sponsor=sponsor,
                )
                record = runtime.store.get(proposal.plan.plan_hash)
            return record

    async def needs_approval(
        _ctx: RunContextWrapper[Any], data: dict[str, Any], call_id: str
    ) -> bool:
        record = plan_for(call_id, params_of(data))
        return record.decision in _NEEDS_PERSON and record.state is State.PENDING_APPROVAL

    async def invoke(ctx: ToolContext[Any], raw: str) -> str:
        record = plan_for(ctx.tool_call_id, params_of(json.loads(raw or "{}")))
        plan_hash = record.plan.plan_hash
        with _lock(runtime):
            if record.state is State.PENDING_APPROVAL:
                runtime.expire_due()
                record = runtime.store.get(plan_hash)
            if record.state is State.PENDING_APPROVAL:
                out = _outcome(
                    record, error="the run was approved, but the plan was not; nothing written"
                )
            elif record.state is State.APPROVED:
                execution = runtime.execute(plan_hash, applier=agent)
                out = _outcome(runtime.store.get(plan_hash), execution)
            else:
                out = _outcome(record)
        return json.dumps(out)

    owner = getattr(bound.plan, "__self__", None)
    doc = inspect.getdoc(bound.plan) or (owner and inspect.getdoc(type(owner))) or action_name
    optional = any(not f.is_required() for f in model.model_fields.values())
    return FunctionTool(
        name=name or action_name.replace(".", "_"),
        description=description or f"{doc}\n\nChanges go through plan, approval and drift check.",
        params_json_schema=model.model_json_schema(),
        on_invoke_tool=invoke,
        # Strict mode makes every argument required, so it is off when plan() has defaults.
        strict_json_schema=not optional,
        needs_approval=needs_approval,
    )


def sealedplan_tools(
    runtime: Runtime,
    *,
    agent: Principal,
    sponsor: Principal | None = None,
    actions: Sequence[str] | None = None,
) -> list[Tool]:
    """One tool per registered action (or per name in ``actions``)."""
    names = actions if actions is not None else list(runtime.actions())
    return [sealedplan_tool(runtime, n, agent=agent, sponsor=sponsor) for n in names]


# --- approvals --------------------------------------------------------------------------


def resolve_approvals(runtime: Runtime, state: RunState[Any, Any]) -> list[dict[str, Any]]:
    """Copy the store's decisions onto a paused run, and return the plans still waiting.

    For each interruption from these tools, it approves the call in ``state`` if a person
    approved its plan, and rejects it if the plan was rejected or expired. Calls whose plan
    still waits for a person are left alone; resuming pauses on them again. Interruptions
    from other tools are left alone too. Each waiting plan is returned as a dict with
    ``call_id``, ``plan_hash``, ``summary``, ``state``, ``expires_at`` and ``plan``.
    """
    waiting: list[dict[str, Any]] = []
    with _lock(runtime):
        runtime.expire_due()
        for item in state.get_interruptions():
            call_id = item.call_id
            if call_id is None:
                continue
            record = next(
                (r for a in runtime.actions() if (r := _find(runtime, a, call_id)) is not None),
                None,
            )
            if record is None:
                continue
            if record.state is State.APPROVED:
                state.approve(item)
            elif record.state is State.PENDING_APPROVAL:
                waiting.append(_interrupt_value(record, call_id))
            else:
                state.reject(item, rejection_message=json.dumps(_outcome(record)))
    return waiting
