"""Serve a sealedplan runtime's actions as MCP tools (SPEC §12, MCP 2026-07-28).

Each registered action becomes one tool whose arguments are the action's ``plan()``
parameters. A call never changes the target system directly:

- **Transparent mode** (§12.2): the call builds a plan and runs policy. ``auto`` applies
  and returns the Applied record; ``deny`` returns a tool error; ``approve`` and
  ``two_person`` return ``input_required`` until a person approves the plan out of band,
  for example with the ``sealedplan`` CLI. The client's retry then drift-checks and
  applies.
- **Explicit mode** (§12.5): ``_meta["io.github.sealedplan/plan-apply"]`` set to
  ``{"mode": "plan"}`` returns the plan without applying; ``{"mode": "apply",
  "plan_hash": ...}`` applies that plan if the arguments match it.

``requestState`` holds the plan hash and the plan's expiry. The MCP SDK seals it (AES-GCM)
and binds it to the tool name, the arguments and the authenticated client (§12.3).
Approval is read from the runtime's store only: an elicitation ``accept`` is never an
approval (§12.4).
"""

from __future__ import annotations

import inspect
import json
import threading
import typing
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any, cast

from mcp.server.extension import Extension, ToolBinding
from mcp.server.mcpserver import Context, MCPServer, RequestStateSecurity
from mcp_types import (
    CallToolResult,
    ElicitRequest,
    ElicitRequestFormParams,
    InputRequiredResult,
    TextContent,
    ToolAnnotations,
)

from sealedplan.actions import BoundAction
from sealedplan.canonical import digest
from sealedplan.models import Effect, Plan, PlanError, Principal
from sealedplan.runtime import Execution, Runtime, SealedPlanError
from sealedplan.state import State
from sealedplan.store import PlanRecord, StoreError

EXTENSION_ID = "io.github.sealedplan/plan-apply"
SPEC_VERSION = "0.1"
DEFAULT_APPROVE_HINT = "sealedplan approve {short}"

AgentSource = Principal | Callable[[Context], Principal]


def tool_name(action_name: str) -> str:
    """The MCP tool name for an action: ``sql.update_row`` becomes ``sql_update_row``."""
    return action_name.replace(".", "_")


def tool_annotations(effect: Effect) -> ToolAnnotations:
    """Standard MCP hints that match an effect class (§12.1)."""
    if effect is Effect.READ_ONLY:
        return ToolAnnotations(read_only_hint=True)
    return ToolAnnotations(
        read_only_hint=False,
        destructive_hint=effect is not Effect.REVERSIBLE,
        idempotent_hint=False,
    )


class PlanApply(Extension):
    """The ``io.github.sealedplan/plan-apply`` extension: one tool per registered action.

    ``agent`` is the principal recorded as the plan's agent: a fixed ``Principal``, or a
    function of the MCP request context (for example, derived from the client's token).
    ``approve_hint`` tells the person how to approve; ``{short}`` and ``{plan_hash}``
    are filled in.
    """

    identifier = EXTENSION_ID

    def __init__(
        self,
        runtime: Runtime,
        *,
        agent: AgentSource,
        approve_hint: str = DEFAULT_APPROVE_HINT,
    ) -> None:
        self.runtime = runtime
        self.agent = agent
        self.approve_hint = approve_hint
        # The runtime and its SQLite store are synchronous; tool calls run on worker
        # threads, so one call at a time uses them.
        self._lock = threading.Lock()

    # --- what the extension contributes -----------------------------------------------

    def _effect(self, bound: BoundAction) -> Effect:
        override = self.runtime.effect_overrides.get(bound.spec.name)
        declared = bound.spec.effect or Effect.IRREVERSIBLE
        return override if override and override.severity > declared.severity else declared

    def settings(self) -> dict[str, Any]:
        ttl = int(self.runtime.plan_ttl.total_seconds())
        return {
            "spec_version": SPEC_VERSION,
            "approval_modes": ["out_of_band", "explicit"],
            "tools": {
                tool_name(name): {
                    "effect": str(self._effect(bound)),
                    "risk": str(bound.spec.risk),
                    "plan_ttl_seconds": ttl,
                }
                for name, bound in self.runtime.actions().items()
            },
        }

    def tools(self) -> list[ToolBinding]:
        return [self._binding(bound) for bound in self.runtime.actions().values()]

    def _binding(self, bound: BoundAction) -> ToolBinding:
        action_name = bound.spec.name

        def call(mcp_context: Context, **arguments: Any) -> Any:
            with self._lock:
                return self.handle(action_name, arguments, mcp_context)

        signature, hints = _tool_signature(bound)
        call.__signature__ = signature  # type: ignore[attr-defined]
        call.__annotations__ = hints
        call.__name__ = tool_name(action_name)
        doc = inspect.getdoc(bound.plan) or f"Propose {action_name}."
        return ToolBinding(
            fn=call,
            kwargs={
                "name": tool_name(action_name),
                "description": f"{doc}\n\nChanges go through plan, approval and drift check.",
                "annotations": tool_annotations(self._effect(bound)),
                "structured_output": False,
            },
        )

    # --- one tools/call -----------------------------------------------------------------

    def handle(
        self, action_name: str, arguments: dict[str, Any], ctx: Context
    ) -> CallToolResult | InputRequiredResult:
        """Run one ``tools/call`` round for ``action_name``."""
        try:
            if ctx.request_state is not None:
                return self._resume(ctx.request_state, action_name, ctx)
            options = _extension_meta(ctx)
            mode = options.get("mode")
            if mode == "apply":
                return self._apply_explicit(action_name, arguments, options, ctx)
            agent = self._agent(ctx)
            proposal = self.runtime.propose(
                action_name,
                arguments,
                agent=agent,
                idempotency_key=f"mcp-{uuid.uuid4()}",
            )
            record = self.runtime.store.get(proposal.plan.plan_hash)
            if mode == "plan":
                return _plan_result(record)
            reasons = list(proposal.decision.reasons)
            return self._advance(record, agent, ctx, reasons)
        except (SealedPlanError, PlanError, StoreError, ValueError) as exc:
            return _error(str(exc))

    def _agent(self, ctx: Context) -> Principal:
        return self.agent if isinstance(self.agent, Principal) else self.agent(ctx)

    def _resume(
        self, state: str, action_name: str, ctx: Context
    ) -> CallToolResult | InputRequiredResult:
        saved = json.loads(state)
        record = self.runtime.store.get(saved["plan_hash"])
        if record.plan.action.name != action_name:
            return _error("request state belongs to a different tool")
        if self.runtime.now() >= datetime.fromisoformat(saved["expires_at"]):
            return _error("the plan has expired; call the tool again for a new plan")
        return self._advance(record, self._agent(ctx), ctx, [])

    def _apply_explicit(
        self, action_name: str, arguments: dict[str, Any], options: Mapping[str, Any], ctx: Context
    ) -> CallToolResult | InputRequiredResult:
        plan_hash = options.get("plan_hash")
        if not isinstance(plan_hash, str):
            return _error('mode "apply" needs a "plan_hash"')
        record = self.runtime.store.get(plan_hash)
        plan = record.plan
        if plan.action.name != action_name or digest(arguments) != digest(plan.params):
            return _error("the arguments do not match the plan's params (§12.5)")
        agent = self._agent(ctx)
        if not agent.same_as(plan.principal.agent):
            return _error("this plan was proposed by a different agent")
        return self._advance(record, agent, ctx, [])

    def _advance(
        self, record: PlanRecord, agent: Principal, ctx: Context, reasons: list[str]
    ) -> CallToolResult | InputRequiredResult:
        """Take a stored plan as far as its state allows (§12.2, from the policy step)."""
        plan = record.plan
        if record.state is State.PENDING_APPROVAL:
            if self.runtime.now() >= plan.expires_at:
                self.runtime.expire_due()
                return _error("the plan has expired; call the tool again for a new plan")
            return self._input_required(plan, ctx)
        if record.state is State.APPROVED:
            return _execution_result(plan, self.runtime.execute(plan.plan_hash, applier=agent))
        if record.state is State.APPLIED:
            applied = self.runtime.store.applied(plan.plan_hash)
            return _result(
                f"Already applied: {plan.summary}",
                {"plan_hash": plan.plan_hash, "state": str(State.APPLIED)}
                | ({"applied": applied.to_obj()} if applied else {}),
            )
        message = {
            State.DENIED: "Policy denied this change",
            State.REJECTED: "A person rejected this change",
            State.EXPIRED: "The plan expired before it was approved and applied",
        }.get(record.state, f"The plan is {record.state}")
        meta: dict[str, Any] = {"plan_hash": plan.plan_hash, "state": str(record.state)}
        if reasons:
            meta["reasons"] = reasons
        detail = f": {'; '.join(reasons)}" if reasons else ""
        return _error(f"{message}{detail} (plan {_short(plan.plan_hash)})", meta)

    def _input_required(self, plan: Plan, ctx: Context) -> InputRequiredResult:
        short = _short(plan.plan_hash)
        hint = self.approve_hint.format(short=short, plan_hash=plan.plan_hash)
        state = json.dumps({"plan_hash": plan.plan_hash, "expires_at": plan.expires_at.isoformat()})
        meta = {EXTENSION_ID: {"plan": plan.to_obj(), "state": str(State.PENDING_APPROVAL)}}
        caps = ctx.client_capabilities
        if caps is None or caps.elicitation is None:
            # §12.2: a state-only result lets the client retry without prompting anyone.
            return InputRequiredResult.model_validate({"requestState": state, "_meta": meta})
        # Out of band (§12.4): this message only tells the person where to approve.
        # Its answer is ignored; approval comes from the store.
        prompt = ElicitRequest(
            params=ElicitRequestFormParams(
                message=(
                    f"Approval needed: {plan.summary} (plan {short}). "
                    f"Approve it with `{hint}`, then continue. "
                    "Continuing here does not approve it."
                ),
                requested_schema={"type": "object", "properties": {}},
            )
        )
        return InputRequiredResult.model_validate(
            {"inputRequests": {"approval": prompt}, "requestState": state, "_meta": meta}
        )


# --- building the tool signature ------------------------------------------------------


def _tool_signature(bound: BoundAction) -> tuple[inspect.Signature, dict[str, Any]]:
    """The action's ``plan()`` parameters after ``ctx``, plus the MCP context parameter."""
    hints = typing.get_type_hints(bound.plan)
    params = list(inspect.signature(bound.plan).parameters.values())[1:]  # drop ctx
    out, annotations = [], {}
    for p in params:
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            raise TypeError(f"{bound.spec.name}: plan() cannot take *args or **kwargs")
        annotation = hints.get(p.name, Any)
        out.append(p.replace(kind=p.KEYWORD_ONLY, annotation=annotation))
        annotations[p.name] = annotation
    out.insert(
        0, inspect.Parameter("mcp_context", inspect.Parameter.KEYWORD_ONLY, annotation=Context)
    )
    annotations["mcp_context"] = Context
    annotations["return"] = Any
    return inspect.Signature(out, return_annotation=Any), annotations


# --- results ----------------------------------------------------------------------------


def _extension_meta(ctx: Context) -> Mapping[str, Any]:
    meta = cast("Mapping[str, Any] | None", ctx.request_context.meta)
    value = (meta or {}).get(EXTENSION_ID)
    return value if isinstance(value, Mapping) else {}


def _short(plan_hash: str) -> str:
    return plan_hash.removeprefix("sha256:")[:12]


def _result(text: str, meta: dict[str, Any], *, structured: Any = None) -> CallToolResult:
    return CallToolResult.model_validate(
        {
            "content": [TextContent(type="text", text=text)],
            "structuredContent": structured if structured is not None else meta,
            "_meta": {EXTENSION_ID: meta},
        }
    )


def _error(text: str, meta: dict[str, Any] | None = None) -> CallToolResult:
    body: dict[str, Any] = {"content": [TextContent(type="text", text=text)], "isError": True}
    if meta:
        body["_meta"] = {EXTENSION_ID: meta}
    return CallToolResult.model_validate(body)


def _plan_result(record: PlanRecord) -> CallToolResult:
    plan = record.plan
    text = (
        f"Plan {_short(plan.plan_hash)}: {plan.summary}. State {record.state}. "
        f"To apply, call again with the same arguments and "
        f'_meta["{EXTENSION_ID}"] = {{"mode": "apply", "plan_hash": "{plan.plan_hash}"}}.'
    )
    return _result(
        text,
        {"plan": plan.to_obj(), "state": str(record.state)},
        structured=plan.to_obj(),
    )


def _execution_result(plan: Plan, execution: Execution) -> CallToolResult:
    meta: dict[str, Any] = {"plan_hash": plan.plan_hash, "state": str(execution.state)}
    if execution.applied is not None:
        meta["applied"] = execution.applied.to_obj()
    if execution.state is State.APPLIED:
        return _result(f"Applied: {plan.summary}", meta)
    if execution.state is State.DRIFTED:
        failed = [r.to_obj() for r in execution.drift]
        meta["failed_preconditions"] = failed
        names = ", ".join(r.id for r in execution.drift)
        return _error(
            f"Not applied: the system changed since the plan was approved ({names}). "
            "Nothing was written; call the tool again for a new plan.",
            meta,
        )
    return _error(f"{execution.state}: {execution.error or 'not applied'}", meta)


# --- convenience ------------------------------------------------------------------------


def create_server(
    runtime: Runtime,
    *,
    agent: AgentSource,
    name: str = "sealedplan",
    approve_hint: str = DEFAULT_APPROVE_HINT,
    request_state_security: RequestStateSecurity | None = None,
) -> MCPServer:
    """An MCP server exposing ``runtime``'s registered actions.

    Without ``request_state_security``, request state is sealed with a key that lives as
    long as the process, and for no longer than the runtime's plan TTL. Pass
    ``RequestStateSecurity(keys=[...])`` to survive restarts or run several replicas.
    """
    ttl = max(runtime.plan_ttl, timedelta(seconds=1)).total_seconds()
    return MCPServer(
        name,
        extensions=[PlanApply(runtime, agent=agent, approve_hint=approve_hint)],
        request_state_security=request_state_security or RequestStateSecurity.ephemeral(ttl=ttl),
    )
