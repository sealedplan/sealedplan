"""Reference runtime: propose, approve, execute, compensate, recover (SPEC §7 to §10)."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

from sealedplan.actions import (
    ApplyFailedError,
    BoundAction,
    CompensationConflictError,
    Context,
    PreconditionFailedError,
)
from sealedplan.models import (
    Applied,
    Approval,
    ApprovalScope,
    Compensated,
    Effect,
    Parent,
    Plan,
    PlanError,
    Principal,
    ResourceRef,
    Trigger,
    whole_seconds,
)
from sealedplan.policy import (
    Decision,
    DefaultPolicy,
    Policy,
    PolicyContext,
    PolicyResult,
    approvals_satisfy,
    decide,
    effective_effect,
)
from sealedplan.preconditions import PreconditionResult, evaluate
from sealedplan.state import State, can_transition
from sealedplan.store import PlanRecord, SqliteStore, StateConflictError


class SealedPlanError(Exception):
    pass


class UnknownActionError(SealedPlanError):
    pass


class ApprovalError(SealedPlanError):
    pass


class WrongStateError(SealedPlanError):
    def __init__(self, plan_hash: str, state: State, wanted: str) -> None:
        super().__init__(f"plan {plan_hash} is {state}; {wanted}")
        self.state = state


@dataclass(frozen=True)
class Proposal:
    plan: Plan
    state: State
    effect: Effect
    decision: PolicyResult


@dataclass(frozen=True)
class Execution:
    state: State
    applied: Applied | None = None
    drift: tuple[PreconditionResult, ...] = ()
    error: str | None = None


def utc_now() -> datetime:
    return datetime.now(UTC)


def _human_only(approval: Approval, record: PlanRecord) -> bool:
    return approval.approver.kind == "human"


@dataclass
class Runtime:
    """One runtime instance. Several may share a store (§7.4)."""

    store: SqliteStore
    identity: Principal
    policy: Policy | None = field(default_factory=DefaultPolicy)
    clock: Callable[[], datetime] = utc_now
    plan_ttl: timedelta = timedelta(minutes=30)
    effect_overrides: Mapping[str, Effect] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    # Who may approve. The default accepts any human other than the plan's agent.
    authorize: Callable[[Approval, PlanRecord], bool] = _human_only
    # Checks a detached JWS on approvals from untrusted channels (§5.3 rule 8). With none
    # configured, such approvals are refused.
    verify_signature: Callable[[Approval], bool] | None = None
    _actions: dict[str, BoundAction] = field(default_factory=dict, init=False)

    def now(self) -> datetime:
        return whole_seconds(self.clock())

    # --- registry ----------------------------------------------------------------------

    def register(self, *actions: object) -> None:
        for obj in actions:
            bound = BoundAction.bind(obj)
            if bound.spec.name in self._actions:
                raise SealedPlanError(f"action {bound.spec.name} is already registered")
            self._actions[bound.spec.name] = bound

    def actions(self) -> Mapping[str, BoundAction]:
        """The registered actions, by name (read-only)."""
        return MappingProxyType(self._actions)

    def _action(self, name: str) -> BoundAction:
        try:
            return self._actions[name]
        except KeyError:
            raise UnknownActionError(f"no action named {name}") from None

    def _context(self, bound: BoundAction, plan: Plan, **extra: Any) -> Context:
        return Context(
            action=bound.spec,
            agent=plan.principal.agent,
            sponsor=plan.principal.sponsor,
            now=self.now(),
            params=plan.params,
            idempotency_key=plan.idempotency_key,
            parent=plan.parent,
            labels=self.labels,
            **extra,
        )

    # --- propose -----------------------------------------------------------------------

    def propose(
        self,
        action_name: str,
        params: Mapping[str, Any],
        *,
        agent: Principal,
        idempotency_key: str,
        sponsor: Principal | None = None,
        parent: Parent | None = None,
    ) -> Proposal:
        """Ask the action for a plan, store it, and run policy (§7.1, §10)."""
        bound = self._action(action_name)
        now = self.now()
        ctx = Context(
            action=bound.spec,
            agent=agent,
            sponsor=sponsor,
            now=now,
            params=dict(params),
            idempotency_key=idempotency_key,
            ttl=self.plan_ttl,
            parent=parent,
            labels=self.labels,
        )
        plan = bound.plan(ctx, **params)
        self._check_provider_plan(bound, plan, ctx)
        effect = effective_effect(
            plan, bound.spec.effect, self.effect_overrides.get(bound.spec.name)
        )
        self.store.create_plan(plan, effect, agent, now)

        result = decide(self.policy, plan, effect, PolicyContext(now, self.labels))
        if result.decision is Decision.DENY:
            state = State.DENIED
        elif result.decision is Decision.AUTO:
            state = State.APPROVED
            self.store.add_approval(
                Approval(
                    approval_id=f"appr-policy-{uuid.uuid4()}",
                    plan_hash=plan.plan_hash,
                    decision="approve",
                    approver=self.identity,
                    method="policy",
                    scope=ApprovalScope(),
                    comment="; ".join(result.reasons) or None,
                    issued_at=now,
                    expires_at=plan.expires_at,
                )
            )
        else:
            state = State.PENDING_APPROVAL
        self.store.record_decision(plan.plan_hash, result, state, self.identity, now)
        return Proposal(plan, state, effect, result)

    def _check_provider_plan(self, bound: BoundAction, plan: Plan, ctx: Context) -> None:
        # §11.1: the provider describes its own change; check it described this call.
        expected = {
            "action": bound.spec.ref,
            "params": dict(ctx.params),
            "idempotency_key": ctx.idempotency_key,
            "agent": ctx.agent,
            "parent": ctx.parent,
        }
        actual = {
            "action": plan.action,
            "params": plan.params,
            "idempotency_key": plan.idempotency_key,
            "agent": plan.principal.agent,
            "parent": plan.parent,
        }
        wrong = [k for k in expected if expected[k] != actual[k]]
        if wrong:
            raise PlanError(f"provider returned a plan for a different call: {wrong}")
        declared = bound.spec.effect or Effect.IRREVERSIBLE
        if plan.effect.severity > declared.severity:
            raise PlanError(f"plan effect {plan.effect} exceeds the action's {declared} (§4.1)")

    # --- approve -----------------------------------------------------------------------

    def submit_approval(self, approval: Approval, *, trusted_channel: bool = True) -> State:
        """Record an approve or reject and advance the plan if it is now decided (§5.3)."""
        record = self.store.get(approval.plan_hash)
        plan, now = record.plan, self.now()
        if record.state is not State.PENDING_APPROVAL:
            raise WrongStateError(plan.plan_hash, record.state, "it is not awaiting approval")
        if now >= plan.expires_at:
            self._move(record, State.EXPIRED, now, {"reason": "plan expired"})
            raise ApprovalError("the plan has expired")
        if approval.method == "policy":
            raise ApprovalError("policy approvals are recorded by the runtime only")
        if approval.approver.same_as(plan.principal.agent):
            raise ApprovalError("the plan's agent cannot approve its own plan (§5.3 rule 6)")
        if not trusted_channel:
            if approval.signature is None:
                raise ApprovalError("approvals from an untrusted channel must be signed")
            if self.verify_signature is None or not self.verify_signature(approval):
                raise ApprovalError("approval signature did not verify")
        if not self.authorize(approval, record):
            raise ApprovalError(f"{approval.approver.id} may not approve this plan")
        if now >= approval.expires_at:
            raise ApprovalError("the approval has already expired")

        self.store.add_approval(approval)
        if approval.decision == "reject":
            return self._move(record, State.REJECTED, now, {"approval_id": approval.approval_id})
        usable = self._usable_approvals(plan, now, applier=None)
        assert record.decision is not None
        if approvals_satisfy(record.decision, plan, usable):
            return self._move(record, State.APPROVED, now, {"decision": str(record.decision)})
        return State.PENDING_APPROVAL

    def _usable_approvals(
        self, plan: Plan, now: datetime, applier: Principal | None
    ) -> list[Approval]:
        out = []
        for a in self.store.approvals(plan.plan_hash, unused_only=True):
            # §5.3 rule 3: an approval never outlives its plan.
            if a.decision != "approve" or now >= min(a.expires_at, plan.expires_at):
                continue
            if applier is not None:
                allowed = a.scope.apply_by or [plan.principal.agent]
                if not any(applier.same_as(p) for p in allowed):
                    continue
            out.append(a)
        return out

    def _move(
        self,
        record: PlanRecord,
        dst: State,
        now: datetime,
        detail: dict[str, Any] | None = None,
    ) -> State:
        """Transition, tolerating another instance having made the same move first."""
        try:
            self.store.transition(
                record.plan.plan_hash, record.state, dst, self.identity, now, detail
            )
        except StateConflictError as exc:
            if exc.actual is not dst:
                raise
        return dst

    def expire_due(self) -> list[str]:
        """Move pending or approved plans past their expiry to EXPIRED."""
        now, moved = self.now(), []
        for record in self.store.list_plans([State.PENDING_APPROVAL, State.APPROVED]):
            if now >= record.plan.expires_at:
                self._move(record, State.EXPIRED, now, {"reason": "plan expired"})
                moved.append(record.plan.plan_hash)
        return moved

    # --- execute -----------------------------------------------------------------------

    def execute(self, plan_hash: str, *, applier: Principal | None = None) -> Execution:
        """Verify approvals, re-check preconditions, then apply (§7.2, §8)."""
        record = self.store.get(plan_hash)
        plan = record.plan
        applier = applier or plan.principal.agent
        bound = self._action(plan.action.name)
        now = self.now()
        if record.state is not State.APPROVED:
            raise WrongStateError(plan_hash, record.state, "only an APPROVED plan can be applied")
        if now >= plan.expires_at:
            self._move(record, State.EXPIRED, now, {"reason": "plan expired"})
            return Execution(State.EXPIRED, error="plan expired")

        usable = self._usable_approvals(plan, now, applier)
        assert record.decision is not None
        if not approvals_satisfy(record.decision, plan, usable):
            if not self._usable_approvals(plan, now, applier=None):
                self._move(record, State.EXPIRED, now, {"reason": "approvals expired"})
                return Execution(State.EXPIRED, error="approvals expired")
            raise ApprovalError(f"{applier.id} holds no valid approval for this plan")

        # §8.1: check every precondition immediately before APPLYING.
        ctx = self._context(bound, plan)
        drift = tuple(
            r
            for r in (evaluate(p, bound.observe(ctx, p.resource)) for p in plan.preconditions)
            if not r.holds
        )
        if drift:
            self._move(record, State.DRIFTED, now, {"failed": [r.to_obj() for r in drift]})
            return Execution(State.DRIFTED, drift=drift)

        approval_ids = [a.approval_id for a in usable]
        self.store.begin_apply(plan_hash, approval_ids, applier, now)
        ctx = self._context(bound, plan, approval_ids=tuple(approval_ids), applier=applier)
        return self._apply(bound, plan, ctx)

    def _apply(self, bound: BoundAction, plan: Plan, ctx: Context) -> Execution:
        def record(outcome: str, error: str) -> Applied:
            return Applied(
                applied_id=f"applied-{uuid.uuid4()}",
                plan_hash=plan.plan_hash,
                approval_ids=list(ctx.approval_ids),
                outcome=outcome,  # type: ignore[arg-type]
                started_at=ctx.now,
                finished_at=self.now(),
                principal=ctx.applier or ctx.agent,
                error=error,
            )

        try:
            applied = bound.apply(ctx, plan)
        except PreconditionFailedError as exc:
            detail = {"failed": [r.to_obj() for r in exc.results], "atomic": True}
            self.store.transition(
                plan.plan_hash, State.APPLYING, State.DRIFTED, self.identity, self.now(), detail
            )
            return Execution(State.DRIFTED, drift=exc.results)
        except ApplyFailedError as exc:
            applied = record("failed", str(exc))
            self.store.record_applied(
                applied, State.APPLYING, State.FAILED, self.identity, self.now()
            )
            return Execution(State.FAILED, applied, error=str(exc))
        except Exception as exc:
            # We cannot tell whether the change happened (§5.4); reconcile decides.
            applied = record("unknown", f"{type(exc).__name__}: {exc}")
            self.store.record_applied(
                applied, State.APPLYING, State.UNKNOWN, self.identity, self.now()
            )
            return Execution(State.UNKNOWN, applied, error=applied.error)

        if applied.plan_hash != plan.plan_hash:
            raise PlanError("provider returned an Applied record for a different plan")
        observed = applied.observed or self._observe_changes(bound, plan, ctx)
        applied = applied.model_copy(update={"finished_at": self.now(), "observed": observed})
        self.store.record_applied(applied, State.APPLYING, State.APPLIED, self.identity, self.now())
        return Execution(State.APPLIED, applied)

    def _observe_changes(
        self, bound: BoundAction, plan: Plan, ctx: Context
    ) -> dict[str, Any] | None:
        observed: dict[str, Any] = {}
        for change in plan.changes:
            res = change.resource
            if res.id not in observed:
                snap = bound.observe(ctx, res).snapshot()
                observed[res.id] = {"type": res.type, **snap}
        return observed or None

    # --- compensate --------------------------------------------------------------------

    def compensate(
        self,
        plan_hash: str,
        *,
        reason: str = "manual",
        trigger: Trigger | None = None,
    ) -> Compensated:
        """Run the approved compensation if nothing has changed since apply (§9.3)."""
        record = self.store.get(plan_hash)
        plan = record.plan
        bound = self._action(plan.action.name)
        if record.state is not State.APPLIED:
            raise WrongStateError(plan_hash, record.state, "only an APPLIED plan is compensated")
        applied = self.store.applied(plan_hash)
        assert applied is not None
        started = self.now()

        def result(outcome: str, error: str | None = None) -> Compensated:
            return Compensated(
                compensation_id=f"comp-{uuid.uuid4()}",
                applied_id=applied.applied_id,
                plan_hash=plan_hash,
                reason=reason,  # type: ignore[arg-type]
                outcome=outcome,  # type: ignore[arg-type]
                started_at=started,
                finished_at=self.now(),
                trigger=trigger,
                error=error,
            )

        if (
            record.effect is Effect.IRREVERSIBLE
            or plan.compensation is None
            or bound.compensate is None
        ):
            skipped = result("skipped", "plan has no compensation")
            self.store.record_compensated(skipped, None, None, self.identity, started)
            return skipped

        ctx = self._context(bound, plan)
        self.store.transition(plan_hash, State.APPLIED, State.COMPENSATING, self.identity, started)
        conflict = self._compensation_conflict(bound, plan, applied, ctx)
        if conflict:
            done = result("conflict", conflict)
        else:
            try:
                bound.compensate(ctx, plan, applied)
                done = result("succeeded")
            except CompensationConflictError as exc:
                done = result("conflict", str(exc))
            except Exception as exc:
                done = result("failed", f"{type(exc).__name__}: {exc}")
        dst = State.COMPENSATED if done.outcome == "succeeded" else State.COMPENSATION_FAILED
        self.store.record_compensated(done, State.COMPENSATING, dst, self.identity, self.now())
        return done

    def _compensation_conflict(
        self, bound: BoundAction, plan: Plan, applied: Applied, ctx: Context
    ) -> str | None:
        assert plan.compensation is not None
        if plan.compensation.preconditions:
            failed = [
                r.id
                for p in plan.compensation.preconditions
                if not (r := evaluate(p, bound.observe(ctx, p.resource))).holds
            ]
            return f"compensation preconditions failed: {failed}" if failed else None
        if not applied.observed:
            return "no post-apply observation to compare against"
        changed = []
        for res_id, then in applied.observed.items():
            res = ResourceRef(type=then["type"], id=res_id)
            now = {"type": res.type, **bound.observe(ctx, res).snapshot()}
            if now != then:
                changed.append(res_id)
        return f"changed since apply: {changed}" if changed else None

    def compensate_run(self, run_id: str, failed_step: int) -> list[Compensated]:
        """Compensate earlier APPLIED steps of a run in reverse order (§9.3)."""
        steps = sorted(
            (
                r
                for r in self.store.list_plans()
                if r.plan.parent and r.plan.parent.run_id == run_id
            ),
            key=lambda r: r.plan.parent.step if r.plan.parent else 0,
        )
        earlier = [r for r in steps if r.plan.parent and r.plan.parent.step < failed_step]
        unknown = [r.plan.plan_hash for r in earlier if r.state is State.UNKNOWN]
        if unknown:
            raise WrongStateError(unknown[0], State.UNKNOWN, "reconcile it before compensating")
        trigger = Trigger(run_id=run_id, failed_step=failed_step)
        return [
            self.compensate(r.plan.plan_hash, reason="step_failed", trigger=trigger)
            for r in reversed(earlier)
            if r.state is State.APPLIED
        ]

    # --- recover -----------------------------------------------------------------------

    def recover(self) -> dict[str, State]:
        """After a restart: never re-apply blindly; reconcile instead (§7.2, §7.3)."""
        now, out = self.now(), {}
        for record in self.store.in_flight():
            h = record.plan.plan_hash
            if record.state is State.APPLYING:
                self.store.transition(
                    h, State.APPLYING, State.UNKNOWN, self.identity, now, {"reason": "restart"}
                )
            else:  # COMPENSATING: see the note in sealedplan.state
                applied = self.store.applied(h)
                assert applied is not None
                lost = Compensated(
                    compensation_id=f"comp-{uuid.uuid4()}",
                    applied_id=applied.applied_id,
                    plan_hash=h,
                    reason="manual",
                    outcome="unknown",
                    started_at=now,
                    finished_at=now,
                    error="runtime restarted during compensation",
                )
                self.store.record_compensated(
                    lost, State.COMPENSATING, State.COMPENSATION_FAILED, self.identity, now
                )
        for record in self.store.list_plans([State.UNKNOWN]):
            out[record.plan.plan_hash] = self.reconcile(record.plan.plan_hash)
        return out

    def reconcile(self, plan_hash: str) -> State:
        record = self.store.get(plan_hash)
        if record.state is not State.UNKNOWN:
            raise WrongStateError(plan_hash, record.state, "only UNKNOWN plans are reconciled")
        bound = self._action(record.plan.action.name)
        if bound.reconcile is None:
            return State.UNKNOWN  # a human resolves it (§7.3)
        applied = self.store.applied(plan_hash)
        ctx = self._context(bound, record.plan)
        found = bound.reconcile(ctx, record.plan, applied)
        if found is State.UNKNOWN:
            return found
        if not can_transition(State.UNKNOWN, found):
            raise SealedPlanError(f"reconcile returned {found}")
        now = self.now()
        update: dict[str, Any] = {
            "outcome": "succeeded" if found is State.APPLIED else "failed",
            "finished_at": now,
        }
        if found is State.APPLIED:
            update["observed"] = self._observe_changes(bound, record.plan, ctx)
            update["error"] = None
        base = applied or ctx.applied(record.plan)
        self.store.record_applied(
            base.model_copy(update=update), State.UNKNOWN, found, self.identity, now
        )
        return found
