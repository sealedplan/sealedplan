"""Policy interface, default policy and invariants (SPEC §4.2, §10)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from sealedplan.canonical import digest
from sealedplan.models import Approval, Effect, Plan, RiskLevel, most_severe


class Decision(StrEnum):
    AUTO = "auto"
    APPROVE = "approve"
    TWO_PERSON = "two_person"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyContext:
    now: datetime
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reasons: tuple[str, ...]
    policy_digest: str


class Policy(Protocol):
    def evaluate(self, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult: ...


def effective_effect(plan: Plan, declared: Effect | None, override: Effect | None = None) -> Effect:
    """§4.2: the most severe of the action's, the plan's and the operator's classes.

    An action with no declaration counts as IRREVERSIBLE, and so does a REVERSIBLE or
    COMPENSATABLE plan without a compensation section. An override can only raise.
    """
    effects = [plan.effect, declared if declared is not None else Effect.IRREVERSIBLE]
    if override is not None:
        effects.append(override)
    if plan.compensation is None and plan.effect in (Effect.REVERSIBLE, Effect.COMPENSATABLE):
        effects.append(Effect.IRREVERSIBLE)
    return most_severe(*effects)


_A, _P, _T = Decision.AUTO, Decision.APPROVE, Decision.TWO_PERSON

DEFAULT_TABLE: Mapping[Effect, Mapping[RiskLevel, Decision]] = {
    Effect.READ_ONLY: dict(zip(RiskLevel, (_A, _A, _A, _P), strict=True)),
    Effect.REVERSIBLE: dict(zip(RiskLevel, (_A, _P, _P, _T), strict=True)),
    Effect.COMPENSATABLE: dict(zip(RiskLevel, (_P, _P, _T, _T), strict=True)),
    Effect.IRREVERSIBLE: dict(zip(RiskLevel, (_P, _P, _T, _T), strict=True)),
}


class DefaultPolicy:
    """The policy a runtime uses when none is configured (§10.3)."""

    digest = digest(
        {str(e): {str(r): str(d) for r, d in row.items()} for e, row in DEFAULT_TABLE.items()}
    )

    def evaluate(self, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult:
        level = plan.risk.level
        decision = DEFAULT_TABLE[effect][level]
        return PolicyResult(decision, (f"default policy: {effect} at {level} risk",), self.digest)


def decide(policy: Policy | None, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult:
    """Evaluate ``policy`` and enforce the rules that hold under any policy (§10.3)."""

    def deny(reason: str, policy_digest: str = "") -> PolicyResult:
        return PolicyResult(Decision.DENY, (reason,), policy_digest)

    if policy is None:
        return deny("no policy configured")
    if effect.severity < plan.effect.severity:
        return deny(f"effective effect {effect} is below the plan's {plan.effect}")
    try:
        result = policy.evaluate(plan, effect, ctx)
    except Exception as exc:
        return deny(f"policy evaluation failed: {type(exc).__name__}")
    if not isinstance(result, PolicyResult) or not isinstance(result.decision, Decision):
        return deny("policy returned an invalid result")
    if result.decision is Decision.AUTO and effect is Effect.IRREVERSIBLE:
        return deny("policy returned auto for an IRREVERSIBLE plan", result.policy_digest)
    return result


def approvals_satisfy(decision: Decision, plan: Plan, approvals: Sequence[Approval]) -> bool:
    """Whether ``approvals`` are enough for ``decision`` (§10.2).

    Counts only ``approve`` decisions for this plan's hash, from someone other than the
    plan's agent. Expiry, use counts and signatures are the runtime's to check.
    """
    if decision is Decision.AUTO:
        return True
    if decision is Decision.DENY:
        return False
    approvers = {
        a.approver.key
        for a in approvals
        if a.decision == "approve"
        and a.plan_hash == plan.plan_hash
        and not a.approver.same_as(plan.principal.agent)
    }
    if decision is Decision.APPROVE:
        return len(approvers) >= 1
    # The plan has one sponsor, so two distinct approvers include at most one sponsor.
    return len(approvers) >= 2
