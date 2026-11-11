"""Declaring actions: the ``@action`` decorator, ``Context`` and provider errors.

An action is a class with these methods::

    @action("k8s.scale_deployment", effect=Effect.REVERSIBLE, risk="medium")
    class ScaleDeployment:
        def plan(self, ctx: Context, name: str, replicas: int) -> Plan: ...
        def observe(self, ctx: Context, resource: ResourceRef) -> Observation: ...
        def apply(self, ctx: Context, plan: Plan) -> Applied: ...
        def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None: ...
        def reconcile(self, ctx: Context, plan: Plan, applied: Applied | None) -> State: ...

``plan`` builds its result with :meth:`Context.plan`, which fills in everything the
runtime already knows. ``compensate`` is required for REVERSIBLE and COMPENSATABLE
actions; ``reconcile`` is optional.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, TypeVar

from sealedplan.models import (
    ActionRef,
    Applied,
    BlastRadius,
    Change,
    Compensation,
    Effect,
    Evidence,
    Parent,
    Plan,
    PlanBody,
    PlanPrincipals,
    Precondition,
    Principal,
    ResourceRef,
    Risk,
    RiskLevel,
)
from sealedplan.preconditions import Observation, PreconditionResult
from sealedplan.state import State

ATTR = "__sealedplan_action__"


@dataclass(frozen=True)
class ActionSpec:
    name: str
    effect: Effect | None
    risk: RiskLevel
    version: str | None = None
    provider: str | None = None

    @property
    def ref(self) -> ActionRef:
        return ActionRef(name=self.name, version=self.version, provider=self.provider)


C = TypeVar("C", bound=type)


def action(
    name: str | None = None,
    *,
    effect: Effect | None = None,
    risk: RiskLevel | str = RiskLevel.MEDIUM,
    version: str | None = None,
    provider: str | None = None,
) -> Callable[[C], C]:
    """Mark a class as an action. No ``effect`` means IRREVERSIBLE (§4.2 rule 1)."""

    def wrap(cls: C) -> C:
        for method in ("plan", "observe", "apply"):
            if not callable(getattr(cls, method, None)):
                raise TypeError(f"action {cls.__name__} must define {method}()")
        if effect in (Effect.REVERSIBLE, Effect.COMPENSATABLE) and not callable(
            getattr(cls, "compensate", None)
        ):
            raise TypeError(f"{effect} action {cls.__name__} must define compensate()")
        spec = ActionSpec(name or cls.__name__, effect, RiskLevel(risk), version, provider)
        setattr(cls, ATTR, spec)
        return cls

    return wrap


def spec_of(obj: object) -> ActionSpec:
    spec = getattr(obj, ATTR, None)
    if not isinstance(spec, ActionSpec):
        raise TypeError(f"{type(obj).__name__} is not decorated with @action")
    return spec


@dataclass(frozen=True)
class Context:
    """What an action method gets from the runtime."""

    action: ActionSpec
    agent: Principal
    now: datetime
    params: Mapping[str, Any]
    idempotency_key: str
    sponsor: Principal | None = None
    ttl: timedelta = timedelta(minutes=30)
    parent: Parent | None = None
    approval_ids: tuple[str, ...] = ()
    applier: Principal | None = None
    labels: Mapping[str, str] = field(default_factory=dict)

    def plan(
        self,
        *,
        summary: str,
        changes: Sequence[Change],
        preconditions: Sequence[Precondition],
        effect: Effect | None = None,
        risk: RiskLevel | str | None = None,
        risk_reasons: Sequence[str] | None = None,
        compensation: Compensation | None = None,
        blast_radius: BlastRadius | None = None,
        evidence: Sequence[Evidence] | None = None,
        extensions: Mapping[str, Any] | None = None,
    ) -> Plan:
        """Build and seal a plan for this call."""
        return PlanBody(
            action=self.action.ref,
            params=dict(self.params),
            effect=effect or self.action.effect or Effect.IRREVERSIBLE,
            risk=Risk(
                level=RiskLevel(risk or self.action.risk),
                reasons=list(risk_reasons) if risk_reasons else None,
            ),
            summary=summary,
            changes=list(changes),
            preconditions=list(preconditions),
            blast_radius=blast_radius,
            compensation=compensation,
            idempotency_key=self.idempotency_key,
            principal=PlanPrincipals(agent=self.agent, sponsor=self.sponsor),
            evidence=list(evidence) if evidence else None,
            created_at=self.now,
            expires_at=self.now + self.ttl,
            parent=self.parent,
            extensions=dict(extensions) if extensions else None,
        ).seal()

    def applied(
        self,
        plan: Plan,
        *,
        result: Any = None,
        compensation_handle: Any = None,
        observed: Mapping[str, Any] | None = None,
    ) -> Applied:
        """Build a successful Applied record; the runtime sets ``finished_at``."""
        return Applied(
            applied_id=f"applied-{uuid.uuid4()}",
            plan_hash=plan.plan_hash,
            approval_ids=list(self.approval_ids),
            outcome="succeeded",
            started_at=self.now,
            finished_at=self.now,
            principal=self.applier or self.agent,
            observed=dict(observed) if observed else None,
            result=result,
            compensation_handle=compensation_handle,
        )


# --- errors a provider raises -------------------------------------------------------


class PreconditionFailedError(Exception):
    """The target system refused the write because a precondition no longer held (§8.4)."""

    def __init__(self, results: Sequence[PreconditionResult]) -> None:
        super().__init__(", ".join(r.id for r in results) or "precondition failed")
        self.results = tuple(results)


class ApplyFailedError(Exception):
    """The change definitely did not happen. Anything else raised from apply is UNKNOWN."""


class CompensationConflictError(Exception):
    """The resource changed since apply; compensating would overwrite someone else."""


# --- what the runtime calls ---------------------------------------------------------


@dataclass(frozen=True)
class BoundAction:
    spec: ActionSpec
    plan: Callable[..., Plan]
    observe: Callable[[Context, ResourceRef], Observation]
    apply: Callable[[Context, Plan], Applied]
    compensate: Callable[[Context, Plan, Applied], None] | None
    reconcile: Callable[[Context, Plan, Applied | None], State] | None

    @classmethod
    def bind(cls, obj: object) -> BoundAction:
        spec = spec_of(obj)
        return cls(
            spec=spec,
            plan=obj.plan,  # type: ignore[attr-defined]
            observe=obj.observe,  # type: ignore[attr-defined]
            apply=obj.apply,  # type: ignore[attr-defined]
            compensate=getattr(obj, "compensate", None),
            reconcile=getattr(obj, "reconcile", None),
        )
