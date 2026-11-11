"""Contract objects (SPEC §5): Principal, Plan, Approval, Applied, Compensated, Event.

Every object serializes with :meth:`SpecModel.to_obj`, which omits optional fields that
have no value (§5) and keeps ``null`` inside free-form JSON (§6.2 rule 3). A
:class:`Plan` cannot be constructed unless its ``plan_hash`` matches its contents.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    ValidationError,
    field_validator,
    model_validator,
)

from sealedplan.canonical import canonicalize, digest, loads_strict
from sealedplan.state import State

SpecVersion = Literal["0.1"]

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


class PlanError(ValueError):
    """A plan breaks a rule of SPEC §5.2 or §6."""


def whole_seconds(dt: datetime) -> datetime:
    """Convert an aware datetime to UTC with whole seconds, as §5 timestamps require."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(UTC).replace(microsecond=0)


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, str):
        if not _TS_RE.fullmatch(value):
            raise ValueError("timestamp must look like 2026-11-09T14:03:00Z")
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be in UTC")
        if value.microsecond:
            raise ValueError("timestamp must have whole seconds")
        return value.astimezone(UTC)
    raise ValueError("timestamp must be a string or datetime")


Timestamp = Annotated[
    datetime,
    BeforeValidator(_parse_timestamp),
    PlainSerializer(lambda dt: dt.strftime(_TS_FORMAT), return_type=str, when_used="json"),
]
Digest = Annotated[str, Field(pattern=_DIGEST_RE.pattern)]


class Effect(StrEnum):
    """Effect classes (§4.1), in severity order."""

    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    COMPENSATABLE = "COMPENSATABLE"
    IRREVERSIBLE = "IRREVERSIBLE"

    @property
    def severity(self) -> int:
        return list(Effect).index(self)


def most_severe(*effects: Effect) -> Effect:
    return max(effects, key=lambda e: e.severity)


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def severity(self) -> int:
        return list(RiskLevel).index(self)


class SpecModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    def to_obj(self) -> dict[str, Any]:
        """The JSON object for this model, with unset optional fields omitted."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


# --- §5.1 ----------------------------------------------------------------------------


class Principal(SpecModel):
    id: str
    issuer: str
    kind: Literal["agent", "human", "service"]

    @property
    def key(self) -> tuple[str, str]:
        """Identity for comparison: ``(id, issuer)``, never ``id`` alone (§5.1)."""
        return (self.id, self.issuer)

    def same_as(self, other: Principal | None) -> bool:
        return other is not None and self.key == other.key


# --- §5.2 ----------------------------------------------------------------------------


class ActionRef(SpecModel):
    name: str
    version: str | None = None
    provider: str | None = None


class ResourceRef(SpecModel):
    type: str
    id: str


class Change(SpecModel):
    resource: ResourceRef
    op: Literal["create", "update", "delete", "invoke"]
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    patch: list[dict[str, Any]] | None = None
    sensitive: list[str] | None = None


class Precondition(SpecModel):
    id: str
    resource: ResourceRef
    kind: Literal["version", "fingerprint", "exists", "absent"]
    expect: str | None = None
    select: list[str] | None = None
    enforcement: Literal["atomic", "check_then_act"]

    @model_validator(mode="after")
    def _check_kind(self) -> Self:
        if self.kind == "version" and self.expect is None:
            raise ValueError("a version precondition needs expect")
        if self.kind == "fingerprint":
            if self.expect is None or not _DIGEST_RE.fullmatch(self.expect):
                raise ValueError("a fingerprint precondition needs expect = sha256:<hex>")
            if not self.select:
                raise ValueError("a fingerprint precondition needs select")
            if any(p and not p.startswith("/") for p in self.select):
                raise ValueError("select entries must be JSON Pointers")
        elif self.select is not None:
            raise ValueError("select is only used by fingerprint preconditions")
        if self.kind in ("exists", "absent") and self.expect is not None:
            raise ValueError(f"a {self.kind} precondition takes no expect")
        return self


class Risk(SpecModel):
    level: RiskLevel
    reasons: list[str] | None = None


class Compensation(SpecModel):
    strategy: Literal["restore", "semantic"]
    summary: str
    params: dict[str, Any] | None = None
    preconditions: list[Precondition] | None = None


class BlastRadius(SpecModel):
    resources: int = Field(ge=0)
    scopes: list[str]
    estimate: bool | None = None
    notes: str | None = None


class Evidence(SpecModel):
    kind: str
    media_type: str
    digest: Digest


class PlanPrincipals(SpecModel):
    agent: Principal
    sponsor: Principal | None = None


class Parent(SpecModel):
    run_id: str
    step: int = Field(ge=0)


def _check_extension_keys(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is not None:
        bad = [k for k in value if "." not in k and ":" not in k]
        if bad:
            raise ValueError(f"extension keys must be reverse-DNS or URIs: {bad}")
    return value


class PlanBody(SpecModel):
    """Every plan field except ``plan_hash``. Call :meth:`seal` to get a :class:`Plan`."""

    spec_version: SpecVersion = "0.1"
    action: ActionRef
    params: dict[str, Any]
    effect: Effect
    risk: Risk
    summary: str
    changes: list[Change]
    preconditions: list[Precondition]
    blast_radius: BlastRadius | None = None
    compensation: Compensation | None = None
    idempotency_key: str = Field(min_length=1)
    principal: PlanPrincipals
    evidence: list[Evidence] | None = None
    created_at: Timestamp
    expires_at: Timestamp
    parent: Parent | None = None
    extensions: dict[str, Any] | None = None

    _check_extensions = field_validator("extensions")(_check_extension_keys)

    @model_validator(mode="after")
    def _check_rules(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if not self.preconditions and self.effect is not Effect.READ_ONLY:
            raise ValueError("only a READ_ONLY plan may have no preconditions (§5.2.1)")
        ids = [p.id for p in self.preconditions]
        if len(ids) != len(set(ids)):
            raise ValueError("precondition ids must be unique")
        if self.compensation is not None:
            if self.effect is Effect.IRREVERSIBLE:
                raise ValueError("an IRREVERSIBLE plan must not have compensation (§5.2.5)")
            if self.compensation.strategy == "restore" and self.effect is not Effect.REVERSIBLE:
                raise ValueError("strategy 'restore' is only for REVERSIBLE plans")
        return self

    def body_obj(self) -> dict[str, Any]:
        obj = self.to_obj()
        obj.pop("plan_hash", None)
        return obj

    def compute_hash(self) -> str:
        """``sha256:`` over the canonical plan without ``plan_hash`` (§6.1)."""
        return digest(self.body_obj())

    def seal(self) -> Plan:
        """Producer side: apply the producer-only rules and attach ``plan_hash``."""
        if self.effect in (Effect.REVERSIBLE, Effect.COMPENSATABLE) and self.compensation is None:
            raise PlanError(f"a {self.effect} plan must include compensation (§5.2.5)")
        obj = self.body_obj()
        return Plan.model_validate({**obj, "plan_hash": digest(obj)})

    @property
    def non_atomic_preconditions(self) -> list[Precondition]:
        return [p for p in self.preconditions if p.enforcement != "atomic"]


class Plan(PlanBody):
    """A sealed plan. Construction fails unless ``plan_hash`` matches the contents."""

    plan_hash: Digest

    @model_validator(mode="after")
    def _check_hash(self) -> Self:
        expected = self.compute_hash()
        if self.plan_hash != expected:
            raise ValueError(f"plan_hash {self.plan_hash} does not match contents ({expected})")
        return self


def parse_plan(text: str | bytes) -> Plan:
    """Receiver side: parse, verify the hash over the bytes as sent, and validate."""
    raw = loads_strict(text)
    if not isinstance(raw, dict):
        raise PlanError("a plan must be a JSON object")
    claimed = raw.get("plan_hash")
    body = {k: v for k, v in raw.items() if k != "plan_hash"}
    if claimed != digest(body):
        raise PlanError("plan_hash does not match the plan as sent")
    try:
        plan = Plan.model_validate(raw)
    except ValidationError as exc:
        raise PlanError(str(exc)) from exc
    if canonicalize(plan.to_obj()) != canonicalize(raw):
        raise PlanError("plan contains values the spec does not allow (for example null fields)")
    return plan


# --- §5.3 ----------------------------------------------------------------------------


class ApprovalScope(SpecModel):
    uses: Literal[1] = 1
    apply_by: list[Principal] | None = None


class Signature(SpecModel):
    alg: str
    kid: str
    value: str


class Approval(SpecModel):
    spec_version: SpecVersion = "0.1"
    approval_id: str
    plan_hash: Digest
    decision: Literal["approve", "reject"]
    approver: Principal
    method: Literal["cli", "url", "webhook", "chat", "signed", "policy"]
    scope: ApprovalScope
    comment: str | None = None
    issued_at: Timestamp
    expires_at: Timestamp
    signature: Signature | None = None

    def signing_input(self) -> bytes:
        """The canonical approval without ``signature`` (§5.3 rule 8)."""
        obj = self.to_obj()
        obj.pop("signature", None)
        return canonicalize(obj)


# --- §5.4 to §5.6 ---------------------------------------------------------------------


class Applied(SpecModel):
    spec_version: SpecVersion = "0.1"
    applied_id: str
    plan_hash: Digest
    approval_ids: list[str]
    outcome: Literal["succeeded", "failed", "unknown"]
    started_at: Timestamp
    finished_at: Timestamp
    principal: Principal
    observed: dict[str, Any] | None = None
    result: Any = None
    compensation_handle: Any = None
    error: str | None = None


class Trigger(SpecModel):
    run_id: str
    failed_step: int = Field(ge=0)


class Compensated(SpecModel):
    spec_version: SpecVersion = "0.1"
    compensation_id: str
    applied_id: str
    plan_hash: Digest
    reason: Literal["step_failed", "manual", "policy"]
    outcome: Literal["succeeded", "failed", "skipped", "conflict", "unknown"]
    started_at: Timestamp
    finished_at: Timestamp
    trigger: Trigger | None = None
    error: str | None = None


class Event(SpecModel):
    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)

    spec_version: SpecVersion = "0.1"
    event_id: str
    plan_hash: Digest
    from_: State | None = Field(default=None, alias="from")
    to: State
    at: Timestamp
    actor: Principal
    detail: dict[str, Any] | None = None
    prev: Digest | None = None

    def digest(self) -> str:
        """Hash used as the next event's ``prev`` (§5.6)."""
        return digest(self.to_obj())
