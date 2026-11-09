from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conftest import IDP, T0, make_plan, plan_fields
from sealedplan.canonical import digest
from sealedplan.models import Approval, Effect, Plan, PlanBody, RiskLevel
from sealedplan.policy import (
    DEFAULT_TABLE,
    Decision,
    DefaultPolicy,
    PolicyContext,
    PolicyResult,
    approvals_satisfy,
    decide,
    effective_effect,
)

CTX = PolicyContext(now=T0)
effects = st.sampled_from(list(Effect))
risks = st.sampled_from(list(RiskLevel))

# SPEC §10.3, copied cell by cell so a change to either side is caught.
SPEC_TABLE = """
READ_ONLY     auto       auto       auto       approve
REVERSIBLE    auto       approve    approve    two_person
COMPENSATABLE approve    approve    two_person two_person
IRREVERSIBLE  approve    approve    two_person two_person
"""


def test_default_table_matches_spec() -> None:
    for line in SPEC_TABLE.strip().splitlines():
        effect, *cells = line.split()
        assert [str(DEFAULT_TABLE[Effect(effect)][r]) for r in RiskLevel] == cells


@given(risks)
def test_default_never_auto_for_irreversible(level: RiskLevel) -> None:
    assert DEFAULT_TABLE[Effect.IRREVERSIBLE][level] is not Decision.AUTO


def test_default_policy_uses_effective_effect(plan: Plan) -> None:
    result = decide(DefaultPolicy(), plan, Effect.COMPENSATABLE, CTX)
    assert result.decision is Decision.APPROVE
    assert result.policy_digest == DefaultPolicy.digest
    low = make_plan(risk={"level": "low"})
    assert decide(DefaultPolicy(), low, Effect.REVERSIBLE, CTX).decision is Decision.AUTO


@pytest.mark.parametrize(
    ("declared", "override", "expected"),
    [
        (Effect.REVERSIBLE, None, Effect.REVERSIBLE),
        (None, None, Effect.IRREVERSIBLE),
        (Effect.READ_ONLY, None, Effect.REVERSIBLE),
        (Effect.REVERSIBLE, Effect.COMPENSATABLE, Effect.COMPENSATABLE),
        (Effect.REVERSIBLE, Effect.READ_ONLY, Effect.REVERSIBLE),
    ],
)
def test_effective_effect(
    plan: Plan, declared: Effect | None, override: Effect | None, expected: Effect
) -> None:
    assert effective_effect(plan, declared, override) is expected


def test_missing_compensation_counts_as_irreversible() -> None:
    obj = PlanBody.model_validate(plan_fields(compensation=None)).to_obj()
    plan = Plan.model_validate({**obj, "plan_hash": digest(obj)})
    assert effective_effect(plan, Effect.REVERSIBLE) is Effect.IRREVERSIBLE


@given(st.none() | effects, st.none() | effects)
def test_effective_effect_never_lowers(declared: Effect | None, override: Effect | None) -> None:
    plan = make_plan()
    result = effective_effect(plan, declared, override)
    for e in (plan.effect, declared, override):
        if e is not None:
            assert result.severity >= e.severity


class _Fixed:
    def __init__(self, decision: Decision) -> None:
        self.decision = decision

    def evaluate(self, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult:
        return PolicyResult(self.decision, ("fixed",), "sha256:" + "0" * 64)


class _Broken:
    def evaluate(self, plan: Plan, effect: Effect, ctx: PolicyContext) -> PolicyResult:
        raise RuntimeError("boom")


def test_missing_policy_denies(plan: Plan) -> None:
    assert decide(None, plan, Effect.REVERSIBLE, CTX).decision is Decision.DENY


def test_policy_error_denies(plan: Plan) -> None:
    result = decide(_Broken(), plan, Effect.REVERSIBLE, CTX)
    assert result.decision is Decision.DENY
    assert "RuntimeError" in result.reasons[0]


def test_auto_for_irreversible_is_denied(plan: Plan) -> None:
    assert decide(_Fixed(Decision.AUTO), plan, Effect.IRREVERSIBLE, CTX).decision is Decision.DENY
    assert decide(_Fixed(Decision.AUTO), plan, Effect.REVERSIBLE, CTX).decision is Decision.AUTO


def test_effect_below_plan_is_denied(plan: Plan) -> None:
    assert decide(_Fixed(Decision.AUTO), plan, Effect.READ_ONLY, CTX).decision is Decision.DENY


def _approval(plan: Plan, who: str, decision: str = "approve", plan_hash: str = "") -> Approval:
    kind = "agent" if who.startswith("agent:") else "human"
    return Approval.model_validate(
        {
            "approval_id": f"appr-{who}",
            "plan_hash": plan_hash or plan.plan_hash,
            "decision": decision,
            "approver": {"id": who, "issuer": IDP, "kind": kind},
            "method": "cli",
            "scope": {"uses": 1},
            "issued_at": T0,
            "expires_at": T0 + timedelta(minutes=10),
        }
    )


def test_single_approval(plan: Plan) -> None:
    assert not approvals_satisfy(Decision.APPROVE, plan, [])
    assert approvals_satisfy(Decision.APPROVE, plan, [_approval(plan, "bob")])
    assert approvals_satisfy(Decision.APPROVE, plan, [_approval(plan, "alice")])


def test_agent_cannot_approve_its_own_plan(plan: Plan) -> None:
    assert not approvals_satisfy(Decision.APPROVE, plan, [_approval(plan, "agent:incident-bot")])


def test_rejections_and_other_hashes_do_not_count(plan: Plan) -> None:
    other = "sha256:" + "1" * 64
    assert not approvals_satisfy(
        Decision.APPROVE,
        plan,
        [_approval(plan, "bob", "reject"), _approval(plan, "carol", plan_hash=other)],
    )


def test_two_person(plan: Plan) -> None:
    bob, carol, alice = (_approval(plan, n) for n in ("bob", "carol", "alice"))
    assert not approvals_satisfy(Decision.TWO_PERSON, plan, [bob])
    assert not approvals_satisfy(Decision.TWO_PERSON, plan, [bob, bob])
    assert approvals_satisfy(Decision.TWO_PERSON, plan, [bob, carol])
    assert approvals_satisfy(Decision.TWO_PERSON, plan, [alice, bob])
    agent = _approval(plan, "agent:incident-bot")
    assert not approvals_satisfy(Decision.TWO_PERSON, plan, [bob, agent])


def test_same_id_different_issuer_is_a_different_person(plan: Plan) -> None:
    bob = _approval(plan, "bob")
    other_bob = Approval.model_validate(
        {
            **bob.to_obj(),
            "approver": {"id": "bob", "issuer": "https://other.invalid", "kind": "human"},
        }
    )
    assert approvals_satisfy(Decision.TWO_PERSON, plan, [bob, other_bob])


def test_auto_and_deny(plan: Plan) -> None:
    assert approvals_satisfy(Decision.AUTO, plan, [])
    assert not approvals_satisfy(Decision.DENY, plan, [_approval(plan, "bob")])
