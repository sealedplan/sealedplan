from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from conftest import IDP, T0, make_plan, plan_fields
from sealedplan.canonical import CanonicalizationError, digest
from sealedplan.models import (
    Approval,
    Effect,
    Event,
    Plan,
    PlanBody,
    PlanError,
    Precondition,
    parse_plan,
)
from sealedplan.state import State


def test_seal_attaches_hash_of_body(plan: Plan) -> None:
    body = plan.to_obj()
    del body["plan_hash"]
    assert plan.plan_hash == digest(body)
    assert plan.to_obj()["created_at"] == "2026-11-09T14:03:00Z"


def test_seal_is_deterministic() -> None:
    assert make_plan().plan_hash == make_plan().plan_hash


def test_every_field_is_covered_by_the_hash(plan: Plan) -> None:
    other = make_plan(summary="Scale shop/checkout from 3 to 6 replicas.")
    assert other.plan_hash != plan.plan_hash


def test_unset_optional_fields_are_omitted_but_nulls_in_params_kept() -> None:
    obj = make_plan(params={"a": None}).to_obj()
    assert "evidence" not in obj
    assert "parent" not in obj
    assert obj["params"] == {"a": None}


def test_tampered_plan_cannot_be_constructed(plan: Plan) -> None:
    obj = plan.to_obj()
    obj["params"]["replicas"] = 60
    with pytest.raises(ValidationError, match="does not match"):
        Plan.model_validate(obj)


def test_parse_plan_round_trips(plan: Plan) -> None:
    assert parse_plan(json.dumps(plan.to_obj())) == plan


def test_parse_plan_rejects_hash_mismatch(plan: Plan) -> None:
    obj = plan.to_obj()
    obj["summary"] = "something harmless"
    with pytest.raises(PlanError, match="as sent"):
        parse_plan(json.dumps(obj))


def test_parse_plan_rejects_null_optional_field(plan: Plan) -> None:
    obj = plan.to_obj()
    obj["parent"] = None
    obj["plan_hash"] = digest({k: v for k, v in obj.items() if k != "plan_hash"})
    with pytest.raises(PlanError):
        parse_plan(json.dumps(obj))


def test_parse_plan_rejects_unknown_top_level_field(plan: Plan) -> None:
    obj = plan.to_obj()
    obj["vendor_note"] = "x"
    obj["plan_hash"] = digest({k: v for k, v in obj.items() if k != "plan_hash"})
    with pytest.raises(PlanError, match="vendor_note"):
        parse_plan(json.dumps(obj))


def test_extensions_need_namespaced_keys() -> None:
    assert make_plan(extensions={"io.example/note": 1}).extensions == {"io.example/note": 1}
    with pytest.raises(ValidationError, match="reverse-DNS"):
        make_plan(extensions={"note": 1})


def test_float_in_params_is_rejected_at_seal() -> None:
    with pytest.raises(CanonicalizationError):
        make_plan(params={"cpu": 0.5})


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-09T14:03:00+00:00",
        "2026-11-09T14:03:00.5Z",
        "2026-11-09 14:03:00Z",
        datetime(2026, 11, 9, 14, 3),
        datetime(2026, 11, 9, 14, 3, 0, 500, tzinfo=UTC),
        datetime(2026, 11, 9, 15, 3, tzinfo=timezone(timedelta(hours=1))),
    ],
)
def test_timestamps_must_be_whole_second_utc(value: Any) -> None:
    with pytest.raises(ValidationError, match="timestamp"):
        make_plan(created_at=value)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"expires_at": T0}, "after created_at"),
        ({"preconditions": []}, "no preconditions"),
        ({"effect": "IRREVERSIBLE"}, "must not have compensation"),
        ({"effect": "COMPENSATABLE"}, "only for REVERSIBLE"),
        ({"idempotency_key": ""}, "idempotency_key"),
        ({"spec_version": "0.2"}, "spec_version"),
    ],
)
def test_plan_rules(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        make_plan(**overrides)


def test_duplicate_precondition_ids_rejected() -> None:
    pre = plan_fields()["preconditions"][0]
    with pytest.raises(ValidationError, match="unique"):
        make_plan(preconditions=[pre, pre])


def test_read_only_plan_may_have_no_preconditions() -> None:
    plan = make_plan(effect="READ_ONLY", preconditions=[], compensation=None)
    assert plan.preconditions == []


def test_seal_requires_compensation_for_reversible() -> None:
    body = PlanBody.model_validate(plan_fields(compensation=None))
    with pytest.raises(PlanError, match="must include compensation"):
        body.seal()


def test_receiver_accepts_reversible_plan_without_compensation() -> None:
    # §4.2 rule 3: receivers treat it as IRREVERSIBLE rather than rejecting it.
    obj = PlanBody.model_validate(plan_fields(compensation=None)).to_obj()
    obj["plan_hash"] = digest(obj)
    assert parse_plan(json.dumps(obj)).effect is Effect.REVERSIBLE


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"kind": "version"}, "needs expect"),
        ({"kind": "fingerprint", "expect": "sha256:00", "select": ["/a"]}, "sha256"),
        ({"kind": "fingerprint", "expect": "sha256:" + "0" * 64}, "needs select"),
        ({"kind": "fingerprint", "expect": "sha256:" + "0" * 64, "select": ["a"]}, "Pointer"),
        ({"kind": "exists", "expect": "1"}, "takes no expect"),
        ({"kind": "absent", "select": ["/a"]}, "only used by fingerprint"),
    ],
)
def test_precondition_rules(fields: dict[str, Any], message: str) -> None:
    base = {"id": "p", "resource": {"type": "t", "id": "x"}, "enforcement": "atomic"}
    with pytest.raises(ValidationError, match=message):
        Precondition.model_validate({**base, **fields})


def test_non_atomic_preconditions_listed() -> None:
    pre = {**plan_fields()["preconditions"][0], "enforcement": "check_then_act"}
    assert [p.id for p in make_plan(preconditions=[pre]).non_atomic_preconditions] == [
        "deploy-generation"
    ]


def test_effect_severity_order() -> None:
    assert [e.severity for e in Effect] == [0, 1, 2, 3]


def test_approval_signing_input_excludes_signature(plan: Plan) -> None:
    approval = Approval.model_validate(
        {
            "approval_id": "appr-0001",
            "plan_hash": plan.plan_hash,
            "decision": "approve",
            "approver": {"id": "bob", "issuer": IDP, "kind": "human"},
            "method": "cli",
            "scope": {"uses": 1},
            "issued_at": T0,
            "expires_at": T0 + timedelta(minutes=15),
            "signature": {"alg": "EdDSA", "kid": "bob-2026", "value": "sig"},
        }
    )
    assert b"signature" not in approval.signing_input()
    with pytest.raises(ValidationError):
        Approval.model_validate({**approval.to_obj(), "scope": {"uses": 2}})


def test_event_serializes_from_by_alias(plan: Plan) -> None:
    event = Event(
        event_id="evt-1",
        plan_hash=plan.plan_hash,
        from_=State.PLANNED,
        to=State.PENDING_APPROVAL,
        at=T0,
        actor=plan.principal.agent,
    )
    obj = event.to_obj()
    assert obj["from"] == "PLANNED"
    assert Event.model_validate(obj) == event
    assert event.digest().startswith("sha256:")
