from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sealedplan.models import Plan, PlanBody

T0 = datetime(2026, 11, 9, 14, 3, tzinfo=UTC)
IDP = "https://idp.example.invalid"
DEPLOY = {"type": "apps/v1/Deployment", "id": "k8s://test-cluster/shop/checkout"}


def plan_fields(**overrides: Any) -> dict[str, Any]:
    """The SPEC §5.2 example plan as a dict, with optional overrides."""
    fields: dict[str, Any] = {
        "action": {"name": "k8s.scale_deployment", "version": "1.0.0"},
        "params": {"namespace": "shop", "name": "checkout", "replicas": 6},
        "effect": "REVERSIBLE",
        "risk": {"level": "medium", "reasons": ["production namespace"]},
        "summary": "Scale shop/checkout from 3 to 6 replicas",
        "changes": [
            {
                "resource": DEPLOY,
                "op": "update",
                "before": {"spec": {"replicas": 3}},
                "after": {"spec": {"replicas": 6}},
            }
        ],
        "preconditions": [
            {
                "id": "deploy-generation",
                "resource": DEPLOY,
                "kind": "version",
                "expect": "7",
                "enforcement": "atomic",
            }
        ],
        "blast_radius": {"resources": 1, "scopes": ["k8s://test-cluster/shop"]},
        "compensation": {
            "strategy": "restore",
            "summary": "Scale shop/checkout back to 3 replicas",
            "params": {"namespace": "shop", "name": "checkout", "replicas": 3},
        },
        "idempotency_key": "incident-4711-scale-checkout",
        "principal": {
            "agent": {"id": "agent:incident-bot", "issuer": IDP, "kind": "agent"},
            "sponsor": {"id": "alice", "issuer": IDP, "kind": "human"},
        },
        "created_at": T0,
        "expires_at": T0 + timedelta(minutes=30),
    }
    fields.update(overrides)
    return fields


def make_plan(**overrides: Any) -> Plan:
    return PlanBody.model_validate(plan_fields(**overrides)).seal()


@pytest.fixture
def plan() -> Plan:
    return make_plan()
