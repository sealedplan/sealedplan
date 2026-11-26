"""The spec's JSON Schemas and hash test vectors agree with this implementation (§6.4)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from sealedplan.canonical import CanonicalizationError, canonicalize, digest
from sealedplan.models import Plan, PlanError, parse_plan
from test_runtime import Env, make_env

SPEC = Path(__file__).resolve().parents[3] / "spec"
VECTORS = json.loads((SPEC / "test-vectors" / "plans.json").read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = [
        Resource.from_contents(json.loads(path.read_text(encoding="utf-8")))
        for path in (SPEC / "schemas").glob("*.schema.json")
    ]
    return Registry().with_resources([(uri, r) for r in resources if (uri := r.id()) is not None])


REGISTRY = _registry()


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SPEC / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=REGISTRY)


def errors(name: str, obj: Any) -> list[str]:
    return [e.message for e in validator(name).iter_errors(obj)]


def test_committed_vectors_match_the_generator() -> None:
    path = SPEC.parent / "scripts" / "test_vectors.py"
    spec = importlib.util.spec_from_file_location("test_vectors_script", path)
    assert spec is not None
    assert spec.loader is not None
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    assert json.loads(script.render()) == VECTORS, "run: uv run python scripts/test_vectors.py"


@pytest.mark.parametrize("case", VECTORS["valid"], ids=lambda c: c["name"])
def test_valid_vector(case: dict[str, Any]) -> None:
    body = {k: v for k, v in case["plan"].items() if k != "plan_hash"}
    assert canonicalize(body) == case["canonical"].encode("utf-8")
    assert digest(body) == case["plan_hash"] == case["plan"]["plan_hash"]
    assert parse_plan(json.dumps(case["plan"])).plan_hash == case["plan_hash"]
    assert errors("plan", case["plan"]) == []


@pytest.mark.parametrize("case", VECTORS["valid"], ids=lambda c: c["name"])
def test_valid_vector_matches_an_independent_jcs(case: dict[str, Any]) -> None:
    body = {k: v for k, v in case["plan"].items() if k != "plan_hash"}
    canonical = rfc8785.dumps(body)
    assert canonical == case["canonical"].encode("utf-8")
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == case["plan_hash"]


@pytest.mark.parametrize("case", VECTORS["invalid"], ids=lambda c: c["name"])
def test_invalid_vector(case: dict[str, Any]) -> None:
    with pytest.raises((PlanError, CanonicalizationError)):
        parse_plan(case["text"])


def test_schema_rejects_what_the_spec_forbids() -> None:
    plan = VECTORS["valid"][0]["plan"]
    assert errors("plan", {**plan, "params": {"replicas": 6.5}})
    assert errors("plan", {**plan, "params": {"n": 2**53}})
    assert errors("plan", {**plan, "blast_radius": None})
    assert errors("plan", {**plan, "created_at": "2026-11-09T14:03:00.5Z"})
    assert errors("plan", {**plan, "preconditions": []})
    assert errors("plan", {**plan, "effect": "IRREVERSIBLE"})  # it has a compensation
    assert errors("plan", {**plan, "extensions": {"nodots": 1}})
    assert errors("plan", {**plan, "surprise": 1})


@pytest.fixture
def env() -> Env:
    return make_env()


def test_runtime_records_match_the_schemas(env: Env) -> None:
    plan: Plan = env.propose("test.set_low")
    applied = env.rt.execute(plan.plan_hash).applied
    assert applied is not None
    compensated = env.rt.compensate(plan.plan_hash)

    assert errors("plan", plan.to_obj()) == []
    for approval in env.store.approvals(plan.plan_hash):
        assert errors("approval", approval.to_obj()) == []
    assert errors("applied", applied.to_obj()) == []
    assert errors("compensated", compensated.to_obj()) == []
    events = env.store.events(plan.plan_hash)
    assert len(events) >= 4
    for event in events:
        assert errors("event", event.to_obj()) == []
