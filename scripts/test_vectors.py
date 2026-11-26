"""Write spec/test-vectors/plans.json from the reference implementation (SPEC §6.4).

Run from the repository root after changing a case or the canonical form:

    uv run python scripts/test_vectors.py

The test suite fails if the committed file and this script disagree.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sealedplan.canonical import canonicalize, digest, digest_bytes

OUT = Path(__file__).resolve().parents[1] / "spec" / "test-vectors" / "plans.json"
IDP = "https://idp.example.invalid"
AGENT = {"id": "agent:incident-bot", "issuer": IDP, "kind": "agent"}
ALICE = {"id": "alice", "issuer": IDP, "kind": "human"}
DEPLOY = {"type": "apps/v1/Deployment", "id": "k8s://prod-cluster/shop/checkout"}


def base(**overrides: Any) -> dict[str, Any]:
    """The SPEC §5.2 example plan, without plan_hash."""
    body: dict[str, Any] = {
        "spec_version": "0.1",
        "action": {
            "name": "k8s.scale_deployment",
            "version": "1.0.0",
            "provider": "sealedplan-k8s",
        },
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
                "id": "deploy-version",
                "resource": DEPLOY,
                "kind": "version",
                "expect": "48213977",
                "enforcement": "atomic",
            }
        ],
        "blast_radius": {"resources": 1, "scopes": ["k8s://prod-cluster/shop"]},
        "compensation": {
            "strategy": "restore",
            "summary": "Scale shop/checkout back to 3 replicas",
            "params": {"namespace": "shop", "name": "checkout", "replicas": 3},
        },
        "idempotency_key": "incident-4711-scale-checkout",
        "principal": {"agent": AGENT, "sponsor": ALICE},
        "evidence": [
            {
                "kind": "k8s.server-dry-run",
                "media_type": "application/json",
                "digest": digest_bytes(b'{"kind":"Deployment"}'),
            }
        ],
        "created_at": "2026-11-09T14:03:00Z",
        "expires_at": "2026-11-09T14:33:00Z",
    }
    body.update(overrides)
    return body


def read_only(params: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """The smallest valid plan: READ_ONLY, only required fields, no preconditions."""
    body: dict[str, Any] = {
        "spec_version": "0.1",
        "action": {"name": "test.echo"},
        "params": params,
        "effect": "READ_ONLY",
        "risk": {"level": "low"},
        "summary": "Read only",
        "changes": [],
        "preconditions": [],
        "idempotency_key": "k",
        "principal": {"agent": AGENT},
        "created_at": "2026-11-09T14:03:00Z",
        "expires_at": "2026-11-09T14:33:00Z",
    }
    body.update(overrides)
    return body


VALID: list[tuple[str, str, dict[str, Any]]] = [
    ("spec-example", "The plan in SPEC §5.2.", base()),
    (
        "minimal-read-only",
        "Only the required fields; empty changes and preconditions.",
        read_only({}),
    ),
    (
        "key-order-utf16",
        "Object keys sort by UTF-16 code units (RFC 8785 §3.2.3), not code points: "
        "U+1F600 (surrogates D83D DE00) sorts before U+FF61.",
        read_only({"\uff61": 1, "\U0001f600": 2, "\u20ac": 3, "\u00e9": 4, "b": 5, "a": 6, "B": 7}),
    ),
    (
        "string-escapes",
        'Only \\b \\t \\n \\f \\r \\" \\\\ use short escapes; other controls are \\u00xx '
        "in lowercase hex; '/' and non-ASCII characters are written as-is.",
        read_only({"s": 'a\bb\tc\nd\fe\rf"g\\h\u0000i\u001fj/k\u007fl\u00e9m\U0001f600'}),
    ),
    (
        "integer-limits",
        "The largest and smallest allowed integers; bigger numbers and decimals are strings.",
        read_only(
            {
                "max": 9007199254740991,
                "min": -9007199254740991,
                "zero": 0,
                "negative": -1,
                "big": "18446744073709551615",
                "decimal": "0.25",
            }
        ),
    ),
    (
        "null-and-empty",
        "null inside params and extensions is hashed as null; empty objects and arrays stay.",
        read_only(
            {"none": None, "empty_object": {}, "empty_array": [], "nested": [None, {"x": []}]},
            extensions={"com.example.ticket": {"id": "T-1", "link": None}},
        ),
    ),
    (
        "compensatable-run-step",
        "A semantic compensation with its own precondition, a fingerprint precondition, "
        "a sensitive field, and a parent run.",
        base(
            action={"name": "crm.issue_credit"},
            params={"account": "acct-9", "amount": "125.00", "currency": "EUR"},
            effect="COMPENSATABLE",
            risk={"level": "high", "reasons": ["money"]},
            summary="Credit 125.00 EUR to acct-9",
            changes=[
                {
                    "resource": {"type": "crm/Account", "id": "crm://acct-9"},
                    "op": "update",
                    "before": {"balance": "10.00", "api_key": "ref:vault/acct-9"},
                    "after": {"balance": "135.00", "api_key": "ref:vault/acct-9"},
                    "sensitive": ["/before/api_key", "/after/api_key"],
                }
            ],
            preconditions=[
                {
                    "id": "balance",
                    "resource": {"type": "crm/Account", "id": "crm://acct-9"},
                    "kind": "fingerprint",
                    "expect": digest({"/balance": "10.00"}),
                    "select": ["/balance"],
                    "enforcement": "check_then_act",
                }
            ],
            blast_radius={"resources": 1, "scopes": ["crm://"], "estimate": False},
            compensation={
                "strategy": "semantic",
                "summary": "Debit 125.00 EUR from acct-9",
                "params": {"account": "acct-9", "amount": "-125.00"},
                "preconditions": [
                    {
                        "id": "credit-exists",
                        "resource": {"type": "crm/Credit", "id": "crm://acct-9/credits/c-1"},
                        "kind": "exists",
                        "enforcement": "check_then_act",
                    }
                ],
            },
            evidence=None,
            parent={"run_id": "run-42", "step": 2},
        ),
    ),
]


def raw(body: dict[str, Any], plan_hash: str) -> str:
    return json.dumps({**body, "plan_hash": plan_hash}, ensure_ascii=False)


def invalid() -> list[dict[str, str]]:
    """Plans a receiver MUST reject. Each breaks one rule; the hash is right otherwise."""
    ok = base()
    good = digest(ok)
    null_field = {**ok, "blast_radius": None}
    bad_time = {**ok, "created_at": "2026-11-09T14:03:00.500Z"}
    no_pre = {**ok, "preconditions": []}
    replicas = json.dumps(ok["params"])
    cases = [
        ("hash-mismatch", "plan_hash is for a different summary (§6.1)",
         raw({**ok, "summary": "Scale shop/checkout from 3 to 60 replicas"}, good)),
        ("non-integer-number", "6.5 is not an integer (§6.2 rule 1)",
         raw(ok, good).replace(replicas, replicas.replace("6", "6.5"))),
        ("integer-out-of-range", "2^53 is outside the safe range (§6.2 rule 1)",
         raw(ok, good).replace(replicas, replicas.replace("6", "9007199254740992"))),
        ("duplicate-key", "\"replicas\" appears twice (§6.2 rule 5)",
         raw(ok, good).replace(replicas, replicas.replace("6}", '6, "replicas": 7}'))),
        ("null-optional-field", "an optional field is null instead of absent (§5)",
         raw(null_field, digest(null_field))),
        ("fractional-seconds", "timestamps have whole seconds (§5)",
         raw(bad_time, digest(bad_time))),
        ("missing-precondition", "a REVERSIBLE plan needs a precondition (§5.2.1)",
         raw(no_pre, digest(no_pre))),
    ]  # fmt: skip
    return [{"name": n, "reason": r, "text": t} for n, r, t in cases]


def build() -> dict[str, Any]:
    valid = []
    for name, description, body in VALID:
        body = {k: v for k, v in body.items() if v is not None}
        valid.append(
            {
                "name": name,
                "description": description,
                "canonical": canonicalize(body).decode("utf-8"),
                "plan_hash": digest(body),
                "plan": {**body, "plan_hash": digest(body)},
            }
        )
    return {
        "description": (
            "SPEC §6.4 test vectors. For each valid case, the JCS form of plan without "
            "plan_hash MUST equal canonical (as UTF-8), its SHA-256 MUST equal plan_hash, and "
            "a receiver MUST accept the plan. A receiver MUST reject the text of every "
            "invalid case."
        ),
        "spec_version": "0.1",
        "valid": valid,
        "invalid": invalid(),
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT}")
