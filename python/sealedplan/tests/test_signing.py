"""Signed approvals: detached JWS over the canonical approval (SPEC §5.3 rule 8)."""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from conftest import IDP, T0
from sealedplan.models import Approval, ApprovalScope, Plan, Principal
from sealedplan.signing import ApprovalVerifier, sign_approval

BOB = Principal(id="bob", issuer=IDP, kind="human")
CAROL = Principal(id="carol", issuer=IDP, kind="human")


def unsigned(plan: Plan, who: Principal = BOB, **fields: Any) -> Approval:
    return Approval(
        approval_id="appr-1",
        plan_hash=plan.plan_hash,
        decision="approve",
        approver=who,
        method="signed",
        scope=ApprovalScope(),
        issued_at=T0,
        expires_at=T0 + timedelta(minutes=10),
        **fields,
    )


@pytest.fixture
def bob_signer() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def verifier(bob_signer: ed25519.Ed25519PrivateKey) -> ApprovalVerifier:
    return ApprovalVerifier({"bob-2026": (bob_signer.public_key(), BOB)})


def test_signed_approval_verifies(
    plan: Plan, bob_signer: ed25519.Ed25519PrivateKey, verifier: ApprovalVerifier
) -> None:
    signed = sign_approval(unsigned(plan), bob_signer, kid="bob-2026")
    assert signed.signature is not None
    assert (signed.signature.alg, signed.signature.kid) == ("EdDSA", "bob-2026")
    assert verifier(signed)


def test_signature_is_a_detached_unencoded_jws(
    plan: Plan, bob_signer: ed25519.Ed25519PrivateKey
) -> None:
    signed = sign_approval(unsigned(plan), bob_signer, kid="bob-2026")
    assert signed.signature is not None
    header_b64, payload, _ = signed.signature.value.split(".")
    assert payload == ""  # detached
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    assert header["alg"] == "EdDSA"
    assert header["kid"] == "bob-2026"
    assert header["b64"] is False
    assert header["crit"] == ["b64"]


def test_any_changed_field_breaks_the_signature(
    plan: Plan, bob_signer: ed25519.Ed25519PrivateKey, verifier: ApprovalVerifier
) -> None:
    signed = sign_approval(unsigned(plan), bob_signer, kid="bob-2026")
    for change in (
        {"plan_hash": "sha256:" + "0" * 64},
        {"decision": "reject"},
        {"expires_at": T0 + timedelta(minutes=20)},
        {"comment": "added later"},
    ):
        assert not verifier(signed.model_copy(update=change)), change


def test_signer_belongs_to_one_approver(
    plan: Plan, bob_signer: ed25519.Ed25519PrivateKey, verifier: ApprovalVerifier
) -> None:
    # Bob's key signing an approval that names Carol is not Carol's approval.
    as_carol = sign_approval(unsigned(plan, CAROL), bob_signer, kid="bob-2026")
    assert not verifier(as_carol)


def test_unknown_or_wrong_signer_is_refused(
    plan: Plan, bob_signer: ed25519.Ed25519PrivateKey, verifier: ApprovalVerifier
) -> None:
    other = ed25519.Ed25519PrivateKey.generate()
    assert not verifier(sign_approval(unsigned(plan), other, kid="bob-2026"))
    assert not verifier(sign_approval(unsigned(plan), bob_signer, kid="bob-old"))
    assert not verifier(unsigned(plan))


def test_signature_fields_must_match_the_jws_header(
    plan: Plan, bob_signer: ed25519.Ed25519PrivateKey, verifier: ApprovalVerifier
) -> None:
    signed = sign_approval(unsigned(plan), bob_signer, kid="bob-2026")
    assert signed.signature is not None
    relabeled = signed.signature.model_copy(update={"alg": "ES256"})
    assert not verifier(signed.model_copy(update={"signature": relabeled}))


def test_es256_and_pem_public_keys(plan: Plan) -> None:
    signer = ec.generate_private_key(ec.SECP256R1())
    pem = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    verifier = ApprovalVerifier({"bob-p256": (pem, BOB)})
    assert verifier(sign_approval(unsigned(plan), signer, kid="bob-p256", alg="ES256"))


def test_symmetric_algorithms_are_refused(plan: Plan) -> None:
    with pytest.raises(ValueError, match="unsupported algorithm"):
        sign_approval(unsigned(plan), bytes(32), kid="k", alg="HS256")
