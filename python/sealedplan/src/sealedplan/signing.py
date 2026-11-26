"""Signed approvals: a detached JWS over the canonical approval (SPEC §5.3 rule 8).

Needs the ``signing`` extra: ``pip install 'sealedplan[signing]'``.

An approver signs :meth:`Approval.signing_input` (the canonical approval without
``signature``) with their private key. The JWS is detached with an unencoded payload
(RFC 7515 Appendix F, RFC 7797): its protected header is ``{"alg", "kid", "b64": false,
"crit": ["b64"]}``, and ``signature.value`` holds ``<header>..<signature>``.

The runtime checks it with :class:`ApprovalVerifier`, given as ``Runtime(verify_signature=
...)``. Each key is registered for one approver, so a valid signature by Bob's key on an
approval that names Alice is refused. Only asymmetric algorithms are accepted: the
runtime holds public keys, never anything that could sign.

    verifier = ApprovalVerifier({"bob-2026": (bob_public_key, BOB)})
    rt = Runtime(store, identity, verify_signature=verifier)
    rt.submit_approval(signed, trusted_channel=False)
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import jwt
from jwt.exceptions import PyJWTError

from sealedplan.models import Approval, Principal, Signature

__all__ = ["ALGORITHMS", "ApprovalVerifier", "sign_approval"]

ALGORITHMS = ("EdDSA", "ES256")
"""The signature algorithms accepted: Ed25519 and ECDSA P-256 with SHA-256."""

_JWS = jwt.PyJWS(algorithms=list(ALGORITHMS))


def sign_approval(
    approval: Approval, private_key: Any, *, kid: str, alg: str = "EdDSA"
) -> Approval:
    """A copy of ``approval`` with ``signature`` set, signed with ``private_key``.

    ``private_key`` is a ``cryptography`` private key or its PEM. ``kid`` names the key
    the verifier knows it by. Set every other field, ``method`` included, before
    signing: the signature covers them all.
    """
    if alg not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {alg!r}; use one of {', '.join(ALGORITHMS)}")
    unsigned = approval.model_copy(update={"signature": None})
    value = _JWS.encode(
        unsigned.signing_input(),
        private_key,
        algorithm=alg,
        headers={"kid": kid},
        is_payload_detached=True,
    )
    return unsigned.model_copy(update={"signature": Signature(alg=alg, kid=kid, value=value)})


class ApprovalVerifier:
    """Checks approval signatures against known public keys; use as ``verify_signature``.

    ``keys`` maps a key id to the public key (a ``cryptography`` key or its PEM) and the
    approver that key belongs to.
    """

    def __init__(self, keys: Mapping[str, tuple[Any, Principal]]) -> None:
        self._keys = dict(keys)

    def __call__(self, approval: Approval) -> bool:
        """True only if the signature is valid, by a known key of the approval's approver."""
        sig = approval.signature
        if sig is None or sig.alg not in ALGORITHMS or sig.kid not in self._keys:
            return False
        public_key, owner = self._keys[sig.kid]
        if not owner.same_as(approval.approver):
            return False
        try:
            header = _JWS.get_unverified_header(sig.value)
            if header.get("alg") != sig.alg or header.get("kid") != sig.kid:
                return False
            _JWS.decode_complete(
                sig.value,
                public_key,
                algorithms=[sig.alg],
                detached_payload=approval.signing_input(),
            )
        except (PyJWTError, ValueError, TypeError):
            return False
        return True
