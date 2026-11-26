# sealedplan (Python)

Reference runtime for the [sealedplan contract](../../spec/SPEC.md): effect classes, sealed
plans, hash-bound approvals, drift guard, compensation.

```python
from sealedplan import Effect, action
```

Status: pre-alpha.

## Signed approvals

An approval that reaches the runtime through a party it does not trust (an MCP or A2A
client) must be signed by the approver (SPEC §5.3 rule 8). Install the extra:

```sh
pip install 'sealedplan[signing]'
```

```python
from sealedplan.signing import ApprovalVerifier, sign_approval

# The approver's side: sign with their private key.
signed = sign_approval(approval, private_key, kid="bob-2026")  # EdDSA by default, or ES256

# The runtime's side: public keys only, each bound to one approver.
rt = Runtime(store, identity, verify_signature=ApprovalVerifier({"bob-2026": (bob_public, BOB)}))
rt.submit_approval(signed, trusted_channel=False)
```

The signature is a detached JWS with an unencoded payload (RFC 7797) over the canonical
approval. Changing any field breaks it, and a valid signature by Bob's key on an approval
that names someone else is refused.
