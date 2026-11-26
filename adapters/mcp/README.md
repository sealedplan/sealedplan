# sealedplan-mcp

Serve a sealedplan runtime's actions as MCP tools, following the
[MCP binding](../../spec/SPEC.md#12-mcp-binding-mcp-2026-07-28) of the contract. Needs
the MCP Python SDK 2.3 or later (protocol 2026-07-28).

```python
from sealedplan_mcp import create_server

server = create_server(rt, agent=AGENT)  # rt: a Runtime with actions registered
server.run()  # stdio
```

Each registered action becomes one tool. `sql.update_row` becomes `sql_update_row`, and
its arguments are the action's `plan()` parameters. A call never changes the target
system directly.

## What a tool call does

| Policy decision | Result |
|---|---|
| `auto` | The change is drift-checked and applied. The Applied record is in `_meta["io.github.sealedplan/plan-apply"]`. |
| `approve`, `two_person` | `input_required`. A person approves the plan hash out of band, for example with `sealedplan approve <hash prefix>`. The client's retry then drift-checks and applies. |
| `deny` | A tool error with the plan hash and the policy's reasons. |

If the system changed after approval, the retry returns a tool error listing the failed
preconditions, and nothing is written.

While the plan waits, a client that supports elicitation shows the person a message
saying how to approve. Answering that message is **not** an approval: the server reads
approvals only from its own store. A client without elicitation gets a state-only
`input_required` and retries on its own.

## Approval page (URL mode)

The recommended channel (SPEC §12.4): the person decides on a web page where they sign
in, not in the agent's client. Serve the page and tell the MCP server where it is:

```python
from sealedplan_mcp import create_server
from sealedplan_mcp.approval_page import approval_app


def identity(request):  # your sign-in, e.g. a header your proxy verified
    user = request.headers.get("x-verified-user")
    return Principal(id=user, issuer="https://idp.example.com", kind="human") if user else None


page = approval_app(rt, authenticate=identity, secret=PAGE_SECRET)  # a Starlette app
server = create_server(
    rt, agent=AGENT, approval_url="https://approve.example.com/plans/{plan_hash}"
)
```

A client that supports URL-mode elicitation is sent to `approval_url` for the plan.
Opening it is still not an approval. The page shows the stored, hash-verified plan as
`sealedplan show` prints it, and records the person's approve or reject in the store
with `method: "url"`. Then the client's retry applies.

- The page never decides who the person is: `authenticate` returns the approver, or
  `None` to refuse. Only `kind="human"` principals may decide.
- Forms carry a token bound to the person and the plan, keyed by `secret`. Without a
  secret, a random key is made per process; pass one when you run several replicas.
- Serve the page and the MCP server from one process: they share the runtime and lock
  around it (`runtime_lock`).
- Clients without URL mode get the out-of-band message, which names `approve_hint`.

## Explicit mode

An agent that knows the extension can ask for a plan first:

```json
"_meta": { "io.github.sealedplan/plan-apply": { "mode": "plan" } }
```

The plan comes back in `structuredContent`. To apply, call the same tool with the same
arguments and `{"mode": "apply", "plan_hash": "sha256:…"}`. The server refuses if the
arguments do not produce the stored plan's params.

## Request state

`requestState` carries the plan hash and the plan's expiry. The MCP SDK encrypts it and
binds it to the tool, the arguments and the authenticated client. By default the key
lives only as long as the process; pass
`request_state_security=RequestStateSecurity(keys=[...])` to keep pending calls across
restarts or replicas.

## Who is the agent

`agent=` is the principal recorded as the plan's agent. Pass a `Principal`, or a function
that takes the MCP request context and returns one, for example from the client's token.
