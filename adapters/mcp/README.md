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
