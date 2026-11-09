# sealedplan

An open contract for **plan → approve → apply → compensate** on agent actions.

Agents increasingly change real systems: Kubernetes, Terraform, SQL, SaaS APIs. Most
safeguards approve a raw tool call. sealedplan instead has an action describe its own
side effects as a **plan** before it runs. The plan comes from the target system's own
dry-run and includes a diff, preconditions, blast radius and an undo strategy. The flow:

1. The approval is bound to the plan's hash.
2. Before applying, the runtime re-checks the preconditions. If the world changed since
   approval, it refuses to apply, like Terraform does with a stale saved plan.
3. If a later step fails, earlier steps are compensated.

This is **not** a new protocol and **not** a gateway. It is one protocol-neutral
contract with bindings for MCP and A2A, plus a reference runtime.

| Path | What |
|---|---|
| [`spec/SPEC.md`](spec/SPEC.md) | The contract (v0.1 draft). Usable without any of this code. |
| [`docs/prior-art.md`](docs/prior-art.md) | Related work and how this differs. |
| [`python/sealedplan`](python/sealedplan) | Reference runtime (Python 3.11+). |
| `adapters/` | MCP, LangGraph, Claude Agent SDK adapters (planned). |
| `examples/` | Demos (planned). |

Status: early draft. Expect breaking changes.

## License

Apache-2.0. See [LICENSE](LICENSE).
