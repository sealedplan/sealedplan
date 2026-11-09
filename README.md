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

## How it works

There are three parties. Only the action touches the target system.

```
   agent                     runtime + action                    person
   ─────                     ────────────────                    ──────
1. propose(action, params) ─▶ action.plan(): read the system,
                              describe the change, change nothing
                              policy: auto, approve, two_person or deny
                              plan stored as PENDING_APPROVAL ──▶ 2. reads the plan,
                                                                     approves its hash
3. execute(plan_hash) ──────▶ re-check preconditions
                              ├─ changed since approval → DRIFTED, nothing written
                              └─ unchanged → action.apply() → APPLIED
4. compensate(plan_hash) ───▶ action.compensate(), unless someone
   (or a later step failed)   changed it since → COMPENSATED or conflict
```

- **An action** is a class that knows one kind of change on one system, for example
  "update a row" or "scale a deployment". It answers four questions: what would this
  change do (`plan`), what does the resource look like now (`observe`), make the change
  (`apply`), and undo it (`compensate`).
- **A plan** is what a person approves: before/after, preconditions such as "row
  version is still 4", blast radius, risk, and how to undo it. It is hashed, and the
  approval names that hash. A plan that changes after approval is no longer approved.
- **The runtime** decides from the plan's effect and risk whether a person must
  approve. It refuses to apply anything not approved, re-checks preconditions just
  before applying, and keeps an append-only record of every transition.
- **The person** approves with the `sealedplan` CLI. It reads the same store and shows
  the plan as it was hashed, not the agent's summary of it.

The agent and the person never talk to each other directly. They share a plan store, a
SQLite file in this runtime.

## Try it

```bash
uv sync
```

```bash
uv run python examples/sql_agent/crm_agent.py demo
```

This demo has an agent propose a change to a customer record. A person approves it with
the CLI, and the agent executes it. Then a second change drifts and is refused, and the
first change is undone. [`examples/`](examples) also has a step-by-step version for two
terminals, and an example of writing your own action.

## Using it in code

Set up a runtime and give it the actions this agent may use. Each action holds its own
allowlist: here, which table and columns.

```python
import sqlite3
from sealedplan.models import Principal
from sealedplan.providers.sql import Table, UpdateRow
from sealedplan.runtime import Runtime
from sealedplan.store import SqliteStore

AGENT = Principal(id="crm-agent", issuer="https://idp.example.com", kind="agent")
RUNTIME = Principal(id="crm-runtime", issuer="https://idp.example.com", kind="service")

rt = Runtime(SqliteStore("plans.db"), RUNTIME)
rt.register(
    UpdateRow(
        lambda: sqlite3.connect("crm.db"),
        "crm",
        {"customers": Table(key="id", version="version", columns=("tier", "credit_limit"))},
    )
)
```

The agent's tool proposes instead of acting. What it gets back is a plan and a state,
not a result:

```python
proposal = rt.propose(
    "sql.update_row",
    {"table": "customers", "key": 1, "values": {"tier": "gold"}},
    agent=AGENT,
    idempotency_key=request_id,  # of the plans sharing a key, at most one is applied
)
proposal.state  # PENDING_APPROVAL, or APPROVED if policy allows it without a person
```

A person reviews and approves it from a terminal:

```bash
sealedplan --db plans.db list
```

```bash
sealedplan --db plans.db approve <hash prefix> --as bob --issuer https://idp.example.com
```

Then the agent, or a worker, executes it:

```python
result = rt.execute(proposal.plan.plan_hash)
result.state  # APPLIED, DRIFTED (result.drift says what moved), FAILED or UNKNOWN
```

To undo, call `rt.compensate(plan_hash)`. For a multi-step run, propose each step with
`parent=Parent(run_id=..., step=n)`; if step n fails, `rt.compensate_run(run_id, n)`
undoes the earlier steps in reverse order.

A common way to wire this into an agent framework is to expose two tools:
`propose_<action>`, which returns the plan's summary and hash, and `execute_plan(hash)`,
which the agent calls once the plan is approved. The agent never gets a tool that
changes the system directly. Adapters for MCP, LangGraph and the Claude Agent SDK are
planned.

### What the outcomes mean

| State | Meaning | What to do |
|---|---|---|
| `APPLIED` | The approved change was made. | Nothing, or `compensate` to undo. |
| `DRIFTED` | A precondition no longer held. Nothing was written. | Propose again; the person sees the new values. |
| `FAILED` | The target refused the change. Nothing was written. | Read `error`; propose again if it makes sense. |
| `UNKNOWN` | The change may or may not have happened, for example after a lost connection. | `rt.reconcile(plan_hash)` asks the action to check; if it cannot tell, a person decides. |
| `COMPENSATED` | Undone. | |
| `COMPENSATION_FAILED` | Undo refused, usually because someone changed the resource after apply. | A person decides; their change is never overwritten. |

### Who must approve

The default policy looks at the plan's effect and risk. An action declares both, and
can raise the risk for a particular plan:

| Effect | low | medium | high | critical |
|---|---|---|---|---|
| `READ_ONLY` | auto | auto | auto | approve |
| `REVERSIBLE` | auto | approve | approve | two_person |
| `COMPENSATABLE` | approve | approve | two_person | two_person |
| `IRREVERSIBLE` | approve | approve | two_person | two_person |

Pass your own `policy=` to `Runtime` to change it.

## Reference actions

| Action | System | Effect | Precondition | Notes |
|---|---|---|---|---|
| `sql.update_row` ([source](python/sealedplan/src/sealedplan/providers/sql.py)) | Any DB-API 2.0 driver | REVERSIBLE | Row `version` column, enforced in the `UPDATE ... WHERE` (atomic) | Tables and columns come from an allowlist; values are bound parameters. |
| `k8s.scale_deployment` ([source](python/sealedplan/src/sealedplan/providers/k8s.py)) | Kubernetes | REVERSIBLE | Deployment `generation`, written with `resourceVersion` (atomic) | Scaling to zero is high risk. Talks to a small `KubeApi` interface; no client is bundled yet. |
| `terraform.apply` ([source](python/sealedplan/src/sealedplan/providers/terraform.py)) | Terraform CLI | IRREVERSIBLE | State `lineage/serial`, Terraform's own stale-plan check (atomic) | Approves a saved plan file by digest and applies that file. Destroy or replace is high risk, so two people approve. Sensitive values are redacted. |

For a Terraform stack:

```python
from pathlib import Path
from sealedplan.providers.terraform import ApplyPlan, CliRunner

rt.register(
    ApplyPlan(CliRunner(), stacks={"network": Path("infra/network")}, plan_dir=Path("tfplans"))
)
rt.propose("terraform.apply", {"stack": "network"}, agent=AGENT, idempotency_key=request_id)
```

To write your own action, see
[`examples/custom_action/feature_flags.py`](examples/custom_action/feature_flags.py).

## Repository

| Path | What |
|---|---|
| [`spec/SPEC.md`](spec/SPEC.md) | The contract (v0.1 draft). Usable without any of this code. |
| [`docs/prior-art.md`](docs/prior-art.md) | Related work and how this differs. |
| [`python/sealedplan`](python/sealedplan) | Reference runtime (Python 3.11+): core, SQLite store, CLI approver, reference actions. |
| [`examples/`](examples) | Runnable examples. |
| `adapters/` | MCP, LangGraph, Claude Agent SDK adapters (planned). |

Status: early draft. Expect breaking changes.

## License

Apache-2.0. See [LICENSE](LICENSE).
