# Prior art for sealedplan

Status: research notes, 2026-11-09. Every claim below comes from the source linked
next to it. Anything I could not confirm is marked **unverified**.

## Summary

Several projects already gate agent tool calls. Two of them come close to this
project's core ideas:

- **Undolith** has effect classes, native dry-run, undo, and its own in-repo spec.
  It does not bind an approval to a hash, and it does not re-check state between
  approval and commit.
- **CTRLRun** binds a single-use, expiring approval to a SHA-256 of the canonical
  call. It also has an opt-in `preconditions=` hook that re-checks resource state
  before execution. It has no dry-run or diff, and it says plainly that "it rolls
  nothing back."

This means "hash-bound approval" and "re-check before execute" are not new on
their own. What is still missing:

1. **The plan is what gets approved, not the call.** The hashed object is a
   structured description of the changes (diff, preconditions, blast radius),
   produced by the target system's own dry-run. Today, approvals cover call
   arguments, which say what the agent *asked for*, not what *will change*.
2. **A spec that stands apart from any runtime.** It has JSON Schemas,
   canonicalization, a state machine, and bindings to both MCP and A2A. Undolith's
   SPEC.md describes a ledger format for its own runtime. CTRLRun points to docs,
   not to a spec. I found no plan-hash approval contract from MCP or A2A, or
   anything published as an extension.
3. **Compensation is part of the approved plan.** The approver sees the undo
   strategy, and it is covered by the same hash.
4. **Preconditions declare how they are enforced.** Each one is either `atomic`
   (enforced inside the write itself: k8s `resourceVersion`, HTTP `If-Match`,
   SQL row version, Terraform saved plan) or `check_then_act`. This states the
   TOCTOU window openly. CTRLRun documents the same window ("narrows… does not
   close it") but does not let an action close it.

## Projects and specs reviewed

### Undolith (Python, MIT)

Source: [GitHub README + SPEC.md draft v0.2](https://github.com/Nulfied/undolith),
[PyPI](https://pypi.org/project/undolith/0.3.0/). Latest version 0.3.0 per a PyPI
search result. Release date is **unverified**; the PyPI page returned a bot
challenge.

- **Pipeline:** classify → policy → simulate → approve/hold → snapshot → commit → observe.
  It keeps an Ed25519-signed, hash-chained ledger in local SQLite or JSONL.
- **Risk classes:** `read < write < destructive < irreversible`. Risk comes from an
  integrator override, then the operation's own declaration, then MCP annotations,
  then a verb-name heuristic. Unknown operations default to at least `write`.
- **Verdicts:** `allow < simulate < approve < hold < deny`. Irreversible actions
  (email, payment, `git push`) are held in an outbox until someone releases them.
- **Simulate:** handled per adapter. It uses native dry-run where one exists
  (`terraform plan`, `kubectl --dry-run`, SQLite rolled-back transaction) and
  returns `simulated=false` when the effect can't be predicted.
- **Approval:** the `approved` entry carries `{by, note}`. **No hash binding** to
  the action or the simulation.
- **Drift:** snapshot taken "after approval and immediately before `run`", but
  **not compared** to anything. Undo does re-observe and raises `UndoConflict` if
  state changed since commit. After commit, it compares predicted with observed
  state and can roll back.
- **Undo:** inverse functions over whole-resource snapshots. Session rollback runs in
  reverse commit order.
- **Integrations:** LangChain, MCP client session wrapper, generic dispatch loop.

**How we differ:** we approve a hashed plan rather than recording a free-form
approval, and we re-check preconditions between approval and apply. Our spec covers
the wire objects and two protocol bindings, not a local ledger format. We use
compensation (saga) semantics instead of snapshot restore, so it scales to systems
where a whole-resource snapshot is impossible (cloud APIs, SaaS). We assume a
multi-process store and async approvers; Undolith is local-first.

**Worth borrowing:** comparing post-apply observed state with predicted state; the
undo-conflict check before compensation; "unknown defaults to stricter."

### CTRLRun (Python, Apache-2.0)

Source: [GitHub README](https://github.com/CTRLRun/ctrlrun). A search result lists
version 0.12.0 on [PyPI](https://pypi.org/project/ctrlrun/); the PyPI page itself
returned a challenge, so this is **unverified**.

- **Hash:** "a name, canonical arguments (sorted keys, no floats), a resource, the
  principal. Its SHA-256 is the action hash." Exactly which fields go into the hash
  is **not documented** in the README.
- **Approval:** "single-use, expires, and matches nothing but that exact action."
  No two-person approval. The README doesn't say how the approver's identity is
  recorded.
- **Preconditions:** opt-in. "Name a `preconditions=` provider and the approval is
  also bound to the resource state it was granted against, rechecked strictly
  before the reservation." The README admits this narrows the race window but does
  not close it.
- **No dry-run, plan or diff.** **No rollback.** Ambiguous outcomes are held until
  `ctrlrun resolve` or a `reconcile` hook settles them.
- **Policy:** YAML `ctrlrun.policy/v2`, decisions `allow | approve | deny`, default
  deny. Its `effect:` key is a string template naming the resource consequence, not
  an effect class.
- **Receipts:** JSON, hash-chained, unsigned.
- **Integrations:** LangChain middleware, LangGraph interrupt, OpenAI Agents SDK
  (attribution only), MCP gateway. **No A2A.**

**How we differ:** CTRLRun is the closest prior art for approval binding. Our
differences: the hashed object is a dry-run plan, not call arguments. We have effect
classes that drive policy defaults, plus compensation. Preconditions are required
for any non-READ_ONLY plan and can be enforced atomically. We have two-person
approval and a published wire spec with MCP and A2A bindings.

**Worth borrowing:** an explicit ambiguous/unknown outcome state with reconcile;
fail-closed on a missing policy or principal; receipts for refusals as well as
successes.

### "PreCheck Guardian"

**Not found.** Searches turned up [gateway/guardian](https://github.com/gateway/guardian)
(dependency install gating for coding agents) and *precheck* (hash-locked
acceptance checks an agent cannot edit). Neither matches the name or the problem.
Please send a link if you meant a specific project.

### LangChain `HumanInTheLoopMiddleware`

Source: [LangChain docs](https://docs.langchain.com/oss/python/langchain/human-in-the-loop),
[reference](https://reference.langchain.com/python/langchain/agents/middleware/human_in_the_loop/HumanInTheLoopMiddleware).

- `interrupt_on` maps tool name → allowed decisions (`approve`, `edit`, `reject`,
  `respond`). Resume uses a checkpointer and thread ID; decisions are keyed by
  interrupt ID.
- The reviewer sees the **raw tool call**. There's no plan, effect class, drift
  check or undo, and nothing ties the approval to a hash. `edit` changes the call
  after review, which works against binding an approval to exact content.

**How we differ:** we are a contract that this middleware can host. The LangGraph
adapter would put a Plan, not a raw call, into the interrupt payload. On resume it
would accept only an Approval whose `plan_hash` matches.

### MCP tool annotations

Source: [MCP blog, 2026-03-16 tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/),
[2026-07-28 tools page](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).

- Four boolean hints: `readOnlyHint` (default false), `destructiveHint` (default true),
  `idempotentHint` (default false), `openWorldHint` (default true). The names and
  defaults come from the blog. The 2026-07-28 tools page lists `annotations` but I
  could not see the field definitions verbatim (**partly unverified**).
- Spec: "clients **MUST** consider tool annotations to be untrusted unless they come
  from trusted servers."
- These are static per tool, not per call. No plan, no diff, no undo.

**How we differ:** our effect class is declared per tool and may be narrowed per
plan. The runtime always takes the *stricter* of the declared class and local
policy. Annotations map onto effect classes as a fallback (see SPEC §4.4).

### MCP 2026-07-28: Multi Round-Trip Requests (MRTR), elicitation, extensions

Source: [MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr),
[elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation),
[changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[extensions overview](https://modelcontextprotocol.io/docs/extensions/overview).

- `tools/call` may return `resultType: "input_required"` with `inputRequests` (map of
  `elicitation/create` / `sampling/createMessage` / `roots/list`) and/or an opaque
  `requestState`. The client retries with a **new** JSON-RPC id, `inputResponses`,
  and the echoed `requestState`.
- `requestState` is attacker-controlled. If it affects authorization it MUST be
  integrity-protected (HMAC/AEAD). Single-use MUST be enforced server-side.
- URL-mode elicitation sends a human to an external page. `accept` means only
  "consented to open"; the server finds out the result when the client retries.
  This fits an async approval page well.
- New `extensions` capability uses reverse-DNS IDs (`com.example/name`). Prefixes
  whose second label is `mcp` or `modelcontextprotocol` are reserved.
- MCP still leaves the content of the approval and its link to the action up to
  each implementation.

**How we differ:** we fill that gap. The binding specifies what the server puts in
`inputRequests` and `requestState` (a plan hash, integrity-protected) and what it
must check on retry. It also explains why a form-mode `accept` relayed by the
agent's own client is not a human approval.

### A2A v1.0 extensions and `TASK_STATE_INPUT_REQUIRED`

Source: [A2A specification 1.0.0](https://a2a-protocol.org/latest/specification/),
[extensions topic](https://a2a-protocol.org/latest/topics/extensions/).

- `AgentCard.capabilities.extensions[]` = `{uri, description, required, params}`.
  Clients activate an extension with the `A2A-Extensions` header. A required
  extension the client didn't declare → `ExtensionSupportRequiredError` (-32008).
- Extension kinds: data-only, profile, method, state-machine. Custom fields go in
  `metadata` keyed by extension URI. Extensions should reuse existing enum values.
- `TASK_STATE_INPUT_REQUIRED` is an interrupted state. The client resumes with a
  message on the same `taskId`/`contextId`. The spec does **not** define what goes
  into the pause.
- Unified `Part` with `data` + `mediaType` carries structured JSON.

**How we differ:** we define a profile extension that types the pause (a Plan
`data` part) and the resume (an Approval `data` part bound to `plan_hash`). It also
maps drift and rejection onto existing task states.

### Gateways: Cordon, hoop.dev

Source: [Cordon](https://glama.ai/mcp/servers/marras0914/cordon),
[hoop.dev MCP approval blog](https://hoop.dev/blog/human-in-the-loop-approval-in-mcp-gateways-explained/)
(vendor material, claims **unverified**).

- Per-tool allow / block / approve rules. The gateway holds the request until a
  reviewer approves; hoop.dev ties this to OIDC groups and approval time-outs.
- The approval covers a held raw request. No dry-run, plan, drift check or undo.

**How we differ:** we are not a gateway. A gateway could carry our contract
(`adapters/mcp` is one such wrapper). The difference is the approved object and the
re-check before apply.

### Other community projects found

- [mcp-approvals](https://github.com/marklynd/mcp-approvals): MCP approval gate
  with a hash-chained audit log.
- [drift](https://mcpservers.org/servers/mrpkk/drift): checks actions against a
  signed mandate (permit / deny / escalate).
- Several small repos bind an approval to a payload hash plus an expiry.

None of them define a plan object or a cross-protocol spec.

### Non-agent precedents we copy on purpose

- **Terraform saved plans:** `terraform apply planfile` refuses if state changed since
  the plan ("Saved plan is stale"). Our drift guard copies this behaviour.
- **Kubernetes server-side dry-run + `resourceVersion`:** a native dry-run, plus an
  optimistic-concurrency token that makes a precondition atomic.
- **HTTP conditional requests (`If-Match`, RFC 9110 §13):** the same pattern for
  generic APIs.
- **Sagas (Garcia-Molina & Salem, 1987):** compensating transactions for steps that
  can't be undone exactly.

## How we differ

| | Approved object | Plan / diff from native dry-run | Approval bound to hash | Re-check before apply | Atomic precondition | Undo / compensation | Async approval, persisted | Two-person | Standalone spec | MCP binding | A2A binding |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Undolith | the call | yes (per adapter) | no | no (only before undo) | no | snapshot undo, session rollback | hold/release, local SQLite | no | in-repo, ledger-centric | client wrapper | no |
| CTRLRun | the call | no | yes (call hash) | opt-in | no (documented gap) | no ("rolls nothing back") | yes | no | no (docs) | gateway | no |
| LangChain HITL | the call | no | no (interrupt ID) | no | no | no | via checkpointer | no | no | n/a | no |
| MCP annotations | n/a | no | n/a | no | no | no | n/a | n/a | yes (hints only) | native | n/a |
| MCP MRTR / elicitation | left to implementer | no | no | no | no | no | yes (URL mode + retry) | no | yes (transport only) | native | n/a |
| A2A input-required | left to implementer | no | no | no | no | no | yes (task pause) | no | yes (state only) | n/a | native |
| Cordon / hoop.dev | held request | no | no | no | no | no | yes | unverified | no | gateway | no |
| **sealedplan** | **the plan** | **yes, required for non-read** | **yes (`plan_hash`, RFC 8785)** | **required** | **declared per precondition** | **compensation in the approved plan** | **yes, store + URL/webhook/CLI** | **yes** | **yes (SPEC; schemas pending)** | **yes (extension + MRTR)** | **yes (profile extension)** |

## Risks to the positioning

- CTRLRun could add dry-run and diff. Our lasting difference is the published contract
  and the bindings, not the runtime. That argues for putting SPEC quality ahead of
  runtime features.
- A plan only means something if the provider can be trusted. A malicious MCP server
  can return a harmless plan and then do something else. The spec can't prevent this.
  It can make it detectable (post-apply observation) and clarify where trust sits
  (SPEC §11).
- MCP's extension process could produce an official approvals extension. We should
  track the MCP extensions repo and be ready to propose ours there instead of
  competing with it.
