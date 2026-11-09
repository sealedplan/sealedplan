# sealedplan: Plan/Apply Contract for Agent Actions — v0.1 (draft)

Status: **draft for review**. Not stable.

Protocol identifiers in this draft (§12, §13, §14) assume a GitHub organization named
`sealedplan`. They change if the project moves to a domain of its own (Q1). Hosts under
`example.invalid` are illustrations only.

## 1. Introduction

Agents now take actions that change real systems. Most safeguards today approve a
*raw tool call*. A raw call says what the agent asked for; it does not say what will
change, whether the world still matches what the reviewer saw, or how to undo it.

This document defines a protocol-neutral contract in which an **action** describes its
own side effects before it runs:

```
plan ──► policy ──► approval(plan_hash) ──► precondition re-check ──► apply ──► record
                                                                         │
                                                       later step fails ─┴─► compensate
```

The contract has four parts: effect classes (§4), wire objects with JSON Schemas (§5),
a hash over the plan that approvals bind to (§6), and a state machine with drift
semantics (§7–§8). Bindings for MCP (§12) and A2A (§13) carry the same objects over
each protocol. This spec can be implemented without using this project's code.

### 1.1 Goals

- One object, the **Plan**, that a human or a policy can judge, and that the action
  must keep to.
- Approvals that cannot be reused for a different plan, a later state of the world,
  or after their expiry.
- Undo semantics that are declared up front and covered by the approval.
- The same objects over MCP, A2A, and in-process frameworks.

### 1.2 Non-goals

- A new transport or protocol. A gateway product. A policy language (§10 defines
  inputs and outputs, not syntax).
- Proving that a provider is honest. A malicious provider can produce a harmless plan
  and then do something else. §11 says what can be detected and where trust sits.
- Prompt-injection detection.

### 1.3 Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

JSON Schemas will live in `schemas/` (JSON Schema 2020-12) and will be normative once
written. Where prose and schema disagree, report it as a bug; until fixed, the prose
wins.

## 2. Terminology

| Term | Meaning |
|---|---|
| **Action** | A named, versioned operation that can change a target system, such as `k8s.scale_deployment`. |
| **Provider** | The code that implements an action's `plan`, `apply`, and optionally `compensate`. It can live in the runtime's process or be a remote MCP server or A2A agent. |
| **Runtime** | The component that enforces this contract: it runs policy, stores records, collects approvals, re-checks preconditions, and calls the provider. |
| **Plan** | An immutable description of what `apply` will do (§5.2). Producing a plan MUST NOT change the target system. |
| **Plan hash** | SHA-256 over the canonical form of a plan (§6). It is the plan's identity. |
| **Approval** | A decision by a human (or a trusted automated approver) bound to one plan hash (§5.3). |
| **Applied** | The record of one apply attempt (§5.4). |
| **Agent** | The software principal that requested the action. |
| **Sponsor** | The human accountable for the agent's request. It can differ from the approver. |
| **Drift** | A precondition in the plan no longer holds at apply time (§8). |

## 3. Roles and trust

| Role | Trusted for | Not trusted for |
|---|---|---|
| Runtime | enforcement, records, identity checks | — |
| In-process provider | plan accuracy, apply, compensate | — |
| Remote provider (MCP server, A2A agent) | nothing by default | effect class, plan accuracy, honest apply |
| Agent | — | approvals, policy decisions, its own effect claims |
| Approver | the decision it signs | anything outside the plan it saw |

A runtime MUST NOT accept an approval from the agent whose action it gates. A runtime
SHOULD treat everything a remote provider declares as a claim to check, not as fact
(§11.1).

## 4. Effect classes

### 4.1 Classes

Each action declares the **most severe** effect it can have. Each plan declares the
effect of *that* call, which MUST NOT be more severe than the action's declaration.

| Class | Meaning | Must provide | Example |
|---|---|---|---|
| `READ_ONLY` | No change to any system outside the runtime's own records. | `plan` MAY be skipped | `kubectl get` |
| `REVERSIBLE` | `compensate` restores the exact state the preconditions describe. | `compensate` | scale replicas 3→5; compensate 5→3 |
| `COMPENSATABLE` | `compensate` undoes the meaning of the change but not the exact state. | `compensate` | create user → disable user; charge → refund |
| `IRREVERSIBLE` | No compensation exists. | — | send email, drop table without backup, publish |

Severity order: `READ_ONLY < REVERSIBLE < COMPENSATABLE < IRREVERSIBLE`.

### 4.2 Rules

1. If an action declares no effect class, the runtime MUST treat it as `IRREVERSIBLE`.
2. Effective class = the most severe of: the action's declaration, the plan's
   declaration, and any local override set by the runtime operator. A local override
   MAY raise the class; it MUST NOT lower it below the plan's own declaration.
3. A plan whose effect is `REVERSIBLE` or `COMPENSATABLE` MUST include a `compensation`
   section (§5.2.5). Without one, the runtime MUST treat the plan as `IRREVERSIBLE`.
4. An action MUST NOT declare `READ_ONLY` if `apply` writes anything outside the
   runtime's records. A runtime that observes a write from a `READ_ONLY` action
   (§8.5) MUST record a `deviation` event.

### 4.3 Why per plan

The same action can have different effects depending on its arguments: scaling a
deployment to zero is riskier than scaling it from 3 to 4; `DELETE … WHERE id = 7` is
not `TRUNCATE`. The action's class is the worst case; the plan's class is this case.

### 4.4 Mapping from MCP tool annotations

When a remote MCP tool declares no effect class but has annotations, a runtime MAY
derive one. It MUST use this table and MUST NOT derive anything less severe:

| `readOnlyHint` | `destructiveHint` | Derived class |
|---|---|---|
| true | any | `READ_ONLY` only if the server is trusted (§3); otherwise `REVERSIBLE`, which still requires a plan |
| false or absent | false | `COMPENSATABLE` |
| false or absent | true or absent | `IRREVERSIBLE` |

`idempotentHint` and `openWorldHint` do not change the class. `openWorldHint: true`
SHOULD raise the default risk by one level (§5.2.4).

## 5. Objects

All objects are JSON. All objects carry `spec_version: "0.1"`. Timestamps are RFC 3339
in UTC with a `Z` suffix and whole seconds (`2026-11-09T14:03:00Z`). Identifiers are
strings. Optional fields that have no value MUST be omitted, not set to `null`.

Fields not defined by this spec MUST be placed under `extensions`, keyed by a
reverse-DNS or URI identifier. Receivers MUST ignore extension keys they do not
understand. `extensions` is still part of the plan hash (§6).

### 5.1 Principal

Who is involved. Used in plans, approvals, and records.

```json
{ "id": "agent:incident-bot", "issuer": "https://idp.example.invalid", "kind": "agent" }
```

`kind` is one of `agent`, `human`, `service`. `issuer` names the identity provider
that vouches for `id`. Two principals are the same only if both `id` and `issuer`
match; a runtime MUST NOT compare principals by `id` alone.

### 5.2 Plan

```json
{
  "spec_version": "0.1",
  "action": { "name": "k8s.scale_deployment", "version": "1.0.0", "provider": "sealedplan-k8s" },
  "params": { "namespace": "shop", "name": "checkout", "replicas": 6 },
  "effect": "REVERSIBLE",
  "risk": { "level": "medium", "reasons": ["production namespace"] },
  "summary": "Scale shop/checkout from 3 to 6 replicas",
  "changes": [
    {
      "resource": { "type": "apps/v1/Deployment", "id": "k8s://prod-cluster/shop/checkout" },
      "op": "update",
      "before": { "spec": { "replicas": 3 } },
      "after":  { "spec": { "replicas": 6 } }
    }
  ],
  "preconditions": [
    {
      "id": "deploy-version",
      "resource": { "type": "apps/v1/Deployment", "id": "k8s://prod-cluster/shop/checkout" },
      "kind": "version",
      "expect": "48213977",
      "enforcement": "atomic"
    }
  ],
  "blast_radius": { "resources": 1, "scopes": ["k8s://prod-cluster/shop"] },
  "compensation": {
    "strategy": "restore",
    "summary": "Scale shop/checkout back to 3 replicas",
    "params": { "namespace": "shop", "name": "checkout", "replicas": 3 }
  },
  "idempotency_key": "incident-4711-scale-checkout",
  "principal": {
    "agent":   { "id": "agent:incident-bot", "issuer": "https://idp.example.invalid", "kind": "agent" },
    "sponsor": { "id": "alice", "issuer": "https://idp.example.invalid", "kind": "human" }
  },
  "evidence": [
    { "kind": "k8s.server-dry-run", "media_type": "application/json", "digest": "sha256:9f2c…" }
  ],
  "created_at": "2026-11-09T14:03:00Z",
  "expires_at": "2026-11-09T14:33:00Z",
  "plan_hash": "sha256:4be1…"
}
```

#### 5.2.1 Required fields

`spec_version`, `action`, `params`, `effect`, `risk`, `summary`, `changes`,
`preconditions`, `idempotency_key`, `principal`, `created_at`, `expires_at`,
`plan_hash`.

`preconditions` MAY be empty only when `effect` is `READ_ONLY`. In every other case at
least one precondition is REQUIRED, because a plan without one cannot detect drift. A
plan that only creates resources satisfies this with an `absent` precondition per
created resource.

#### 5.2.2 `changes`

A list of resource-level changes. Each entry has:

- `resource`: `{type, id}`. `id` SHOULD be a URI that names the system and the object.
- `op`: `create | update | delete | invoke`. `invoke` covers calls whose effect is not
  a state change on a named resource (send a message, trigger a job).
- `before`, `after`: OPTIONAL partial state projections. They SHOULD contain only the
  fields that change, plus enough context for a human to recognise the object.
- `patch`: OPTIONAL RFC 6902 JSON Patch from `before` to `after`.
- `sensitive`: OPTIONAL list of JSON Pointers into `before`/`after` whose values have
  been replaced by references or keyed digests (§11.6).

`changes` describes intent at plan time. It is not a promise about values the target
system computes (generated IDs, timestamps). Those belong in the Applied record.

#### 5.2.3 `preconditions`

Each precondition names one observable fact that MUST still be true at apply time:

| `kind` | `expect` | Holds when |
|---|---|---|
| `version` | opaque string | the resource's version token equals `expect` (k8s `resourceVersion`, HTTP `ETag`, Terraform state `serial` + `lineage`, SQL row version) |
| `fingerprint` | `sha256:<hex>` | SHA-256 of the canonical (§6) projection named by `select` equals `expect` |
| `exists` | — | the resource exists |
| `absent` | — | the resource does not exist |

Fields: `id` (unique within the plan), `resource`, `kind`, `expect` (where the kind
uses it), `select` (for `fingerprint`: a list of JSON Pointers into the resource's
state; the projection is an object mapping pointer → value), and `enforcement`:

- `atomic`: the provider passes the precondition into the write itself, so the target
  system rejects the write if the precondition fails (`resourceVersion`, `If-Match`,
  `UPDATE … WHERE version = $1`, a Terraform saved plan). No race window.
- `check_then_act`: the runtime re-checks just before `apply`. A window remains between
  the check and the write. §8.3 bounds it.

Providers SHOULD use `atomic` whenever the target system supports it.

#### 5.2.4 `risk`

`level` is `low | medium | high | critical`. `reasons` is a list of short strings for
humans. Risk is the provider's claim; policy MAY raise it (§10).

#### 5.2.5 `compensation`

REQUIRED when `effect` is `REVERSIBLE` or `COMPENSATABLE`. MUST be absent when
`IRREVERSIBLE`.

- `strategy`: `restore` (REVERSIBLE only: return to the precondition state) or
  `semantic` (an opposing business operation).
- `summary`: what compensation will do, for humans.
- `params`: OPTIONAL. The compensation input, as far as it is known at plan time.
- `preconditions`: OPTIONAL. What must hold for compensation to run automatically.
  When absent, the runtime uses the post-apply observation (§9.3).

Because `compensation` is part of the hash, an approval covers both the change and its
undo. The approver sees exactly what will happen if a later step fails.

#### 5.2.6 Other fields

- `blast_radius`: `{resources, scopes, estimate?, notes?}`. `resources` is the count of
  distinct resources in `changes`, or an upper bound when the provider cannot enumerate
  them (`estimate: true`).
- `idempotency_key`: unique per logical request (§9.1).
- `evidence`: OPTIONAL list of native dry-run outputs, by digest. The runtime MAY store
  raw output and serve it by digest; only the digest is hashed.
- `expires_at`: MUST be after `created_at`. Providers SHOULD keep plans short-lived
  (RECOMMENDED default: 30 minutes). An expired plan cannot be approved or applied.
- `summary`: a short human sentence. It is part of the hash but is the provider's
  words; approval UIs MUST also render `changes` (§11.5).
- `parent`: OPTIONAL `{run_id, step}` linking the plan to a multi-step run (§9.2).

### 5.3 Approval

```json
{
  "spec_version": "0.1",
  "approval_id": "appr-0001",
  "plan_hash": "sha256:4be1…",
  "decision": "approve",
  "approver": { "id": "bob", "issuer": "https://idp.example.invalid", "kind": "human" },
  "method": "url",
  "scope": { "uses": 1 },
  "comment": "Traffic spike confirmed",
  "issued_at": "2026-11-09T14:06:12Z",
  "expires_at": "2026-11-09T14:21:12Z",
  "signature": { "alg": "EdDSA", "kid": "bob-2026", "value": "…" }
}
```

Rules:

1. `plan_hash` MUST equal the hash of the plan being applied. An approval for one hash
   means nothing for any other hash.
2. `decision` is `approve` or `reject`. A `reject` is final for that plan.
3. `expires_at` MUST NOT be later than the plan's `expires_at`. If it is, the runtime
   MUST cap it.
4. `scope.uses` is the number of successful applies the approval allows. In v0.1 it
   MUST be `1`.
5. `scope.apply_by`, when present, lists the principals allowed to apply. When absent,
   only the plan's `principal.agent` may apply.
6. `approver` MUST NOT be the plan's `principal.agent`.
7. `method` records how the approval was collected: `cli | url | webhook | chat |
   signed | policy`. `policy` is used only for runtime-recorded `auto` decisions (§10).
8. `signature` is OPTIONAL when the runtime collected the approval itself over an
   authenticated channel. It is REQUIRED when the approval arrives through a party the
   runtime does not trust (an MCP client or A2A client: §12.4, §13.4). It is a detached
   JWS (RFC 7515) over the canonical approval with `signature` removed.

### 5.4 Applied

Fields: `spec_version`, `applied_id`, `plan_hash`, `approval_ids`, `outcome`
(`succeeded | failed | unknown`), `started_at`, `finished_at`, `principal` (who actually
applied), and optionally `observed` (post-apply state projections per resource, used for
deviation detection and as compensation preconditions), `result` (provider output),
`compensation_handle` (opaque data the provider needs to compensate, such as a
generated ID), and `error` (when `failed` or `unknown`).

`unknown` means the runtime cannot tell whether the change happened, for example after
a timeout once the request was sent. It is not a failure; see §7.3.

### 5.5 Compensated

Fields: `spec_version`, `compensation_id`, `applied_id`, `plan_hash`, `reason`
(`step_failed | manual | policy`), `outcome` (`succeeded | failed | skipped | conflict |
unknown`), `started_at`, `finished_at`, and optionally `trigger` (`{run_id,
failed_step}`) and `error`.

### 5.6 Event

Every state transition (§7) is recorded as an event:
`{event_id, plan_hash, from, to, at, actor, detail?, prev?}`. `actor` is a Principal.
Runtimes SHOULD set `prev` to the previous event's hash, which makes alteration of the
log detectable.

## 6. Hashing and canonicalization

### 6.1 Algorithm

```
plan_hash = "sha256:" + lowercase_hex( SHA-256( JCS( plan without "plan_hash" ) ) )
```

- JCS is the JSON Canonicalization Scheme, RFC 8785.
- Everything in the plan except `plan_hash` is hashed, including `summary`,
  `extensions`, `evidence`, `principal`, and timestamps.
- A receiver MUST recompute the hash and MUST reject a plan whose `plan_hash` does not
  match.

### 6.2 Value restrictions

These avoid cross-language differences that JCS alone does not settle:

1. **Numbers** MUST be integers in the range −(2⁵³−1) … 2⁵³−1. Non-integers, larger
   integers, and decimals MUST be encoded as strings (`"0.25"`,
   `"18446744073709551615"`). A producer MUST reject a plan containing a non-integer
   number.
2. **Strings** MUST be valid Unicode. Producers SHOULD normalize to NFC before hashing.
   Receivers MUST NOT normalize before verifying; the hash covers the bytes as sent.
3. **Absent vs null.** Optional fields with no value are omitted (§5). `null` MAY appear
   inside `params`, `before`, `after`, and `extensions`, and is hashed as `null`.
4. **Timestamps** use the exact format in §5.
5. **Duplicate object keys** MUST be rejected when parsing.

### 6.3 Other hashes

`fingerprint` preconditions and `evidence` digests use the same `sha256:<hex>`
encoding. Fingerprints are computed over the JCS form of the projection object.
Approval signatures (§5.3) are computed over the JCS form of the approval.

### 6.4 Test vectors

`schemas/test-vectors/` will hold plans and their expected hashes. Implementations
MUST pass them. They will be produced by the reference implementation and checked
against at least one independent JCS implementation.

## 7. State machine

### 7.1 States

```
PLANNED ──policy: deny──────────────────────► DENIED            (terminal)
   │
   ├──policy: approve / two_person──► PENDING_APPROVAL
   │                                     ├──reject──────────► REJECTED          (terminal)
   │                                     ├──expiry──────────► EXPIRED           (terminal)
   │                                     ▼
   └──policy: auto─────────────────► APPROVED
                                         ├──precondition fails──► DRIFTED      (terminal; re-plan)
                                         ├──expiry──────────────► EXPIRED      (terminal)
                                         ▼
                                     APPLYING
                                         ├──► FAILED                            (terminal)
                                         ├──► UNKNOWN ──reconcile──► APPLIED | FAILED
                                         ▼
                                     APPLIED ──► COMPENSATING ──► COMPENSATED          (terminal)
                                                              └──► COMPENSATION_FAILED (terminal; human)
```

APPLIED is final unless compensation is triggered.

### 7.2 Transition rules

| From | To | Allowed when |
|---|---|---|
| PLANNED | APPROVED | policy decision `auto` (§10); the runtime records a `policy` approval |
| PLANNED | PENDING_APPROVAL | policy decision `approve` or `two_person` |
| PLANNED | DENIED | policy decision `deny` |
| PENDING_APPROVAL | APPROVED | enough valid approvals for the decision (§10.2) |
| PENDING_APPROVAL | REJECTED | any valid `reject` |
| PENDING_APPROVAL, APPROVED | EXPIRED | now ≥ plan `expires_at`, or every approval has expired |
| APPROVED | DRIFTED | any precondition fails on re-check (§8) |
| APPROVED | APPLYING | approvals valid, unexpired, unused; all preconditions hold |
| APPLYING | APPLIED, FAILED, UNKNOWN | provider result |
| UNKNOWN | APPLIED, FAILED | reconcile (§7.3) |
| APPLIED | COMPENSATING | compensation triggered (§9.3) |
| COMPENSATING | COMPENSATED, COMPENSATION_FAILED | provider result or conflict |

Any transition not in this table MUST be refused.

A transition MUST be persisted before the side effect that follows it: APPLYING is
written before `apply` is called, and COMPENSATING before `compensate`. A runtime that
restarts and finds a plan in APPLYING or COMPENSATING MUST move it to UNKNOWN and
reconcile. It MUST NOT call `apply` again blindly.

### 7.3 Reconcile

A provider MAY implement `reconcile(plan, applied?) → APPLIED | FAILED | UNKNOWN`, which
inspects the target system. Without it, a human resolves UNKNOWN. While a plan is in
UNKNOWN, neither that plan nor any other plan with the same `idempotency_key` may be
applied.

### 7.4 Persistence and async approval

Plans, approvals, and events MUST be stored durably before the runtime tells the agent
a plan is pending. Approval MAY arrive minutes later through a different channel (CLI,
webhook, URL) and MAY reach a different runtime instance. Any instance with access to
the store MUST be able to continue the plan.

## 8. Drift

### 8.1 When

After validating approvals and immediately before the APPLYING transition, the runtime
MUST evaluate every precondition. If any fails, the plan moves to DRIFTED and `apply`
MUST NOT be called.

### 8.2 What the agent gets back

A DRIFTED result MUST include the failed precondition IDs and the observed values or
fingerprints, so the agent can re-plan. A re-plan is a new plan with a new hash and
needs a new approval. Runtimes MUST NOT carry approvals across plans, even when the new
plan looks the same.

### 8.3 Check-then-act window

For `check_then_act` preconditions, the runtime MUST NOT perform other I/O for that
plan between the check and the call to `apply`, and providers SHOULD write as soon as
they are called. A plan is only as strong as its weakest precondition; approval UIs
SHOULD show which preconditions are not atomic.

### 8.4 Atomic preconditions

For `atomic` preconditions the runtime still checks them first, to fail early with a
clear error, and the provider MUST also pass them to the target system. If the target
system rejects the write because a precondition failed, the runtime MUST record
DRIFTED, not FAILED.

### 8.5 Post-apply deviation

After APPLIED, a runtime SHOULD observe the changed resources and compare them with
`changes[].after`. A mismatch on a field the plan said would change, or a change to a
resource the plan did not list, is recorded as a `deviation` event. Policy decides
whether a deviation triggers compensation. The default is to alert and not compensate.

## 9. Idempotency, runs, and compensation

### 9.1 Idempotency

The runtime MUST enforce at most one successful apply per `(action.name,
idempotency_key)`. Providers SHOULD pass the key to the target system when it accepts
one.

### 9.2 Runs

A **run** is an ordered list of plans executed as one unit, such as a remediation with
several steps. Each step has its own plan, hash, and approval. An approval UI MAY show
the steps together. v0.1 does not define a run-level hash (open question Q4).

### 9.3 Compensation

When step *k* of a run ends in FAILED, DRIFTED, or EXPIRED, the runtime MUST compensate
every earlier step that is APPLIED and has a `compensation` section, in reverse order.

Before calling `compensate` automatically, the runtime MUST check that each resource is
still in the state the step left it in: the compensation `preconditions` if present,
otherwise the Applied `observed` state. If it is not, the runtime MUST NOT compensate
automatically. It records COMPENSATION_FAILED with outcome `conflict` and escalates to a
human. This stops compensation from overwriting someone else's later change.

Compensation needs no new approval when it matches the approved plan's `compensation`
section. If the provider needs to compensate differently, it MUST produce a new plan,
which goes through policy like any other.

A step in UNKNOWN blocks compensation of earlier steps until it is reconciled.
IRREVERSIBLE steps are not compensated and are recorded as `skipped`.

## 10. Policy

### 10.1 Interface

Policy is evaluated per plan. This spec defines its interface, not its language.

- Input: the plan (with the effective effect class from §4.2), and runtime context
  (environment labels, time, run membership).
- Output: `{decision, reasons, policy_digest}`, where `decision` is
  `auto | approve | two_person | deny` and `policy_digest` identifies the policy version
  that decided (`sha256:` over the policy source).

The decision and digest are recorded as an event.

### 10.2 Decisions

| Decision | Required before APPROVED |
|---|---|
| `auto` | nothing; the runtime records an approval with `method: policy` |
| `approve` | one valid `approve` from an authorized approver |
| `two_person` | two valid `approve`s from distinct approvers, at most one of them the sponsor |
| `deny` | — (terminal) |

Distinct means different `(id, issuer)` pairs (§5.1).

### 10.3 Defaults

A runtime with no configured policy MUST behave as if it had this one:

| Effective class | low | medium | high | critical |
|---|---|---|---|---|
| READ_ONLY | auto | auto | auto | approve |
| REVERSIBLE | auto | approve | approve | two_person |
| COMPENSATABLE | approve | approve | two_person | two_person |
| IRREVERSIBLE | approve | approve | two_person | two_person |

Rules that hold under any policy:

1. A policy MUST NOT return `auto` for `IRREVERSIBLE`.
2. A missing policy, an error while evaluating policy, or a missing principal means
   `deny`.
3. Policy MAY raise risk or effect. It MUST NOT lower the provider's stated risk or
   effect.

## 11. Security considerations

### 11.1 Untrusted providers

A remote provider controls both its plan and its apply. Nothing in this contract stops
it from describing one change and making another. Mitigations, strongest first:

1. Run providers for sensitive systems inside the runtime as trusted code, and expose
   them over MCP or A2A only as a front, not as the place where the side effect happens.
2. Have the runtime check preconditions itself where it can reach the target system,
   instead of asking the provider.
3. Observe after apply and record deviations (§8.5).
4. Never take a remote `READ_ONLY` claim as fact (§4.4).

### 11.2 Replay

- Approvals are bound to `plan_hash`, single-use (`scope.uses: 1`), and expiring.
- The runtime records an approval's use atomically with the APPLYING transition, so two
  concurrent applies cannot share one approval.
- `idempotency_key` stops the same logical request from being applied twice through two
  different plans.
- Protocol state that round-trips through a client (MCP `requestState`) is
  integrity-protected and checked by the server (§12.3).

### 11.3 TOCTOU

The world can change between approval and apply; the drift guard (§8) catches this. It
can also change between the check and the write. `atomic` preconditions close that
window, and `check_then_act` preconditions make it visible (§8.3).

### 11.4 Self-approval and approval laundering

- The agent MUST NOT approve its own plans (§5.3 rule 6).
- An approval relayed by the agent's own client (an MCP form-mode elicitation answered
  in the agent host, or an A2A message from the calling agent) is only as trustworthy as
  that client. Such approvals MUST be signed by an approver key the runtime trusts, or
  the runtime MUST collect the approval itself out-of-band (URL, CLI, webhook): §12.4,
  §13.4.

### 11.5 Approval UI integrity

`summary` and `risk.reasons` are the provider's words. They may be misleading or carry
prompt-injection text aimed at an LLM-assisted reviewer. Approval UIs MUST render
`changes`, `preconditions` (marking non-atomic ones), `effect`, `compensation`, and
`blast_radius` from the hashed plan, and SHOULD show a prefix of `plan_hash`. An
approval UI MUST NOT render a plan whose hash does not verify.

### 11.6 Secrets in plans

Plans are stored, shown to people, and sent across protocols, so they MUST NOT contain
secret values. A field that holds a secret MUST be replaced by a reference
(`{"$ref": "secret://…"}`) or by a keyed digest (`{"$digest": "hmac-sha256:<hex>"}`)
computed with a key the runtime holds, and listed in the change's `sensitive` pointers.
A plain SHA-256 of a low-entropy secret can be brute-forced and MUST NOT be used.

### 11.7 Store integrity

Anyone who can write to the store can forge approvals. Stores MUST be access-controlled
so that agents cannot write approvals. Signed approvals (§5.3 rule 8) and chained
events (§5.6) make tampering detectable; they do not prevent it.

### 11.8 Clocks

Expiry checks use the runtime's clock. Runtimes SHOULD allow no more than 60 seconds of
skew on timestamps that come from other parties.

### 11.9 Denial of service

An agent can flood approvers with plans. Runtimes SHOULD rate-limit pending plans per
agent and per sponsor.

## 12. MCP binding (MCP 2026-07-28)

### 12.1 Declaring support

A server that implements this contract declares the extension in its `server/discover`
capabilities. Per-tool declarations go in the extension's own tool map. This works
whether or not `Tool` carries `_meta` in this MCP revision, which is unverified (Q7):

```json
"capabilities": {
  "extensions": {
    "io.github.sealedplan/plan-apply": {
      "spec_version": "0.1",
      "approval_modes": ["url", "explicit"],
      "tools": {
        "scale_deployment": { "effect": "REVERSIBLE", "risk": "medium", "plan_ttl_seconds": 1800 }
      }
    }
  }
}
```

Servers SHOULD also set the standard tool annotations to match the effect class, so
clients that don't know this extension still get the right hint.

### 12.2 Transparent mode (agent unaware)

The agent calls `tools/call` as usual. The server, or a proxy wrapping it, builds a plan
and runs policy.

- **`auto`:** the server applies and returns `resultType: "complete"`. The Applied
  record goes in the result's `_meta["io.github.sealedplan/plan-apply"]`.
- **`deny`:** the server returns a tool error result (`isError: true`) whose `_meta`
  carries the plan hash and the decision reasons.
- **`approve` / `two_person`:** the server stores the plan and returns:

```json
{
  "resultType": "input_required",
  "inputRequests": {
    "approval": {
      "method": "elicitation/create",
      "params": {
        "mode": "url",
        "message": "Approval needed: Scale shop/checkout from 3 to 6 replicas (plan 4be1…)",
        "url": "https://approvals.example.invalid/p/4be1…"
      }
    }
  },
  "requestState": "<integrity-protected, see 12.3>",
  "_meta": { "io.github.sealedplan/plan-apply": { "plan": { "...": "full Plan object" } } }
}
```

When the client retries, the server verifies `requestState`, loads the plan, and looks
up approvals **in its own store**. If the plan is not yet approved, the server returns
another `input_required`. It MAY send only `requestState` without `inputRequests`, so
the client can retry later without prompting the user again. If the plan is approved,
the server runs the drift check and applies. A DRIFTED plan comes back as a tool error
result listing the failed preconditions.

### 12.3 `requestState`

MCP requires servers to treat `requestState` as attacker-controlled. In this binding it
MUST be integrity-protected (HMAC or AEAD) and MUST contain at least: `plan_hash`, the
authenticated client principal, an expiry no later than the plan's, and a digest of the
original `tools/call` name and arguments. On retry, the server MUST reject state that
fails verification, belongs to a different principal, has expired, or whose digest does
not match the retried call. Single use comes from the approval and apply records
(§11.2), not from `requestState`.

### 12.4 Approval channels

- **URL mode (RECOMMENDED):** the approver authenticates on the server's approval page.
  An `accept` in `inputResponses` means only that the user agreed to open the URL. It is
  never an approval.
- **Form mode:** the answer passes through the MCP client, which is the agent host being
  gated. A form-mode `accept` MUST NOT count as an approval unless the server is
  configured to trust that client as a human-facing UI *and* the client's authenticated
  session establishes who the approver is. Form mode MUST NOT be used for `two_person`.
- **Out-of-band (CLI, webhook, chat):** the server's own approver collects the decision.
  The MCP retry only picks up the result.

### 12.5 Explicit mode (agent aware)

An agent that understands the extension can ask for a plan without applying:

```json
{ "method": "tools/call",
  "params": { "name": "scale_deployment", "arguments": { "...": "..." },
              "_meta": { "io.github.sealedplan/plan-apply": { "mode": "plan" } } } }
```

The server returns `resultType: "complete"` with the Plan in `structuredContent` and in
`_meta`. To apply, the agent calls the same tool with the same arguments and
`"_meta": { "io.github.sealedplan/plan-apply": { "mode": "apply", "plan_hash": "sha256:…" } }`.
The server MUST check that the arguments produce the same `params` as the stored plan,
then continues as in §12.2 from the policy step.

### 12.6 Clients that don't support the extension

The extension changes no core semantics. A client that ignores it sees ordinary
`input_required` URL elicitations and ordinary results. Servers MUST NOT require the
extension from clients.

## 13. A2A binding (A2A 1.0.0)

### 13.1 Declaring support

```json
"capabilities": {
  "extensions": [
    {
      "uri": "https://github.com/sealedplan/spec/ext/a2a/v0.1",
      "description": "Typed plan and approval for side-effecting tasks",
      "required": false,
      "params": { "spec_version": "0.1", "approval_modes": ["signed", "url"] }
    }
  ]
}
```

This is a **profile** extension. It adds no methods and no task states. Clients activate
it with the `A2A-Extensions` request header. An agent MAY set `required: true` if it
will not perform side-effecting tasks without the extension; it then returns
`ExtensionSupportRequiredError` to clients that don't activate it.

### 13.2 Media types

| Object | `mediaType` |
|---|---|
| Plan | `application/vnd.sealedplan.plan+json` |
| Approval | `application/vnd.sealedplan.approval+json` |
| Applied | `application/vnd.sealedplan.applied+json` |
| Compensated | `application/vnd.sealedplan.compensated+json` |

Objects travel as `Part` values with `data` set to the object and `mediaType` set as
above.

### 13.3 Flow

Metadata below is stored under the key `https://github.com/sealedplan/spec/ext/a2a/v0.1`.

1. **Approval needed:** the agent moves the task to `TASK_STATE_INPUT_REQUIRED`. The
   status message contains a Plan part, and its metadata is
   `{"kind": "approval_request", "plan_hash": "sha256:…", "approval_url": "…"}`
   (`approval_url` is OPTIONAL).
2. **Resume:** the client sends a message with the same `taskId` and `contextId`
   containing one or more Approval parts.
3. **Approved, preconditions hold:** the agent goes back to `TASK_STATE_WORKING` and
   emits an Artifact containing the Applied part.
4. **Rejected:** `TASK_STATE_REJECTED`, metadata `{"kind": "rejected", "plan_hash": …}`.
5. **Drift:** either back to `TASK_STATE_INPUT_REQUIRED` with a new plan (metadata
   `{"kind": "replanned", "previous_plan_hash": …, "failed_preconditions": […]}`), or
   `TASK_STATE_FAILED` with metadata `{"kind": "drifted", …}`.
6. **Expired:** `TASK_STATE_FAILED`, metadata `{"kind": "expired"}`.

### 13.4 Trusting an A2A approval

The A2A client is usually another agent, often the one whose request is being gated. An
Approval part sent by the client MUST carry a valid `signature` from an approver key the
receiving agent trusts. Otherwise the receiving agent MUST ignore it and rely on its own
out-of-band channel (`approval_url`). `TASK_STATE_AUTH_REQUIRED` is for authentication
and MUST NOT be used for plan approval.

## 14. Observability

Runtimes SHOULD emit OpenTelemetry spans for `plan`, `policy`, `approve`, `apply`, and
`compensate`, linked in one trace. Attributes:

| Attribute | Value |
|---|---|
| `sealedplan.plan.hash` | plan hash |
| `sealedplan.action.name` | action name |
| `sealedplan.effect` | effective effect class |
| `sealedplan.risk` | risk level |
| `sealedplan.decision` | policy decision |
| `sealedplan.state` | state after the span |
| `sealedplan.agent.id`, `sealedplan.sponsor.id`, `sealedplan.approver.id` | principal IDs |
| `sealedplan.drift.failed` | failed precondition IDs |

`params`, `before`, and `after` MUST NOT be recorded as span attributes by default. In
MCP, trace context travels in `_meta.traceparent`.

## 15. Versioning

`spec_version` is `MAJOR.MINOR`. Minor versions only add optional fields. Receivers MUST
reject a plan whose major version they don't support. The MCP extension identifier and
the A2A extension URI change with every major version.

## 16. Open questions for review

- **Q1 — Identifiers.** The MCP extension ID `io.github.sealedplan/plan-apply` and the
  A2A URI `https://github.com/sealedplan/spec/ext/a2a/v0.1` only work if the
  `sealedplan` GitHub organization is claimed. A domain the project owns (for example
  `sealedplan.dev` → `dev.sealedplan/plan-apply`) would be more durable. Media types
  `application/vnd.sealedplan.*+json` are unregistered vendor types.
- **Q2 — `principal` in the hash.** Included in this draft: an approval is for *this*
  agent to do *this*. The cost is that the same change from two agents needs two
  approvals.
- **Q3 — `summary` in the hash.** Included, so the text the approver read can't be
  swapped. The alternative is to exclude it and render only structured fields.
- **Q4 — Run-level approval.** Should a run get its own hash over its step hashes, so a
  reviewer approves a whole remediation once?
- **Q5 — Standing approvals.** `scope.uses > 1`, or approvals that match a class of
  plans ("any REVERSIBLE scale in namespace X today"). Deferred, because it weakens hash
  binding.
- **Q6 — Edit.** LangChain HITL lets reviewers edit a call. Here an edit must be a
  re-plan with a new hash. Is that acceptable UX?
- **Q7 — MCP `Tool._meta`.** If confirmed for 2026-07-28, per-tool declarations could
  move from the capability map onto each tool.
- **Q8 — Signature format.** Detached JWS is proposed. COSE, or plain Ed25519 over JCS
  bytes, are alternatives.
- **Q9 — JSON Schemas.** Field tables are written in prose here. The schema files and
  hash test vectors are next, once the object shapes are agreed.
