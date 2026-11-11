# SQL agent with a human approver

An agent wants to change customer records in a database. Every change goes
through a person first.

```
 agent process                     plan store                    person
 (crm_agent.py)                    (plans.db)                    (sealedplan CLI)
 ──────────────                    ──────────                    ────────────────
 propose ─── sealed plan ────────▶ PENDING_APPROVAL
                                                   ◀──────────── list / show
                                   APPROVED        ◀──────────── approve
 execute ─── re-check row version,
             then write ─────────▶ APPLIED  (or DRIFTED: nothing written)
 undo ────── write old values ───▶ COMPENSATED
```

The agent and the person never talk to each other. They share one SQLite file,
the plan store. The person sees the plan exactly as it was hashed. The agent can
only execute that same plan, and only after it is approved.

## Run the whole story

```bash
uv run python examples/sql_agent/crm_agent.py demo
```

It works in a temporary directory and prints each step.

## Play both parts yourself

Use two terminals, both at the repository root. The files go in `./sealedplan-demo`.

**Agent terminal.** Create the database, then have the agent propose a change:

```bash
uv run python examples/sql_agent/crm_agent.py init
```

```bash
uv run python examples/sql_agent/crm_agent.py propose 1 --tier gold --credit-limit 2000
```

```
agent proposed: Set tier, credit_limit on customers row id=1
  plan  sha256:<hash>
  state PENDING_APPROVAL (approve by policy)
```

Nothing has been written to `crm.db` yet. If the agent tries to execute now, it is
refused:

```
error: plan sha256:<hash> is PENDING_APPROVAL; only an APPROVED plan can be applied
```

**Approver terminal.** Look at what is waiting, read the plan, and approve it:

```bash
uv run sealedplan --db sealedplan-demo/plans.db list
```

```bash
uv run sealedplan --db sealedplan-demo/plans.db approve <hash prefix> --as bob --issuer https://idp.example.com
```

`approve` prints the full plan before asking for confirmation:

- the row's values before and after;
- the precondition: the row's `version` must still be what it was when the plan
  was made;
- how the change would be undone.

**Agent terminal.** Execute the approved plan, look at the table, then undo the change:

```bash
uv run python examples/sql_agent/crm_agent.py execute <hash prefix>
```

```bash
uv run python examples/sql_agent/crm_agent.py rows
```

```bash
uv run python examples/sql_agent/crm_agent.py undo <hash prefix>
```

**Drift.** Propose and approve another change. Before executing it, change the row
behind the agent's back:

```bash
uv run python examples/sql_agent/crm_agent.py meddle 1
```

Executing now ends in `DRIFTED`, and nothing is written. The person approved a
change to the row as it was. The row is now different, so the approval no longer
applies. The agent has to propose again, and the person sees the new values.

## Where the safety comes from

- **The action decides what is possible.** `UpdateRow` gets an allowlist: the
  `customers` table, columns `tier` and `credit_limit`. The agent picks values,
  never table or column names. Values are always bound parameters.
- **The approval is bound to the plan hash.** If the agent changed one byte of the
  plan after approval, the hash would not match.
- **The precondition is enforced by the database.** The write is
  `UPDATE ... WHERE id = ? AND version = ?`. A concurrent writer makes it match no
  rows, and the result is DRIFTED rather than a lost update.
- **Undo checks too.** If someone edited the row after the agent's change, `undo`
  reports a conflict instead of overwriting their edit.
