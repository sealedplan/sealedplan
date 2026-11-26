# sealedplan-openai-agents

Use a sealedplan runtime's actions as tools in an [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
agent. A tool call builds a plan; if a person must approve it, the run stops on the
SDK's tool approval, and continues only once the plan is approved in the runtime's store.
Needs `openai-agents` 0.26.

```python
from agents import Agent
from sealedplan_openai_agents import sealedplan_tools

tools = sealedplan_tools(rt, agent=AGENT)  # rt: a Runtime with actions registered
assistant = Agent(name="ops", instructions="...", tools=tools)
```

Each registered action becomes one tool. `sql.update_row` becomes `sql_update_row`, and
its arguments are the action's `plan()` parameters. A call never changes the target
system directly.

## What a tool call does

| Policy decision | Result |
|---|---|
| `auto` | The change is drift-checked and applied; the tool returns the outcome. |
| `approve`, `two_person` | The run stops with the call in `result.interruptions`. |
| `deny` | The tool returns `state: DENIED` with the plan hash. Nothing is written. |

The tool returns a JSON object to the model: `state`, `plan_hash`, `summary`, `message`,
and where they apply `applied`, `failed_preconditions` (drift), `deviation` and `error`.

## Approving and resuming

```python
from agents import Runner
from sealedplan_openai_agents import resolve_approvals

result = await Runner.run(assistant, "Upgrade customer 1 to gold")
state = result.to_state()
for plan in resolve_approvals(rt, state):  # the plans waiting for a person
    print(plan["plan_hash"], plan["summary"])
```

A person approves the plan out of band, for example:

```bash
sealedplan --db plans.db approve <hash prefix> --as dana --issuer https://idp.example.com
```

Then the application copies the store's decisions onto the run and resumes it:

```python
resolve_approvals(rt, state)
result = await Runner.run(assistant, state)
```

`resolve_approvals` approves the calls whose plan was approved, rejects those whose plan
was rejected or expired (the model sees why), and leaves the rest waiting; a resumed run
stops on those again. Do not call `state.approve()` on these calls yourself: the SDK's
approval only lets the run continue. The tool reads approval from the store, and a call
approved in the run but not in the store writes nothing. If the system changed after
approval, the tool returns `DRIFTED` and nothing is written.

## One tool call, one plan

The SDK asks whether a call needs approval before it runs the tool. The adapter makes
the plan at that point and uses the call's id as the plan's idempotency key
(`KEY_PREFIX` + call id), so the approval check, `resolve_approvals` and the tool itself
all find the same plan.

## Who is the agent

`agent=` is the principal recorded as the plan's agent, and `sponsor=` optionally the
person on whose behalf it acts.
