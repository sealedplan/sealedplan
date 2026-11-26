# sealedplan-langgraph

Use a sealedplan runtime's actions as tools in a LangGraph agent. A tool call builds a
plan; if a person must approve it, the graph pauses with the plan as the interrupt
value, and continues only for that plan's hash. Needs LangGraph 1.2 or later.

```python
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.prebuilt import create_react_agent
from sealedplan_langgraph import sealedplan_tools

tools = sealedplan_tools(rt, agent=AGENT)  # rt: a Runtime with actions registered
graph = create_react_agent(model, tools, checkpointer=InMemorySaver())
```

Each registered action becomes one tool. `sql.update_row` becomes `sql_update_row`, and
its arguments are the action's `plan()` parameters. A call never changes the target
system directly. Interrupts need a checkpointer.

## What a tool call does

| Policy decision | Result |
|---|---|
| `auto` | The change is drift-checked and applied; the tool returns the outcome. |
| `approve`, `two_person` | The graph pauses. The interrupt value is the plan (below). |
| `deny` | The tool returns `state: DENIED` with the plan hash. Nothing is written. |

The tool returns a JSON object to the model: `state`, `plan_hash`, `summary`, `message`,
and where they apply `applied`, `failed_preconditions` (drift), `deviation` and `error`.

## Approving and resuming

```python
result = graph.invoke({"messages": [("user", "Upgrade customer 1 to gold")]}, config)
paused = result["__interrupt__"][0].value
# {"kind": "io.github.sealedplan/plan-apply", "plan_hash": "sha256:…", "summary": …,
#  "state": "PENDING_APPROVAL", "expires_at": …, "plan": {…}, "resume": {"plan_hash": …}}
```

A person approves the plan out of band, for example:

```bash
sealedplan --db plans.db approve <hash prefix> --as dana --issuer https://idp.example.com
```

Then the application resumes the graph:

```python
from langgraph.types import Command

graph.invoke(Command(resume=paused["resume"]), config)
```

The resume value only says which plan to continue. It is **never** an approval: the tool
reads approvals from the runtime's store. Resuming before approval pauses again on the
same plan. A resume that names a different plan is refused, and nothing is written. If
the system changed after approval, the tool returns `DRIFTED` and nothing is written.

## One tool call, one plan

LangGraph runs an interrupted node again from the start when it resumes. The adapter
uses the tool call's id as the plan's idempotency key, so the second run finds the plan
the first run stored, in whatever state it is now, instead of proposing a new one.

To gate your own node instead of a tool, call `run_action(rt, action_name, params,
agent=..., idempotency_key=...)` inside it. Use a key that names that one call and stays
the same when the node runs again.

## Who is the agent

`agent=` is the principal recorded as the plan's agent, and `sponsor=` optionally the
person on whose behalf it acts.
