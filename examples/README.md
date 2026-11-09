# Examples

Run each one from the repository root after `uv sync`. They need nothing beyond
the `sealedplan` package and Python's standard library, and the test suite runs
them so they stay working.

| Example | What it shows |
|---|---|
| [`sql_agent/`](sql_agent) | An agent that edits customer records and a person who approves each change with the `sealedplan` CLI. They run as two processes that share only a plan store. Covers approval, drift and undo. |
| [`custom_action/`](custom_action) | Writing your own action. A feature-flag service in one file, with auto-approval for low-risk changes, a person's approval for risky ones, drift and undo. |

```bash
uv run python examples/sql_agent/crm_agent.py demo
```

```bash
uv run python examples/custom_action/feature_flags.py
```
