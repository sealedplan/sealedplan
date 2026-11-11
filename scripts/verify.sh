#!/usr/bin/env bash
# Project checks. Run before calling any change done; CI runs the same steps.
set -euo pipefail
cd "$(dirname "$0")/.."

uv sync --locked --all-packages --group dev
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --no-git --no-banner --redact -s . >/dev/null 2>&1 \
    || { echo "verify: gitleaks reported a possible secret; run it without redirects to see it" >&2; exit 1; }
fi
echo "verify: ok"
