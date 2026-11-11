"""examples/mcp_server is documentation; this keeps it running."""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[3] / "examples" / "mcp_server" / "crm_server.py"


def test_crm_server_demo(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = importlib.util.spec_from_file_location("crm_server", EXAMPLE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    assert module.main(["demo", "--dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "result: APPLIED" in out
    assert "plan: PENDING_APPROVAL" in out
    assert "apply: DRIFTED (error)" in out
    with sqlite3.connect(tmp_path / "crm.db") as conn:
        rows = conn.execute("SELECT id, tier, credit_limit FROM customers ORDER BY id").fetchall()
    assert rows == [(1, "gold", 1000), (2, "gold", 6000)]
