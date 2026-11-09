"""The examples are documentation; these tests keep them running."""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path
from types import ModuleType

import pytest

from sealedplan import cli

EXAMPLES = Path(__file__).resolve().parents[3] / "examples"


def load(relative: str) -> ModuleType:
    path = EXAMPLES / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


def customers(workdir: Path) -> list[tuple[object, ...]]:
    with sqlite3.connect(workdir / "crm.db") as conn:
        return conn.execute("SELECT id, tier, credit_limit FROM customers ORDER BY id").fetchall()


def test_sql_agent_demo(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    crm_agent = load("sql_agent/crm_agent.py")
    assert crm_agent.main(["--dir", str(tmp_path), "demo"]) == 0
    out = capsys.readouterr().out
    assert "plan is now APPROVED" in out
    assert ": APPLIED" in out
    assert ": DRIFTED" in out
    assert "compensated" in out
    assert customers(tmp_path) == [(1, "silver", 1000), (2, "gold", 5500)]


def test_sql_agent_step_by_step(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The manual flow from examples/sql_agent/README.md."""
    crm_agent = load("sql_agent/crm_agent.py")

    def run(*args: str) -> int:
        result: int = crm_agent.main(["--dir", str(tmp_path), *args])
        return result

    assert run("init") == 0
    assert run("propose", "1", "--tier", "gold") == 0
    plan = capsys.readouterr().out.split("plan  ")[1].split()[0]
    assert run("execute", plan) == 1  # not approved yet
    db = str(tmp_path / "plans.db")
    assert cli.main(["--db", db, "approve", plan, "--as", "bob", "--issuer", "idp", "--yes"]) == 0
    assert run("execute", plan) == 0
    assert customers(tmp_path)[0] == (1, "gold", 1000)
    assert run("undo", plan) == 0
    assert customers(tmp_path)[0] == (1, "silver", 1000)


def test_feature_flags(capsys: pytest.CaptureFixture[str]) -> None:
    load("custom_action/feature_flags.py").main()
    out = capsys.readouterr().out
    assert "APPROVED (policy: auto)" in out
    assert "PENDING_APPROVAL (policy: approve)" in out
    assert "execute: DRIFTED" in out
    assert "compensate: succeeded" in out
