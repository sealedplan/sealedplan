from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from conftest import IDP, T0
from sealedplan.cli import main, short_hash
from sealedplan.models import Plan
from sealedplan.state import State
from sealedplan.store import SqliteStore
from test_runtime import AGENT, Cell, Env, World, make_env

SPOOF = "k\x1b[2J‮"


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "plans.db"


@pytest.fixture
def env(db: Path) -> Env:
    world = World({"k": Cell(3), "a": Cell(1), SPOOF: Cell(1)})
    return make_env(SqliteStore(db), world=world)


def run(db: Path, *args: str) -> int:
    return main(["--db", str(db), *args], clock=lambda: T0)


def as_bob(*args: str) -> tuple[str, ...]:
    return (*args, "--as", "bob", "--issuer", IDP)


def test_list_shows_pending_only_by_default(
    env: Env, db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pending = env.propose()
    auto = env.propose("test.set_low", key="a")
    assert run(db, "list") == 0
    out = capsys.readouterr().out
    assert short_hash(pending.plan_hash) in out
    assert short_hash(auto.plan_hash) not in out
    assert run(db, "list", "--all") == 0
    assert short_hash(auto.plan_hash) in capsys.readouterr().out


def test_show_renders_what_the_spec_requires(
    env: Env, db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = env.propose("test.send", key="new")
    assert run(db, "show", short_hash(plan.plan_hash)) == 0
    out = capsys.readouterr().out
    assert plan.plan_hash in out
    assert "IRREVERSIBLE" in out
    assert "invoke" in out
    assert "test://new" in out
    assert "NOT ATOMIC" in out
    assert "none: this change is not undone" in out
    assert "blast radius  not stated" in out


def test_show_escapes_terminal_control_characters(
    env: Env, db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = env.propose(key=SPOOF)
    assert run(db, "show", plan.plan_hash) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "‮" not in out
    assert "\\x1b[2J" in out
    assert "\\u202e" in out


def test_show_json_is_the_plan(env: Env, db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plan = env.propose()
    assert run(db, "show", "--json", plan.plan_hash) == 0
    assert Plan.model_validate_json(capsys.readouterr().out) == plan


def test_approve(env: Env, db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plan = env.propose()
    assert run(db, *as_bob("approve", short_hash(plan.plan_hash), "--yes")) == 0
    assert "plan is now APPROVED" in capsys.readouterr().out
    assert env.state(plan) is State.APPROVED
    [approval] = env.store.approvals(plan.plan_hash)
    assert (approval.approver.id, approval.method) == ("bob", "cli")
    assert approval.expires_at == T0.replace(minute=18)
    assert env.store.events(plan.plan_hash)[-1].actor.id == "bob"
    assert env.rt.execute(plan.plan_hash).state is State.APPLIED


def test_approve_asks_first(
    env: Env, db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = env.propose()
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert run(db, *as_bob("approve", plan.plan_hash)) == 1
    assert "nothing recorded" in capsys.readouterr().out
    assert env.state(plan) is State.PENDING_APPROVAL
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    assert run(db, *as_bob("approve", plan.plan_hash)) == 0
    assert env.state(plan) is State.APPROVED


def test_reject(env: Env, db: Path) -> None:
    plan = env.propose()
    assert run(db, *as_bob("reject", plan.plan_hash, "--yes", "--comment", "not today")) == 0
    assert env.state(plan) is State.REJECTED
    assert env.store.approvals(plan.plan_hash)[0].comment == "not today"


def test_identity_from_environment(env: Env, db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = env.propose()
    monkeypatch.setenv("SEALEDPLAN_APPROVER", "carol")
    monkeypatch.setenv("SEALEDPLAN_ISSUER", IDP)
    assert run(db, "approve", plan.plan_hash, "--yes") == 0
    assert env.store.approvals(plan.plan_hash)[0].approver.id == "carol"


def test_agent_cannot_approve_through_the_cli(
    env: Env, db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = env.propose()
    args = ("approve", plan.plan_hash, "--yes", "--as", AGENT.id, "--issuer", AGENT.issuer)
    assert run(db, *args) == 1
    assert "cannot approve its own plan" in capsys.readouterr().err
    assert env.state(plan) is State.PENDING_APPROVAL


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("show", "sha256:ffff"), "no plans match"),
        (("approve", "sha256:ffff", "--yes"), "approver identity needed"),
    ],
)
def test_errors(
    env: Env,
    db: Path,
    args: tuple[str, ...],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env.propose()
    assert run(db, *args) == 1
    assert message in capsys.readouterr().err


def test_missing_store_is_not_created(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "nope.db"
    assert run(missing, "list") == 1
    assert "no store" in capsys.readouterr().err
    assert not missing.exists()


def test_tampered_plan_is_not_rendered(
    env: Env, db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = env.propose()
    env.store.close()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE plans SET body = replace(body, '\"value\":5', '\"value\":500')")
    assert run(db, "show", plan.plan_hash) == 1
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "500" not in captured.out
