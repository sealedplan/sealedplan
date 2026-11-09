from __future__ import annotations

import copy
import json
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from conftest import T0
from sealedplan.canonical import digest_bytes
from sealedplan.models import Effect, Plan, RiskLevel
from sealedplan.providers.terraform import (
    KNOWN_AFTER_APPLY,
    SENSITIVE,
    ApplyPlan,
    CliRunner,
    TerraformError,
)
from sealedplan.runtime import Runtime
from sealedplan.state import State
from sealedplan.store import SqliteStore
from test_runtime import AGENT, ALICE, BOB, CAROL, RUNTIME, Clock, approval

STACK = "network"
LINEAGE = "lineage-test"

CREATE_AND_UPDATE: dict[str, Any] = {
    "resource_changes": [
        {
            "address": "aws_s3_bucket.logs",
            "type": "aws_s3_bucket",
            "change": {
                "actions": ["create"],
                "before": None,
                "after": {"bucket": "logs", "acl": "private", "weight": 0.5},
                "after_unknown": {"arn": True},
                "after_sensitive": {},
            },
        },
        {
            "address": "aws_db_instance.main",
            "type": "aws_db_instance",
            "change": {
                "actions": ["update"],
                "before": {"instance_class": "db.small", "password": "old", "port": 5432},
                "after": {"instance_class": "db.medium", "password": "new", "port": 5432},
                "before_sensitive": {"password": True},
                "after_sensitive": {"password": True},
            },
        },
        {
            "address": "null_resource.unchanged",
            "type": "null_resource",
            "change": {"actions": ["no-op"], "before": {}, "after": {}},
        },
    ]
}

REPLACE: dict[str, Any] = {
    "resource_changes": [
        {
            "address": "aws_instance.web",
            "type": "aws_instance",
            "change": {
                "actions": ["delete", "create"],
                "before": {"image": "image-1"},
                "after": {"image": "image-2"},
            },
        }
    ]
}


@dataclass
class FakeTerraform:
    """A TerraformRunner over an in-memory state. Plan files record the serial they saw."""

    serial: int | None = 3
    show: Mapping[str, Any] = field(default_factory=lambda: copy.deepcopy(CREATE_AND_UPDATE))
    applies: list[Path] = field(default_factory=list)
    fail: str | None = None  # "error" (nothing written) or "partial" (state moved)
    during_plan: Callable[[], None] | None = None
    before_apply: Callable[[], None] | None = None

    def bump(self) -> None:
        self.serial = 1 if self.serial is None else self.serial + 1

    def plan(self, workdir: Path, out: Path) -> None:
        assert workdir == Path("stacks") / STACK
        out.write_text(json.dumps({"serial": self.serial, "show": self.show}))
        if self.during_plan:
            self.during_plan()

    def show_json(self, workdir: Path, planfile: Path) -> Mapping[str, Any]:
        shown: Mapping[str, Any] = json.loads(planfile.read_text())["show"]
        return shown

    def apply(self, workdir: Path, planfile: Path) -> None:
        if self.before_apply:
            self.before_apply()
        if json.loads(planfile.read_text())["serial"] != self.serial:
            raise TerraformError("Saved plan is stale", stale=True)
        if self.fail == "error":
            raise TerraformError("Error: creating bucket: AccessDenied")
        self.bump()
        if self.fail == "partial":
            raise TerraformError("Error: creating instance: quota exceeded")
        self.applies.append(planfile)

    def state(self, workdir: Path) -> Mapping[str, Any] | None:
        if self.serial is None:
            return None
        return {"version": 4, "lineage": LINEAGE, "serial": self.serial}


@dataclass
class TfEnv:
    tf: FakeTerraform
    rt: Runtime
    store: SqliteStore
    plan_dir: Path

    def propose(self, stack: str = STACK) -> Plan:
        return self.rt.propose(
            "terraform.apply",
            {"stack": stack},
            agent=AGENT,
            sponsor=ALICE,
            idempotency_key=f"apply-{stack}",
        ).plan

    def approved(self) -> Plan:
        plan = self.propose()
        assert self.rt.submit_approval(approval(plan, BOB)) is State.APPROVED
        return plan

    def state(self, plan: Plan) -> State:
        return self.store.get(plan.plan_hash).state

    def planfiles(self) -> list[Path]:
        return sorted(self.plan_dir.glob("*"))


@pytest.fixture
def tf(tmp_path: Path) -> TfEnv:
    fake = FakeTerraform()
    store = SqliteStore()
    rt = Runtime(store, RUNTIME, clock=Clock(T0))
    plan_dir = tmp_path / "plans"
    rt.register(ApplyPlan(fake, {STACK: Path("stacks") / STACK}, plan_dir))
    return TfEnv(fake, rt, store, plan_dir)


# --- plan -----------------------------------------------------------------------------


def test_plan(tf: TfEnv) -> None:
    plan = tf.propose()
    assert plan.effect is Effect.IRREVERSIBLE
    assert plan.risk.level is RiskLevel.MEDIUM
    assert plan.summary == "Apply Terraform stack network: 1 to create, 1 to update"
    bucket, db = plan.changes
    assert (bucket.resource.type, bucket.resource.id, bucket.op) == (
        "terraform/aws_s3_bucket",
        "tf://network/aws_s3_bucket.logs",
        "create",
    )
    assert bucket.after == {
        "bucket": "logs",
        "acl": "private",
        "weight": {"$number": "0.5"},
        "arn": KNOWN_AFTER_APPLY,
    }
    assert (db.op, db.before, db.after) == (
        "update",
        {"instance_class": "db.small", "password": SENSITIVE},
        {"instance_class": "db.medium", "password": SENSITIVE},
    )
    assert db.sensitive == ["/before/password", "/after/password"]
    [pre] = plan.preconditions
    assert (pre.resource.id, pre.kind, pre.expect, pre.enforcement) == (
        "tf://network",
        "version",
        f"{LINEAGE}/3",
        "atomic",
    )
    assert plan.blast_radius is not None
    assert (plan.blast_radius.resources, plan.blast_radius.scopes) == (2, ["tf://network"])
    assert tf.state(plan) is State.PENDING_APPROVAL


def test_plan_seals_the_plan_file(tf: TfEnv) -> None:
    plan = tf.propose()
    [evidence] = plan.evidence or []
    [planfile] = tf.planfiles()
    assert evidence.kind == "terraform.plan-file"
    assert evidence.digest == digest_bytes(planfile.read_bytes())
    assert planfile.name == evidence.digest.removeprefix("sha256:") + ".tfplan"
    assert (tf.tf.serial, tf.tf.applies) == (3, [])


def test_secrets_stay_out_of_the_plan(tf: TfEnv) -> None:
    text = json.dumps(tf.propose().to_obj())
    assert '"old"' not in text
    assert '"new"' not in text


def test_replace_is_delete_then_create_and_needs_two_people(tf: TfEnv) -> None:
    tf.tf.show = REPLACE
    plan = tf.propose()
    assert [(c.op, c.before, c.after) for c in plan.changes] == [
        ("delete", {"image": "image-1"}, None),
        ("create", None, {"image": "image-2"}),
    ]
    assert plan.risk.level is RiskLevel.HIGH
    assert plan.risk.reasons == [
        "destroys or replaces 1 resource(s): tf://network/aws_instance.web"
    ]
    assert plan.blast_radius is not None
    assert plan.blast_radius.resources == 1
    assert tf.rt.submit_approval(approval(plan, BOB)) is State.PENDING_APPROVAL
    assert tf.rt.submit_approval(approval(plan, CAROL)) is State.APPROVED


def test_first_apply_expects_no_state(tf: TfEnv) -> None:
    tf.tf.serial = None
    [pre] = tf.propose().preconditions
    assert (pre.kind, pre.expect) == ("absent", None)


@pytest.mark.parametrize(
    ("stack", "show", "message"),
    [
        ("prod", CREATE_AND_UPDATE, "not one this action may apply"),
        (STACK, {"resource_changes": []}, "no changes"),
        (STACK, {}, "no changes"),
    ],
)
def test_bad_requests(tf: TfEnv, stack: str, show: dict[str, Any], message: str) -> None:
    tf.tf.show = show
    with pytest.raises(ValueError, match=message):
        tf.propose(stack)
    assert tf.planfiles() == []


def test_state_moving_while_planning_is_refused(tf: TfEnv) -> None:
    tf.tf.during_plan = tf.tf.bump
    with pytest.raises(ValueError, match="state changed while planning"):
        tf.propose()
    assert tf.planfiles() == []


# --- apply ----------------------------------------------------------------------------


def test_apply(tf: TfEnv) -> None:
    plan = tf.approved()
    result = tf.rt.execute(plan.plan_hash)
    assert result.state is State.APPLIED
    assert tf.tf.serial == 4
    assert result.applied is not None
    assert result.applied.result == {"state": f"{LINEAGE}/4"}
    assert result.applied.observed == {
        "tf://network": {"type": "terraform/state", "exists": True, "version": f"{LINEAGE}/4"}
    }
    assert tf.planfiles() == []  # plan files can hold secrets; gone once applied


def test_state_moved_after_approval_is_drift(tf: TfEnv) -> None:
    plan = tf.approved()
    tf.tf.bump()
    result = tf.rt.execute(plan.plan_hash)
    assert result.state is State.DRIFTED
    assert [(d.expected, d.observed) for d in result.drift] == [(f"{LINEAGE}/3", f"{LINEAGE}/4")]
    assert tf.tf.applies == []


def test_stale_plan_refused_by_terraform_is_drift(tf: TfEnv) -> None:
    plan = tf.approved()
    tf.tf.before_apply = tf.tf.bump
    assert tf.rt.execute(plan.plan_hash).state is State.DRIFTED
    assert tf.tf.applies == []


def test_altered_plan_file_is_never_applied(tf: TfEnv) -> None:
    plan = tf.approved()
    [planfile] = tf.planfiles()
    planfile.write_text(planfile.read_text().replace("logs", "everything"))
    result = tf.rt.execute(plan.plan_hash)
    assert result.state is State.FAILED
    assert "altered" in (result.error or "")
    assert (tf.tf.serial, tf.tf.applies) == (3, [])


def test_missing_plan_file_is_failed(tf: TfEnv) -> None:
    plan = tf.approved()
    for f in tf.planfiles():
        f.unlink()
    assert tf.rt.execute(plan.plan_hash).state is State.FAILED


def test_error_without_state_change_is_failed(tf: TfEnv) -> None:
    plan = tf.approved()
    tf.tf.fail = "error"
    result = tf.rt.execute(plan.plan_hash)
    assert result.state is State.FAILED
    assert "AccessDenied" in (result.error or "")


def test_partial_apply_is_unknown(tf: TfEnv) -> None:
    plan = tf.approved()
    tf.tf.fail = "partial"
    assert tf.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert tf.rt.reconcile(plan.plan_hash) is State.UNKNOWN  # a human reads the state


def test_lost_runner_reconciles_failed_when_state_never_moved(tf: TfEnv) -> None:
    plan = tf.approved()

    def crash() -> None:
        raise TimeoutError("runner lost")

    tf.tf.before_apply = crash
    assert tf.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert tf.rt.reconcile(plan.plan_hash) is State.FAILED


# --- CliRunner ------------------------------------------------------------------------


@dataclass
class FakeRun:
    """Stands in for subprocess.run; terraform itself is never started."""

    replies: list[tuple[int, str, str]]
    calls: list[tuple[list[str], Path]] = field(default_factory=list)

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs == {
            "cwd": kwargs["cwd"],
            "capture_output": True,
            "text": True,
            "check": False,
        }
        self.calls.append((args, kwargs["cwd"]))
        code, out, err = self.replies.pop(0)
        return subprocess.CompletedProcess(args, code, out, err)


def test_cli_runner_commands(tmp_path: Path) -> None:
    run = FakeRun([(0, "", ""), (0, '{"resource_changes": []}', ""), (0, "", ""), (0, "", "")])
    cli = CliRunner(run=run)
    planfile = tmp_path / "x.tfplan"
    cli.plan(tmp_path, planfile)
    assert cli.show_json(tmp_path, planfile) == {"resource_changes": []}
    cli.apply(tmp_path, planfile)
    assert cli.state(tmp_path) is None
    assert [args for args, _ in run.calls] == [
        ["terraform", "plan", "-input=false", "-no-color", f"-out={planfile}"],
        ["terraform", "show", "-json", "-no-color", str(planfile)],
        ["terraform", "apply", "-input=false", "-no-color", str(planfile)],
        ["terraform", "state", "pull"],
    ]
    assert {cwd for _, cwd in run.calls} == {tmp_path}


def test_cli_runner_reads_state(tmp_path: Path) -> None:
    cli = CliRunner(run=FakeRun([(0, '{"lineage": "l", "serial": 9}\n', "")]))
    assert cli.state(tmp_path) == {"lineage": "l", "serial": 9}


def test_cli_runner_errors(tmp_path: Path) -> None:
    cli = CliRunner(
        run=FakeRun(
            [
                (1, "", "Error: Saved plan is stale\n\nThe given plan file can no longer..."),
                (1, "", "Error: creating bucket: AccessDenied"),
            ]
        )
    )
    with pytest.raises(TerraformError) as stale:
        cli.apply(tmp_path, tmp_path / "x.tfplan")
    assert stale.value.stale
    with pytest.raises(TerraformError, match="AccessDenied") as other:
        cli.apply(tmp_path, tmp_path / "x.tfplan")
    assert not other.value.stale
