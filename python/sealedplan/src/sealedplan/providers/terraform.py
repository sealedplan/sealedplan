"""Reference action: apply a Terraform saved plan.

Terraform already has plan/apply, and a saved plan already refuses to apply once the
state it was planned against has moved on ("Saved plan is stale"). This action wraps that:

- ``plan`` runs ``terraform plan -out``, reads ``terraform show -json``, and turns the
  resource changes into a sealed plan. The plan file's digest is the plan's evidence,
  so the approval covers that exact file.
- the precondition is the state's ``lineage/serial``. Terraform enforces it at apply
  time under its state lock, so it is atomic.
- ``apply`` checks the plan file still has that digest, then applies the file. No
  re-plan happens after approval.

The action is IRREVERSIBLE: Terraform has no general undo, and a destroyed resource can
take its data with it. Plans that destroy or replace anything are high risk, which the
default policy turns into a two-person approval.

Limits worth knowing:

- The precondition covers Terraform state, not the real infrastructure. A change made
  outside Terraform after planning is not detected. Planning refreshes, so keep the
  window between plan and apply short (plans expire after 30 minutes by default).
- Plan files can contain secret values. They are kept in ``plan_dir`` and deleted once
  applied; plans that are rejected, expire or fail leave theirs behind. Protect that
  directory like the state itself and clear out old files. Values Terraform marks
  sensitive are replaced in the sealed plan and listed in ``sensitive`` (§11.6).
- Plans are canonical JSON, which has no floats; non-integer numbers in before/after
  appear as ``{"$number": "<text>"}``.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from sealedplan.actions import ApplyFailedError, Context, PreconditionFailedError, action
from sealedplan.canonical import digest_bytes
from sealedplan.models import (
    Applied,
    BlastRadius,
    Change,
    Effect,
    Evidence,
    Plan,
    Precondition,
    ResourceRef,
    RiskLevel,
)
from sealedplan.preconditions import ABSENT, Observation, PreconditionResult
from sealedplan.state import State

STATE_TYPE = "terraform/state"
PRECONDITION_ID = "state-serial"
EVIDENCE_KIND = "terraform.plan-file"
SENSITIVE = {"$ref": "terraform:sensitive"}
KNOWN_AFTER_APPLY = {"$ref": "terraform:known-after-apply"}


class TerraformError(Exception):
    def __init__(self, message: str, *, stale: bool = False) -> None:
        super().__init__(message)
        self.stale = stale


class TerraformRunner(Protocol):
    def plan(self, workdir: Path, out: Path) -> None:
        """``terraform plan -out=<out>``. Raises TerraformError on failure."""
        ...

    def show_json(self, workdir: Path, planfile: Path) -> Mapping[str, Any]:
        """``terraform show -json <planfile>``."""
        ...

    def apply(self, workdir: Path, planfile: Path) -> None:
        """``terraform apply <planfile>``. Raises TerraformError, with ``stale`` set when
        Terraform refused the plan because the state moved on."""
        ...

    def state(self, workdir: Path) -> Mapping[str, Any] | None:
        """``terraform state pull`` as JSON, or None when there is no state yet."""
        ...


Run = Callable[..., "subprocess.CompletedProcess[str]"]


class CliRunner:
    """Runs the ``terraform`` binary. The working directory must already be initialised."""

    def __init__(self, binary: str = "terraform", run: Run = subprocess.run) -> None:
        self.binary = binary
        self._run = run

    def _call(self, workdir: Path, *args: str) -> str:
        proc = self._run(
            [self.binary, *args],
            cwd=workdir,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "").strip()
            raise TerraformError(message, stale="Saved plan is stale" in message)
        return proc.stdout

    def plan(self, workdir: Path, out: Path) -> None:
        self._call(workdir, "plan", "-input=false", "-no-color", f"-out={out}")

    def show_json(self, workdir: Path, planfile: Path) -> Mapping[str, Any]:
        parsed: Mapping[str, Any] = json.loads(
            self._call(workdir, "show", "-json", "-no-color", str(planfile))
        )
        return parsed

    def apply(self, workdir: Path, planfile: Path) -> None:
        self._call(workdir, "apply", "-input=false", "-no-color", str(planfile))

    def state(self, workdir: Path) -> Mapping[str, Any] | None:
        out = self._call(workdir, "state", "pull").strip()
        if not out:
            return None
        parsed: Mapping[str, Any] = json.loads(out)
        return parsed


# --- turning `terraform show -json` into changes ----------------------------------------

_OPS: Mapping[tuple[str, ...], tuple[str, ...]] = {
    ("create",): ("create",),
    ("update",): ("update",),
    ("delete",): ("delete",),
    ("delete", "create"): ("delete", "create"),  # replace
    ("create", "delete"): ("create", "delete"),  # replace, create_before_destroy
}


def _clean(value: Any, sensitive: Any, pointer: str, marked: list[str]) -> Any:
    """Replace values marked sensitive and floats; record the pointers that were hidden."""
    if sensitive is True:
        marked.append(pointer)
        return SENSITIVE
    if isinstance(value, float):
        return {"$number": repr(value)}
    if isinstance(value, dict):
        sub = sensitive if isinstance(sensitive, dict) else {}
        return {
            k: _clean(v, sub.get(k), f"{pointer}/{_escape(k)}", marked) for k, v in value.items()
        }
    if isinstance(value, list):
        subs = sensitive if isinstance(sensitive, list) else []
        return [
            _clean(v, subs[i] if i < len(subs) else None, f"{pointer}/{i}", marked)
            for i, v in enumerate(value)
        ]
    return value


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _change_values(
    change: Mapping[str, Any], actions: tuple[str, ...]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    """Cleaned ``before``/``after`` and the JSON pointers of the values hidden as sensitive.

    For an update only the top-level keys whose value changes are kept. Values Terraform
    only learns during apply show as ``{"$ref": "terraform:known-after-apply"}``.
    """
    before = change.get("before") if isinstance(change.get("before"), dict) else None
    after = change.get("after") if isinstance(change.get("after"), dict) else None
    if after is not None:
        unknown = change.get("after_unknown")
        if isinstance(unknown, dict):
            after = {**after, **{k: KNOWN_AFTER_APPLY for k, v in unknown.items() if v is True}}
    if actions == ("update",) and before is not None and after is not None:
        changed = {k for k in before.keys() | after.keys() if before.get(k) != after.get(k)}
        before = {k: v for k, v in before.items() if k in changed}
        after = {k: v for k, v in after.items() if k in changed}
    marked: list[str] = []
    if before is not None:
        before = _clean(before, change.get("before_sensitive"), "/before", marked)
    if after is not None:
        after = _clean(after, change.get("after_sensitive"), "/after", marked)
    return before, after, marked


def changes_from_show(stack: str, shown: Mapping[str, Any]) -> list[Change]:
    """Turn ``terraform show -json`` output into changes. A replace becomes two changes."""
    out: list[Change] = []
    for rc in shown.get("resource_changes", []):
        actions = tuple(rc["change"]["actions"])
        if actions in (("no-op",), ("read",)):
            continue
        if actions not in _OPS:
            raise ValueError(f"unexpected Terraform actions {actions} for {rc['address']}")
        ref = ResourceRef(type=f"terraform/{rc['type']}", id=f"tf://{stack}/{rc['address']}")
        before, after, marked = _change_values(rc["change"], actions)
        for op in _OPS[actions]:
            keep_before, keep_after = op != "create", op != "delete"
            sensitive = [
                p
                for p in marked
                if (keep_before and p.startswith("/before/"))
                or (keep_after and p.startswith("/after/"))
            ]
            out.append(
                Change(
                    resource=ref,
                    op=op,  # type: ignore[arg-type]
                    before=before if keep_before else None,
                    after=after if keep_after else None,
                    sensitive=sensitive or None,
                )
            )
    return out


def _version(state: Mapping[str, Any] | None) -> str | None:
    if state is None:
        return None
    return f"{state['lineage']}/{state['serial']}"


@action(
    "terraform.apply",
    effect=Effect.IRREVERSIBLE,
    risk="medium",
    version="1.0.0",
    provider="sealedplan-terraform",
)
class ApplyPlan:
    def __init__(
        self,
        runner: TerraformRunner,
        stacks: Mapping[str, Path],
        plan_dir: Path,
    ) -> None:
        self.runner = runner
        self.stacks = dict(stacks)
        self.plan_dir = plan_dir

    def _workdir(self, stack: str) -> Path:
        try:
            return self.stacks[stack]
        except KeyError:
            raise ValueError(f"stack {stack!r} is not one this action may apply") from None

    def _state_ref(self, stack: str) -> ResourceRef:
        return ResourceRef(type=STATE_TYPE, id=f"tf://{stack}")

    def _planfile(self, plan: Plan) -> tuple[Path, str]:
        ev = next(e for e in plan.evidence or [] if e.kind == EVIDENCE_KIND)
        return self.plan_dir / f"{ev.digest.removeprefix('sha256:')}.tfplan", ev.digest

    # --- the action -------------------------------------------------------------------

    def plan(self, ctx: Context, stack: str) -> Plan:
        workdir = self._workdir(stack)
        self.plan_dir.mkdir(parents=True, exist_ok=True)
        before = _version(self.runner.state(workdir))
        scratch = self.plan_dir / f"pending-{uuid.uuid4().hex}.tfplan"
        try:
            self.runner.plan(workdir, scratch)
            if _version(self.runner.state(workdir)) != before:
                raise ValueError("Terraform state changed while planning; plan again")
            shown = self.runner.show_json(workdir, scratch)
            changes = changes_from_show(stack, shown)
            if not changes:
                raise ValueError(f"nothing to apply: stack {stack} has no changes")
            file_digest = digest_bytes(scratch.read_bytes())
            scratch.replace(self.plan_dir / f"{file_digest.removeprefix('sha256:')}.tfplan")
        finally:
            scratch.unlink(missing_ok=True)

        state_ref = self._state_ref(stack)
        destroyed = sorted({c.resource.id for c in changes if c.op == "delete"})
        risk, reasons = RiskLevel.MEDIUM, []
        if destroyed:
            risk = RiskLevel.HIGH
            reasons = [f"destroys or replaces {len(destroyed)} resource(s): {', '.join(destroyed)}"]
        counts = {op: sum(c.op == op for c in changes) for op in ("create", "update", "delete")}
        summary = f"Apply Terraform stack {stack}: " + ", ".join(
            f"{n} to {op}" for op, n in counts.items() if n
        )
        return ctx.plan(
            summary=summary,
            changes=changes,
            preconditions=[
                Precondition(
                    id=PRECONDITION_ID,
                    resource=state_ref,
                    kind="version" if before else "absent",
                    expect=before,
                    enforcement="atomic",
                )
            ],
            risk=risk,
            risk_reasons=reasons,
            blast_radius=BlastRadius(
                resources=len({c.resource.id for c in changes}), scopes=[f"tf://{stack}"]
            ),
            evidence=[
                Evidence(
                    kind=EVIDENCE_KIND, media_type="application/octet-stream", digest=file_digest
                )
            ],
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        """Only the stack's state is observed; individual resources are Terraform's business."""
        if resource.type != STATE_TYPE:
            raise ValueError(f"terraform.apply observes only {STATE_TYPE}, not {resource.type}")
        version = _version(self.runner.state(self._workdir(resource.id.removeprefix("tf://"))))
        return ABSENT if version is None else Observation(True, version)

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        stack = plan.params["stack"]
        workdir = self._workdir(stack)
        planfile, expected_digest = self._planfile(plan)
        if not planfile.is_file() or digest_bytes(planfile.read_bytes()) != expected_digest:
            raise ApplyFailedError("the approved plan file is missing or has been altered")
        pre = next(p for p in plan.preconditions if p.id == PRECONDITION_ID)
        try:
            self.runner.apply(workdir, planfile)
        except TerraformError as exc:
            now = _version(self.runner.state(workdir))
            if exc.stale:
                raise PreconditionFailedError(
                    [PreconditionResult(pre.id, False, pre.expect, now or "absent")]
                ) from exc
            if now == pre.expect:
                raise ApplyFailedError(str(exc)) from exc  # state untouched: nothing applied
            raise  # state moved: a partial apply, so the outcome is UNKNOWN
        planfile.unlink(missing_ok=True)
        state_ref = self._state_ref(stack)
        after = self.observe(ctx, state_ref)
        return ctx.applied(
            plan,
            result={"state": after.version},
            observed={state_ref.id: {"type": STATE_TYPE, **after.snapshot()}},
        )

    def reconcile(self, ctx: Context, plan: Plan, applied: Applied | None) -> State:
        """FAILED if the state never moved; anything else needs a human to read the state."""
        pre = next(p for p in plan.preconditions if p.id == PRECONDITION_ID)
        now = _version(self.runner.state(self._workdir(plan.params["stack"])))
        return State.FAILED if now == pre.expect else State.UNKNOWN
