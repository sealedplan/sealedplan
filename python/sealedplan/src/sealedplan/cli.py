"""Command-line approver: list, show, approve and reject plans in a SQLite store.

The CLI reads the store directly, so it is a trusted channel (§11.4): approvals it
records are unsigned and carry ``method: cli``. Everything it shows comes from the hashed
plan as the store re-verifies it on load, never from a summary of it (§11.5).

Approver identity comes from ``--as``/``--issuer`` or ``SEALEDPLAN_APPROVER``/
``SEALEDPLAN_ISSUER``; the store path from ``--db`` or ``SEALEDPLAN_DB``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sealedplan.models import Approval, ApprovalScope, Plan, PlanError, Principal
from sealedplan.runtime import Runtime, SealedPlanError, utc_now
from sealedplan.state import State
from sealedplan.store import PlanRecord, SqliteStore, StoreError

DEFAULT_DB = "sealedplan.db"
HASH_PREFIX = len("sha256:") + 12


class CliError(Exception):
    pass


# --- rendering ------------------------------------------------------------------------


def _text(value: object) -> str:
    """Provider text, with control and format characters (ANSI, bidi) shown escaped."""
    return "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in str(value)
    )


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _who(p: Principal) -> str:
    return f"{_text(p.id)} ({_text(p.issuer)}, {p.kind})"


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def short_hash(plan_hash: str) -> str:
    return plan_hash[:HASH_PREFIX]


def render_plan(record: PlanRecord, approvals: Sequence[Approval]) -> str:
    plan = record.plan
    lines: list[str] = []

    def field(label: str, value: str) -> None:
        lines.append(f"{label:<14}{value}")

    field("plan", plan.plan_hash)
    decision = f"  (policy: {record.decision})" if record.decision else ""
    field("state", f"{record.state}{decision}")
    version = f" {_text(plan.action.version)}" if plan.action.version else ""
    field("action", f"{_text(plan.action.name)}{version}")
    effect = str(plan.effect)
    if record.effect is not plan.effect:
        effect += f"  (treated as {record.effect})"
    field("effect", effect)
    field("risk", str(plan.risk.level))
    field("agent", _who(plan.principal.agent))
    if plan.principal.sponsor:
        field("sponsor", _who(plan.principal.sponsor))
    field("created", _ts(plan.created_at))
    field("expires", _ts(plan.expires_at))
    if plan.parent:
        field("run", f"{_text(plan.parent.run_id)} step {plan.parent.step}")
    if plan.blast_radius:
        br = plan.blast_radius
        approx = " (estimate)" if br.estimate else ""
        scopes = ", ".join(_text(s) for s in br.scopes)
        field("blast radius", f"{br.resources} resource(s){approx} in {scopes}")
        if br.notes:
            field("", _text(br.notes))
    else:
        field("blast radius", "not stated")

    lines += ["", "provider's description (not verified):"]
    lines.append(f"  summary: {_text(plan.summary)}")
    for reason in plan.risk.reasons or []:
        lines.append(f"  risk reason: {_text(reason)}")

    lines += ["", f"changes ({len(plan.changes)})"]
    for ch in plan.changes:
        lines.append(f"  {ch.op:<7} {_text(ch.resource.type)}  {_text(ch.resource.id)}")
        for label in ("before", "after", "patch"):
            value = getattr(ch, label)
            if value is not None:
                lines.append(f"    {label:<7} {_json(value)}")
        if ch.sensitive:
            lines.append(f"    sensitive (redacted): {', '.join(_text(s) for s in ch.sensitive)}")

    lines += ["", f"preconditions ({len(plan.preconditions)})"]
    for pre in plan.preconditions:
        if pre.kind in ("exists", "absent"):
            test: str = pre.kind
        elif pre.kind == "version":
            test = f"version == {_text(pre.expect)}"
        else:
            selected = ", ".join(_text(s) for s in pre.select or [])
            test = f"fingerprint of [{selected}] == {_text(pre.expect)}"
        lines.append(f"  {_text(pre.id)}: {test}  on {_text(pre.resource.id)}")
        if pre.enforcement == "atomic":
            lines.append("    atomic: the target refuses the write if this no longer holds")
        else:
            lines.append("    NOT ATOMIC: checked just before apply; a change after that is missed")

    lines += ["", "compensation"]
    if plan.compensation is None:
        lines.append("  none: this change is not undone automatically")
    else:
        comp = plan.compensation
        lines.append(f"  {comp.strategy}: {_text(comp.summary)}")
        if comp.params is not None:
            lines.append(f"    params  {_json(comp.params)}")

    if plan.evidence:
        lines += ["", "evidence"]
        for ev in plan.evidence:
            lines.append(f"  {_text(ev.kind)}  {_text(ev.media_type)}  {ev.digest}")

    lines += ["", f"approvals ({len(approvals)})"]
    for ap in approvals:
        lines.append(
            f"  {ap.decision:<7} {_who(ap.approver)} via {ap.method}, expires {_ts(ap.expires_at)}"
        )
        if ap.comment:
            lines.append(f"    comment: {_text(ap.comment)}")
    return "\n".join(lines)


def render_list(records: Sequence[PlanRecord]) -> str:
    rows = [("PLAN", "STATE", "EFFECT", "RISK", "ACTION", "SUMMARY")]
    for r in records:
        summary = _text(r.plan.summary)
        if len(summary) > 60:
            summary = summary[:57] + "..."
        rows.append(
            (
                short_hash(r.plan.plan_hash),
                str(r.state),
                str(r.effect),
                str(r.plan.risk.level),
                _text(r.plan.action.name),
                summary,
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    return "\n".join(
        "  ".join(cell.ljust(w) for cell, w in zip(row[:-1], widths, strict=True)) + "  " + row[-1]
        for row in rows
    )


# --- commands -------------------------------------------------------------------------


def _open_store(path: str) -> SqliteStore:
    if path != ":memory:" and not Path(path).is_file():
        raise CliError(f"no store at {path}")
    return SqliteStore(path)


def _approver(args: argparse.Namespace) -> Principal:
    approver_id = args.approver or os.environ.get("SEALEDPLAN_APPROVER")
    issuer = args.issuer or os.environ.get("SEALEDPLAN_ISSUER")
    if not approver_id or not issuer:
        raise CliError(
            "approver identity needed: --as and --issuer (or SEALEDPLAN_APPROVER/_ISSUER)"
        )
    return Principal(id=approver_id, issuer=issuer, kind="human")


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _cmd_list(store: SqliteStore, args: argparse.Namespace) -> int:
    states = None if args.all else [State(s) for s in args.state or [State.PENDING_APPROVAL]]
    records = store.list_plans(states)
    print(render_list(records) if records else "no plans")
    return 0


def _cmd_show(store: SqliteStore, args: argparse.Namespace) -> int:
    record = store.find(args.plan)
    if args.json:
        print(json.dumps(record.plan.to_obj(), ensure_ascii=True, sort_keys=True, indent=2))
    else:
        print(render_plan(record, store.approvals(record.plan.plan_hash)))
    return 0


def _decide(
    store: SqliteStore, args: argparse.Namespace, decision: str, clock: Callable[[], datetime]
) -> int:
    approver = _approver(args)
    record = store.find(args.plan)
    plan: Plan = record.plan
    print(render_plan(record, store.approvals(plan.plan_hash)))
    print()
    verb = "Approve" if decision == "approve" else "Reject"
    if not args.yes and not _confirm(f"{verb} plan {short_hash(plan.plan_hash)} as {approver.id}?"):
        print("nothing recorded")
        return 1
    # The person at the keyboard is the actor for the resulting state change.
    rt = Runtime(store, approver, clock=clock)
    now = rt.now()
    approval = Approval(
        approval_id=f"cli-{uuid.uuid4()}",
        plan_hash=plan.plan_hash,
        decision="approve" if decision == "approve" else "reject",
        approver=approver,
        method="cli",
        scope=ApprovalScope(),
        comment=args.comment,
        issued_at=now,
        expires_at=min(now + timedelta(minutes=args.minutes), plan.expires_at),
    )
    state = rt.submit_approval(approval, trusted_channel=True)
    print(f"recorded {decision} for {short_hash(plan.plan_hash)}: plan is now {state}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sealedplan", description=__doc__.splitlines()[0])
    parser.add_argument(
        "--db",
        default=os.environ.get("SEALEDPLAN_DB", DEFAULT_DB),
        help=f"store path (default: $SEALEDPLAN_DB or {DEFAULT_DB})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list plans (default: those awaiting approval)")
    p_list.add_argument("--state", action="append", choices=[str(s) for s in State])
    p_list.add_argument("--all", action="store_true", help="every plan, in any state")

    p_show = sub.add_parser("show", help="show a plan in full")
    p_show.add_argument("plan", help="plan hash or a unique prefix of it")
    p_show.add_argument("--json", action="store_true", help="print the plan as JSON")

    for name, help_text in (("approve", "approve a plan"), ("reject", "reject a plan")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("plan", help="plan hash or a unique prefix of it")
        p.add_argument("--as", dest="approver", help="approver id ($SEALEDPLAN_APPROVER)")
        p.add_argument("--issuer", help="approver's identity issuer ($SEALEDPLAN_ISSUER)")
        p.add_argument("--comment")
        p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
        p.add_argument(
            "--minutes",
            type=int,
            default=15,
            help="approval lifetime, capped at the plan's expiry (default: 15)",
        )
    return parser


def main(argv: Sequence[str] | None = None, *, clock: Callable[[], datetime] = utc_now) -> int:
    args = build_parser().parse_args(argv)
    try:
        store = _open_store(args.db)
        if args.command == "list":
            return _cmd_list(store, args)
        if args.command == "show":
            return _cmd_show(store, args)
        return _decide(store, args, args.command, clock)
    except (CliError, SealedPlanError, StoreError, PlanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
