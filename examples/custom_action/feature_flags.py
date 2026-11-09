"""Write your own action: feature flags, in one file.

An action is a class that knows one kind of change on one kind of system. It answers
four questions for the runtime:

- ``plan``: what would this change do? Read the system, change nothing, and describe
  the change: before/after, what must still be true to apply it (preconditions), and
  how to undo it (compensation).
- ``observe``: what does this resource look like right now? The runtime uses it to
  re-check preconditions just before applying, and to spot later edits before undoing.
- ``apply``: make exactly the planned change.
- ``compensate``: undo it.

The runtime does the rest: hashing the plan, asking policy whether a person must
approve, refusing to apply a plan that drifted, and keeping the record.

Run it::

    uv run python examples/custom_action/feature_flags.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from sealedplan.actions import Context, action
from sealedplan.models import (
    Applied,
    Approval,
    ApprovalScope,
    Change,
    Compensation,
    Effect,
    Plan,
    Precondition,
    Principal,
    ResourceRef,
)
from sealedplan.preconditions import ABSENT, Observation
from sealedplan.runtime import Runtime, WrongStateError
from sealedplan.store import SqliteStore

# --- the system the agent changes ----------------------------------------------------


@dataclass
class Flags:
    """A toy flag service. Every write bumps the flag's revision."""

    enabled: dict[str, bool] = field(default_factory=dict)
    revision: dict[str, int] = field(default_factory=dict)

    def set(self, name: str, on: bool) -> None:
        self.enabled[name] = on
        self.revision[name] = self.revision.get(name, 0) + 1


# --- the action ------------------------------------------------------------------------


@action(
    "flags.set",
    effect=Effect.REVERSIBLE,  # it can be undone exactly, so compensate() is required
    risk="low",  # the default; plan() can raise it for a particular change
    version="1.0.0",
    provider="example-flags",
)
class SetFlag:
    def __init__(self, flags: Flags) -> None:
        self.flags = flags

    def _ref(self, name: str) -> ResourceRef:
        return ResourceRef(type="example/flag", id=f"flag://{name}")

    def plan(self, ctx: Context, name: str, enabled: bool) -> Plan:
        if name not in self.flags.enabled:
            raise ValueError(f"no flag named {name}")
        current = self.flags.enabled[name]
        ref = self._ref(name)
        risky = name.startswith("payments.")
        return ctx.plan(
            summary=f"Turn {name} {'on' if enabled else 'off'}",
            changes=[
                Change(
                    resource=ref,
                    op="update",
                    before={"enabled": current},
                    after={"enabled": enabled},
                )
            ],
            preconditions=[
                # Apply only if nobody has touched the flag since this plan was made.
                # The flag service cannot enforce this itself, so the runtime checks it
                # just before apply ("check_then_act"). A database or API that supports
                # conditional writes would make it "atomic"; see the SQL action.
                Precondition(
                    id="flag-revision",
                    resource=ref,
                    kind="version",
                    expect=str(self.flags.revision[name]),
                    enforcement="check_then_act",
                )
            ],
            risk="high" if risky else None,
            risk_reasons=["payments flags change how customers are charged"] if risky else None,
            compensation=Compensation(
                strategy="restore",
                summary=f"Turn {name} back {'on' if current else 'off'}",
                params={"enabled": current},
            ),
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        name = resource.id.removeprefix("flag://")
        if name not in self.flags.enabled:
            return ABSENT
        return Observation(
            exists=True,
            version=str(self.flags.revision[name]),
            state={"enabled": self.flags.enabled[name]},
        )

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        self.flags.set(plan.params["name"], plan.params["enabled"])
        return ctx.applied(plan)

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        self.flags.set(plan.params["name"], plan.compensation.params["enabled"])


# --- using it ----------------------------------------------------------------------------

ISSUER = "https://idp.example.com"
AGENT = Principal(id="release-agent", issuer=ISSUER, kind="agent")
RUNTIME = Principal(id="release-runtime", issuer=ISSUER, kind="service")
DANA = Principal(id="dana", issuer=ISSUER, kind="human")


def approve(rt: Runtime, plan: Plan, who: Principal) -> None:
    """What an approval is: a person's decision bound to one plan hash, for a short time.

    This is the record ``sealedplan approve`` writes. Approvals arriving from outside the
    process (a chat bot, a web page) should be signed and submitted with
    ``trusted_channel=False`` so the runtime verifies the signature.
    """
    now = rt.now()
    state = rt.submit_approval(
        Approval(
            approval_id=f"appr-{uuid.uuid4()}",
            plan_hash=plan.plan_hash,
            decision="approve",
            approver=who,
            method="cli",
            scope=ApprovalScope(),
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
        )
    )
    print(f"  {who.id} approved: {state}")


def main() -> None:
    flags = Flags()
    for name in ("checkout.new_banner", "payments.new_provider"):
        flags.set(name, False)

    rt = Runtime(SqliteStore(), RUNTIME)  # an in-memory store; pass a path to keep it
    rt.register(SetFlag(flags))

    def propose(name: str, enabled: bool) -> Plan:
        p = rt.propose(
            "flags.set",
            {"name": name, "enabled": enabled},
            agent=AGENT,
            idempotency_key=f"{name}-{uuid.uuid4()}",
        )
        print(f"proposed: {p.plan.summary} -> {p.state} (policy: {p.decision.decision})")
        return p.plan

    print("\n1. Low risk and reversible: policy approves it without a person")
    banner = propose("checkout.new_banner", True)
    print(f"  execute: {rt.execute(banner.plan_hash).state}")
    print(f"  flags: {flags.enabled}")

    print("\n2. High risk: it waits for a person")
    payments = propose("payments.new_provider", True)
    try:
        rt.execute(payments.plan_hash)
    except WrongStateError as exc:
        print(f"  execute before approval: refused ({exc})")
    approve(rt, payments, DANA)

    print("\n3. Someone flips the flag before the agent gets to it")
    flags.set("payments.new_provider", True)
    result = rt.execute(payments.plan_hash)
    print(f"  execute: {result.state}")
    for d in result.drift:
        print(f"  {d.id}: approved at revision {d.expected}, now {d.observed}")

    print("\n4. Undo the banner change")
    print(f"  compensate: {rt.compensate(banner.plan_hash).outcome}")
    print(f"  flags: {flags.enabled}")


if __name__ == "__main__":
    main()
