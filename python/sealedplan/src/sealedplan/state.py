"""Plan state machine (SPEC §7)."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum


class State(StrEnum):
    PLANNED = "PLANNED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    DRIFTED = "DRIFTED"
    APPLYING = "APPLYING"
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    COMPENSATING = "COMPENSATING"
    COMPENSATED = "COMPENSATED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"


S = State

# §7.2, plus APPLYING -> DRIFTED, which §8.4 requires (the target system rejected an
# atomic precondition) but the table omits.
#
# A restart that finds COMPENSATING records COMPENSATION_FAILED (outcome "unknown") and
# escalates to a human. §7.2's prose says UNKNOWN, but UNKNOWN only reconciles to APPLIED
# or FAILED, which would lose the fact that compensation had started.
TRANSITIONS: Mapping[State, frozenset[State]] = {
    S.PLANNED: frozenset({S.APPROVED, S.PENDING_APPROVAL, S.DENIED}),
    S.PENDING_APPROVAL: frozenset({S.APPROVED, S.REJECTED, S.EXPIRED}),
    S.APPROVED: frozenset({S.EXPIRED, S.DRIFTED, S.APPLYING}),
    S.APPLYING: frozenset({S.APPLIED, S.FAILED, S.UNKNOWN, S.DRIFTED}),
    S.UNKNOWN: frozenset({S.APPLIED, S.FAILED}),
    S.APPLIED: frozenset({S.COMPENSATING}),
    S.COMPENSATING: frozenset({S.COMPENSATED, S.COMPENSATION_FAILED}),
}

TERMINAL: frozenset[State] = frozenset(s for s in State if not TRANSITIONS.get(s))

# States a restarted runtime must not leave as they are (§7.2).
IN_FLIGHT: frozenset[State] = frozenset({S.APPLYING, S.COMPENSATING})


class InvalidTransitionError(Exception):
    def __init__(self, src: State, dst: State) -> None:
        super().__init__(f"transition {src} -> {dst} is not allowed (§7.2)")
        self.src = src
        self.dst = dst


def can_transition(src: State, dst: State) -> bool:
    return dst in TRANSITIONS.get(src, frozenset())


def check_transition(src: State, dst: State) -> None:
    if not can_transition(src, dst):
        raise InvalidTransitionError(src, dst)
