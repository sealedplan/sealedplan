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

# The transition table of SPEC §7.2, including APPLYING -> DRIFTED (§8.4) and the
# restart rule for COMPENSATING.
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
