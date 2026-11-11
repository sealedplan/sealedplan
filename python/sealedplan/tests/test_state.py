from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sealedplan.state import (
    IN_FLIGHT,
    TERMINAL,
    TRANSITIONS,
    InvalidTransitionError,
    State,
    can_transition,
    check_transition,
)

states = st.sampled_from(list(State))


def _reachable(start: State) -> set[State]:
    seen, todo = {start}, [start]
    while todo:
        for nxt in TRANSITIONS.get(todo.pop(), frozenset()):
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return seen


def test_terminal_states_match_spec() -> None:
    assert {
        State.DENIED,
        State.REJECTED,
        State.EXPIRED,
        State.DRIFTED,
        State.FAILED,
        State.COMPENSATED,
        State.COMPENSATION_FAILED,
    } == TERMINAL


def test_every_state_is_reachable_from_planned() -> None:
    assert _reachable(State.PLANNED) == set(State)


def test_every_state_can_reach_a_terminal_state() -> None:
    for state in State:
        assert (_reachable(state) & TERMINAL) or state is State.APPLIED


def test_apply_happens_only_after_approval() -> None:
    sources = {s for s, targets in TRANSITIONS.items() if State.APPLYING in targets}
    assert sources == {State.APPROVED}


def test_in_flight_states_can_end() -> None:
    assert all(TRANSITIONS[s] for s in IN_FLIGHT)


@given(states, states)
def test_check_transition_agrees_with_table(src: State, dst: State) -> None:
    if dst in TRANSITIONS.get(src, frozenset()):
        check_transition(src, dst)
    else:
        with pytest.raises(InvalidTransitionError):
            check_transition(src, dst)


@given(st.lists(states, max_size=30))
def test_random_walks_only_follow_the_table(choices: list[State]) -> None:
    # Follow each choice when it is allowed; the walk must never leave a terminal state.
    state = State.PLANNED
    for wanted in choices:
        if can_transition(state, wanted):
            assert state not in TERMINAL
            state = wanted
    assert state in _reachable(State.PLANNED)


@given(states)
def test_no_transition_leads_back_to_planned(src: State) -> None:
    assert not can_transition(src, State.PLANNED)
