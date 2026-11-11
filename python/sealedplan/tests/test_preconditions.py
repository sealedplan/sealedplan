from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sealedplan.canonical import digest
from sealedplan.models import Precondition
from sealedplan.preconditions import (
    ABSENT,
    Observation,
    evaluate,
    fingerprint,
    projection,
    resolve_pointer,
)

DOC: dict[str, Any] = {"a": {"b/c": 1, "m~n": [10, 20]}, "": 5}


@pytest.mark.parametrize(
    ("pointer", "expected"),
    [("", DOC), ("/a/b~1c", 1), ("/a/m~0n/1", 20), ("/", 5)],
)
def test_resolve_pointer(pointer: str, expected: Any) -> None:
    assert resolve_pointer(DOC, pointer) == expected


@pytest.mark.parametrize("pointer", ["/x", "/a/m~0n/2", "/a/m~0n/01", "/a/m~0n/-"])
def test_missing_pointers_are_left_out(pointer: str) -> None:
    assert projection(DOC, [pointer]) == {}


def test_pointer_must_start_with_slash() -> None:
    with pytest.raises(ValueError, match="Pointer"):
        resolve_pointer(DOC, "a")


def _pre(kind: str, **kw: Any) -> Precondition:
    return Precondition.model_validate(
        {
            "id": "p",
            "resource": {"type": "t", "id": "x"},
            "kind": kind,
            "enforcement": "atomic",
            **kw,
        }
    )


def test_version() -> None:
    assert evaluate(_pre("version", expect="7"), Observation(True, "7")).holds
    result = evaluate(_pre("version", expect="7"), Observation(True, "8"))
    assert (result.holds, result.observed) == (False, "8")
    assert evaluate(_pre("version", expect="7"), ABSENT).observed == "absent"


def test_exists_and_absent() -> None:
    assert evaluate(_pre("exists"), Observation(True)).holds
    assert not evaluate(_pre("exists"), ABSENT).holds
    assert evaluate(_pre("absent"), ABSENT).holds
    assert not evaluate(_pre("absent"), Observation(True)).holds


def test_fingerprint() -> None:
    state = {"spec": {"replicas": 3}, "status": {"ready": 2}}
    expect = digest({"/spec/replicas": 3})
    pre = _pre("fingerprint", expect=expect, select=["/spec/replicas"])
    assert evaluate(pre, Observation(True, state=state)).holds
    assert not evaluate(pre, Observation(True, state={"spec": {"replicas": 4}})).holds


@given(st.integers(0, 100), st.dictionaries(st.text(min_size=1), st.integers()))
def test_fingerprint_ignores_unselected_fields(replicas: int, noise: dict[str, int]) -> None:
    base = {"spec": {"replicas": replicas}}
    noisy = {**base, "status": noise}
    assert fingerprint(base, ["/spec/replicas"]) == fingerprint(noisy, ["/spec/replicas"])


def test_snapshot() -> None:
    assert ABSENT.snapshot() == {"exists": False}
    snap = Observation(True, "3", {"a": 1}).snapshot()
    assert snap == {"exists": True, "version": "3", "fingerprint": digest({"a": 1})}
