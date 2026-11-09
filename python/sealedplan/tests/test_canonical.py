from __future__ import annotations

import json
import random
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sealedplan.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    canonicalize,
    digest,
    loads_strict,
)

json_text = st.text(st.characters(codec="utf-8"))
json_values: st.SearchStrategy[Any] = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | json_text,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(json_text, children, max_size=5)
    ),
    max_leaves=25,
)


def _shuffled(value: Any, rng: random.Random) -> Any:
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {k: _shuffled(v, rng) for k, v in items}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


# --- known vectors -------------------------------------------------------------


def test_sorts_keys_and_drops_whitespace() -> None:
    assert canonicalize({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'


def test_sorts_keys_by_utf16_code_units_not_code_points() -> None:
    # U+1F600 is encoded as the surrogate pair D83D DE00, which sorts before U+FB01.
    value = {"\ufb01": 1, "\U0001f600": 2}
    expected = '{"\U0001f600":2,"\ufb01":1}'.encode()
    assert canonicalize(value) == expected


def test_string_escaping_matches_jcs() -> None:
    value = 'q"b\\n\n t\t c\u0007 del\u007f e\u00e9 ls\u2028'
    expected = '"q\\"b\\\\n\\n t\\t c\\u0007 del\u007f e\u00e9 ls\u2028"'.encode()
    assert canonicalize(value) == expected


def test_digest_format() -> None:
    d = digest({"a": 1})
    assert d.startswith("sha256:")
    assert len(d) == len("sha256:") + 64
    assert d == digest({"a": 1})


# --- rejected values -------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        1.0,
        float("nan"),
        MAX_SAFE_INTEGER + 1,
        -MAX_SAFE_INTEGER - 1,
        "\ud800",
        {"\udc00": 1},
        {1: "x"},
        {"a": {1, 2}},
        b"bytes",
    ],
)
def test_rejects_values_outside_spec(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_bool_is_not_an_integer() -> None:
    assert canonicalize([True, 1]) == b"[true,1]"


@pytest.mark.parametrize(
    "text",
    ['{"a":1,"a":2}', '{"a":1.0}', '{"a":NaN}', '{"a":Infinity}', "9007199254740992"],
)
def test_loads_strict_rejects(text: str) -> None:
    with pytest.raises(CanonicalizationError):
        loads_strict(text)


# --- properties --------------------------------------------------------------------


@given(json_values)
def test_round_trips_through_json(value: Any) -> None:
    assert json.loads(canonicalize(value)) == value


@given(json_values)
def test_is_idempotent(value: Any) -> None:
    once = canonicalize(value)
    assert canonicalize(loads_strict(once)) == once


@given(json_values, st.randoms(use_true_random=False))
def test_independent_of_key_insertion_order(value: Any, rng: random.Random) -> None:
    assert canonicalize(_shuffled(value, rng)) == canonicalize(value)


@given(json_values, json_values)
def test_distinct_values_have_distinct_digests(a: Any, b: Any) -> None:
    if a != b or type(a) is not type(b):
        # bool vs int: True == 1 in Python, but they are different JSON values.
        assert (digest(a) == digest(b)) == (canonicalize(a) == canonicalize(b))
