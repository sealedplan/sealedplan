"""Canonical JSON and digests (SPEC §6).

Implements RFC 8785 (JCS) for the value set that SPEC §6.2 allows: null, booleans,
integers within ±(2**53 - 1), valid Unicode strings, arrays and objects. Floats are
rejected rather than canonicalized, so the hard part of JCS (ECMAScript number
formatting) is never needed and every implementation agrees byte for byte.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
DIGEST_PREFIX = "sha256:"


class CanonicalizationError(ValueError):
    """The value is outside the set SPEC §6.2 allows."""


def canonicalize(value: object) -> bytes:
    """Return the canonical UTF-8 bytes of ``value``."""
    return _serialize(value, "$").encode("utf-8")


def digest(value: object) -> str:
    """Return ``sha256:<lowercase hex>`` over the canonical form of ``value``."""
    return digest_bytes(canonicalize(value))


def digest_bytes(data: bytes) -> str:
    """Return ``sha256:<lowercase hex>`` over raw bytes (evidence, policy sources)."""
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def loads_strict(text: str | bytes) -> Any:
    """Parse JSON, rejecting duplicate keys, non-integer numbers and NaN/Infinity."""

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, val in pairs:
            if key in out:
                raise CanonicalizationError(f"duplicate object key {key!r}")
            out[key] = val
        return out

    def no_float(token: str) -> Any:
        raise CanonicalizationError(f"non-integer number {token!r} is not allowed")

    value = json.loads(
        text,
        object_pairs_hook=no_duplicates,
        parse_float=no_float,
        parse_constant=no_float,
    )
    canonicalize(value)  # enforce integer range and string validity
    return value


def _utf16_key(key: str) -> bytes:
    # RFC 8785 §3.2.3: object members are sorted by their UTF-16 code units.
    return key.encode("utf-16-be")


def _check_string(value: str, path: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{path}: string is not valid Unicode") from exc


def _serialize(value: object, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"{path}: integer {value} is outside ±(2**53 - 1); encode it as a string"
            )
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: non-integer numbers must be encoded as strings")
    if isinstance(value, str):
        _check_string(value, path)
        # Python's escaping matches ECMAScript JSON.stringify for valid Unicode:
        # \" \\ \b \f \n \r \t, other C0 controls as lowercase \u00xx, nothing else.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list | tuple):
        return "[" + ",".join(_serialize(v, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    if isinstance(value, dict):
        items: list[tuple[str, object]] = []
        for key, val in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check_string(key, path)
            items.append((key, val))
        items.sort(key=lambda kv: _utf16_key(kv[0]))
        members = (
            json.dumps(k, ensure_ascii=False) + ":" + _serialize(v, f"{path}.{k}") for k, v in items
        )
        return "{" + ",".join(members) + "}"
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")
