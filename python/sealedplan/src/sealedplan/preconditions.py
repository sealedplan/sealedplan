"""Evaluating preconditions against observed resource state (SPEC §5.2.3, §8)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sealedplan.canonical import digest
from sealedplan.models import Precondition


@dataclass(frozen=True)
class Observation:
    """What a provider sees for one resource right now.

    ``version`` is the token a ``version`` precondition compares. ``state`` is the
    projection that ``fingerprint`` preconditions select from; providers should leave
    out fields that change on their own (status, timestamps) so they do not read as drift.
    """

    exists: bool
    version: str | None = None
    state: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        """Compact record kept in ``Applied.observed`` for the compensation check (§9.3)."""
        snap: dict[str, Any] = {"exists": self.exists}
        if self.version is not None:
            snap["version"] = self.version
        if self.state is not None:
            snap["fingerprint"] = digest(self.state)
        return snap


ABSENT = Observation(exists=False)


@dataclass(frozen=True)
class PreconditionResult:
    id: str
    holds: bool
    expected: str | None
    observed: str | None

    def to_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"id": self.id, "holds": self.holds}
        if self.expected is not None:
            obj["expected"] = self.expected
        if self.observed is not None:
            obj["observed"] = self.observed
        return obj


_MISSING = object()


def resolve_pointer(doc: Any, pointer: str) -> Any:
    """RFC 6901 lookup. Returns a private sentinel when the path does not exist."""
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        raise ValueError(f"not a JSON Pointer: {pointer!r}")
    node = doc
    for raw in pointer[1:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            if part != "0" and part.startswith("0"):
                return _MISSING
            node = node[int(part)]
        else:
            return _MISSING
    return node


def projection(state: dict[str, Any], select: list[str]) -> dict[str, Any]:
    """Object mapping each pointer to its value. Pointers that do not resolve are left out."""
    out: dict[str, Any] = {}
    for pointer in select:
        value = resolve_pointer(state, pointer)
        if value is not _MISSING:
            out[pointer] = value
    return out


def fingerprint(state: dict[str, Any], select: list[str]) -> str:
    return digest(projection(state, select))


def evaluate(pre: Precondition, obs: Observation) -> PreconditionResult:
    if pre.kind == "exists":
        return PreconditionResult(pre.id, obs.exists, "exists", _presence(obs))
    if pre.kind == "absent":
        return PreconditionResult(pre.id, not obs.exists, "absent", _presence(obs))
    if not obs.exists:
        return PreconditionResult(pre.id, False, pre.expect, "absent")
    if pre.kind == "version":
        return PreconditionResult(pre.id, obs.version == pre.expect, pre.expect, obs.version)
    assert pre.select is not None  # guaranteed by Precondition validation
    seen = fingerprint(obs.state or {}, pre.select)
    return PreconditionResult(pre.id, seen == pre.expect, pre.expect, seen)


def _presence(obs: Observation) -> str:
    return "exists" if obs.exists else "absent"
