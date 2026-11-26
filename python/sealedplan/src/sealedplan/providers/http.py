"""Reference action: replace a JSON document over HTTP, guarded by ``ETag`` / ``If-Match``.

``http.put_json`` reads the document with ``GET``, plans a ``PUT`` of the new body, and
records the ``ETag`` as a ``version`` precondition. ``apply`` sends ``If-Match`` with that
``ETag``, so an API that honours it answers 412 when the document changed after approval,
and nothing is written.

Limits, stated plainly:

- **Atomic only where the API enforces ``If-Match``.** Many APIs return an ``ETag`` but
  ignore ``If-Match`` on writes. The action cannot tell, so preconditions are
  ``check_then_act`` unless the operator says ``atomic=True`` for an API they know
  enforces it (RFC 9110 §13.1.1).
- **Updates only.** A document that does not exist yet cannot be planned. Undoing a
  create needs a ``DELETE`` the API may not allow, or may treat as more than the
  inverse.
- **COMPENSATABLE, not REVERSIBLE.** Compensation ``PUT``s the previous body back, with
  ``If-Match`` on the current ``ETag``. Fields the server computes (timestamps,
  revision counters) and side effects of the first write (webhooks, emails) are not
  restored.
- **Bodies go into the plan.** ``before`` and ``after`` are the full documents, shown to
  approvers and stored (SPEC §11.6). Do not use it for documents that hold secrets.

Requests are confined to ``base_url``: the agent supplies a path, never a host.
Credentials (an ``Authorization`` header, say) are given to the action, never put in a
plan. The default transport uses ``urllib`` from the standard library and does not
follow redirects.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from sealedplan.actions import (
    ApplyFailedError,
    CompensationConflictError,
    Context,
    PreconditionFailedError,
    action,
)
from sealedplan.models import (
    Applied,
    BlastRadius,
    Change,
    Compensation,
    Effect,
    Plan,
    Precondition,
    ResourceRef,
)
from sealedplan.preconditions import ABSENT, Observation, PreconditionResult
from sealedplan.state import State

__all__ = ["HttpStatusError", "PutJson", "Response", "Transport", "UrllibTransport"]

RESOURCE_TYPE = "http/json"
PRECONDITION_ID = "etag"

# The server refused the request, so nothing changed. Any other status (5xx, 3xx) or a
# lost response may come after the write was committed and leaves the plan UNKNOWN.
_REJECTED = frozenset({400, 401, 403, 405, 409, 413, 415, 422, 428, 429})
_GONE = frozenset({404, 410})
_OK = frozenset({200, 201, 204})
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_RESERVED = frozenset({"if-match", "if-none-match", "content-type", "host", "content-length"})


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)  # names in lower case
    body: bytes = b""


class Transport(Protocol):
    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        """Send one request and return the response, whatever its status. Raise only
        when there is no response (timeout, connection reset)."""
        ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a 3xx comes back as a response, not a request to another URL


class UrllibTransport:
    """A :class:`Transport` on ``urllib.request``. Redirects are not followed."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        if urlsplit(url).scheme not in ("http", "https"):
            raise ValueError(f"only http(s) URLs: {url!r}")
        # The scheme is checked above, so file: and custom schemes never reach urllib.
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers=dict(headers), method=method
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as reply:
                return Response(reply.status, _lower(reply.headers.items()), reply.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(exc.code, _lower(exc.headers.items()), exc.read())


def _lower(items: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in items}


class HttpStatusError(Exception):
    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(f"HTTP {status} {message}".strip())
        self.status = status


@dataclass(frozen=True)
class _Doc:
    etag: str | None
    body: dict[str, Any]


def _subset(want: Mapping[str, Any], got: Mapping[str, Any]) -> bool:
    """Every field of ``want`` is in ``got`` with the same value; extra fields are fine."""
    for k, v in want.items():
        if k not in got:
            return False
        if isinstance(v, Mapping) and isinstance(got[k], Mapping):
            if not _subset(v, got[k]):
                return False
        elif v != got[k]:
            return False
    return True


@action(
    "http.put_json",
    effect=Effect.COMPENSATABLE,
    risk="medium",
    version="1.0.0",
    provider="sealedplan-http",
)
class PutJson:
    """Replace the JSON document at ``base_url + path`` with ``body``.

    ``headers`` are sent on every request (for example ``Authorization``); they are not
    part of any plan. Set ``atomic=True`` only for an API that refuses a write with 412
    when ``If-Match`` does not match.
    """

    def __init__(
        self,
        base_url: str,
        *,
        transport: Transport | None = None,
        headers: Mapping[str, str] | None = None,
        atomic: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"base_url must be an http(s) URL: {base_url!r}")
        if parts.query or parts.fragment:
            raise ValueError("base_url must not have a query or fragment")
        reserved = _RESERVED & {h.lower() for h in headers or {}}
        if reserved:
            raise ValueError(f"headers set by the action itself: {sorted(reserved)}")
        self.base_url = base_url.rstrip("/")
        self.transport = transport or UrllibTransport()
        self.headers = dict(headers or {})
        self.atomic = atomic

    # --- helpers ----------------------------------------------------------------------

    def _url(self, path: str) -> str:
        if not isinstance(path, str) or not _PATH.match(path) or path.startswith("//"):
            raise ValueError(f"path must be an absolute path with no query: {path!r}")
        if any(seg in (".", "..") for seg in path.split("/")):
            raise ValueError(f"path must not contain . or .. segments: {path!r}")
        return self.base_url + path

    def _path(self, resource: ResourceRef) -> str:
        if resource.type != RESOURCE_TYPE or not resource.id.startswith(self.base_url + "/"):
            raise ValueError(f"not a document under {self.base_url}: {resource.id}")
        return resource.id.removeprefix(self.base_url)

    def _send(self, method: str, url: str, body: bytes | None = None, **extra: str) -> Response:
        headers = {**self.headers, "Accept": "application/json", **extra}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self.transport(method, url, headers, body)

    def _get(self, url: str) -> _Doc | None:
        reply = self._send("GET", url)
        if reply.status in _GONE:
            return None
        if reply.status != 200:
            raise HttpStatusError(reply.status, f"GET {url}")
        try:
            body = json.loads(reply.body)
        except ValueError as exc:
            raise ValueError(f"GET {url} did not return JSON") from exc
        if not isinstance(body, dict):
            raise ValueError(f"GET {url} did not return a JSON object")
        return _Doc(reply.headers.get("etag"), body)

    @staticmethod
    def _encode(body: Mapping[str, Any]) -> bytes:
        return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()

    @staticmethod
    def _precondition(plan: Plan) -> Precondition:
        return next(p for p in plan.preconditions if p.id == PRECONDITION_ID)

    # --- the action -------------------------------------------------------------------

    def plan(self, ctx: Context, path: str, body: dict[str, Any]) -> Plan:
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        url = self._url(path)
        current = self._get(url)
        if current is None:
            raise ValueError(f"{url} not found; http.put_json only replaces documents")
        if not current.etag or current.etag.startswith("W/"):
            raise ValueError(f"{url} has no strong ETag, so the write cannot be guarded")
        ref = ResourceRef(type=RESOURCE_TYPE, id=url)
        fields = sorted(set(current.body) | set(body))
        touched = [k for k in fields if current.body.get(k, ...) != body.get(k, ...)]
        what = ", ".join(touched) if touched else "nothing"
        return ctx.plan(
            summary=f"Replace the JSON document at {url}; changes: {what}",
            changes=[Change(resource=ref, op="update", before=current.body, after=body)],
            preconditions=[
                Precondition(
                    id=PRECONDITION_ID,
                    resource=ref,
                    kind="version",
                    expect=current.etag,
                    enforcement="atomic" if self.atomic else "check_then_act",
                )
            ],
            blast_radius=BlastRadius(resources=1, scopes=[self.base_url]),
            compensation=Compensation(
                strategy="semantic",
                summary=f"PUT the previous document back to {url}. Fields the server "
                "computes and side effects of the write are not restored.",
                params={"body": current.body},
            ),
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        doc = self._get(self._url(self._path(resource)))
        if doc is None:
            return ABSENT
        return Observation(True, doc.etag, doc.body)

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        url = self._url(plan.params["path"])
        pre = self._precondition(plan)

        def drifted(observed: str | None) -> PreconditionFailedError:
            return PreconditionFailedError(
                [PreconditionResult(pre.id, False, pre.expect, observed)]
            )

        current = self._get(url)
        if current is None:
            raise drifted("absent")
        if current.etag != pre.expect:
            raise drifted(current.etag)
        assert pre.expect is not None
        reply = self._send(
            "PUT", url, self._encode(plan.params["body"]), **{"If-Match": pre.expect}
        )
        if reply.status == 412:
            raise drifted("changed during apply")
        if reply.status in _GONE:
            raise drifted("absent")
        if reply.status in _REJECTED:
            raise ApplyFailedError(f"PUT {url}: HTTP {reply.status}")
        if reply.status not in _OK:
            raise HttpStatusError(reply.status, f"PUT {url}")
        return ctx.applied(plan, result={"status": reply.status, "etag": reply.headers.get("etag")})

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        url = self._url(plan.params["path"])
        current = self._get(url)
        if current is None:
            raise CompensationConflictError(f"{url} no longer exists")
        if not current.etag:
            raise CompensationConflictError(f"{url} has no ETag to guard the restore")
        previous = plan.compensation.params["body"]
        reply = self._send("PUT", url, self._encode(previous), **{"If-Match": current.etag})
        if reply.status == 412:
            raise CompensationConflictError(f"{url} changed during compensation")
        if reply.status not in _OK:
            raise HttpStatusError(reply.status, f"PUT {url}")

    def reconcile(self, ctx: Context, plan: Plan, applied: Applied | None) -> State:
        """Decide an UNKNOWN apply from the document as it is now."""
        current = self._get(self._url(plan.params["path"]))
        if current is None:
            return State.UNKNOWN
        if _subset(plan.params["body"], current.body):
            return State.APPLIED  # the document holds what we wrote
        if current.etag == self._precondition(plan).expect:
            return State.FAILED  # untouched since the plan, so the write never landed
        return State.UNKNOWN  # someone else changed it; a human decides
