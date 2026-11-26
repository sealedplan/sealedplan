"""A web page where a person approves or rejects one plan (SPEC §12.4, URL mode).

:func:`approval_app` returns a Starlette app with one route, ``/plans/{plan_hash}``.
``GET`` shows the plan as the ``sealedplan show`` command prints it, from the stored,
hash-verified plan (§11.5). ``POST`` records the person's decision in the runtime's store.

The page never decides who the person is. ``authenticate`` does: it receives the request
and returns the approver, or ``None`` to refuse. Put the page behind your identity
provider (for example a reverse proxy that sets a verified header) and read the identity
there. Only people (``kind="human"``) may decide.

Forms carry a token bound to the approver and the plan, so another site cannot submit a
decision in the person's name.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import uuid
from collections.abc import Callable
from datetime import timedelta
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from sealedplan.cli import render_plan
from sealedplan.models import Approval, ApprovalScope, Principal
from sealedplan.runtime import Runtime, SealedPlanError
from sealedplan.state import State
from sealedplan.store import StoreError

from .server import runtime_lock

__all__ = ["Authenticate", "approval_app"]

Authenticate = Callable[[Request], Principal | None]
"""Return the authenticated approver for a request, or ``None`` to refuse it."""

_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

_STYLE = """
body { font: 15px/1.5 system-ui, sans-serif; max-width: 60rem; margin: 2rem auto;
       padding: 0 1rem; color: #1a1a1a; background: #fff; }
pre { background: #f4f4f4; padding: 1rem; overflow-x: auto; white-space: pre-wrap; }
.note { color: #555; }
.error { color: #a00; font-weight: 600; }
button { font: inherit; padding: .4rem 1.2rem; margin-right: .5rem; }
textarea { width: 100%; font: inherit; }
"""


def approval_app(
    runtime: Runtime,
    *,
    authenticate: Authenticate,
    secret: bytes | None = None,
    approval_ttl: timedelta = timedelta(minutes=10),
) -> Starlette:
    """A Starlette app serving ``/plans/{plan_hash}`` for ``runtime``'s plans.

    ``secret`` keys the form tokens. Without it, a random key is made, and forms stop
    working when the process restarts; pass a fixed secret when you run several
    replicas. ``approval_ttl`` bounds how long an approval stays usable; it never
    outlives the plan.
    """
    key = secret or secrets.token_bytes(32)
    lock = runtime_lock(runtime)

    def token(approver: Principal, plan_hash: str) -> str:
        message = "\n".join((approver.issuer, approver.id, plan_hash)).encode()
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def page(title: str, body: str, status: int = 200) -> HTMLResponse:
        doc = (
            "<!doctype html><html lang=en><head><meta charset=utf-8>"
            '<meta name=viewport content="width=device-width, initial-scale=1">'
            f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
            f"<body>{body}</body></html>"
        )
        return HTMLResponse(doc, status_code=status, headers=_HEADERS)

    def refuse(status: int, message: str) -> HTMLResponse:
        return page("sealedplan", f"<p class=error>{html.escape(message)}</p>", status)

    def who(request: Request) -> Principal | HTMLResponse:
        approver = authenticate(request)
        if approver is None:
            return refuse(401, "Sign in to review this plan.")
        if approver.kind != "human":
            return refuse(403, "Only people can approve plans.")
        return approver

    async def show(request: Request) -> Response:
        approver = who(request)
        if isinstance(approver, HTMLResponse):
            return approver
        plan_hash = request.path_params["plan_hash"]
        with lock:
            try:
                record = runtime.store.get(plan_hash)
            except StoreError:
                return refuse(404, "No such plan.")
            approvals = runtime.store.approvals(plan_hash)
        parts = [
            f"<h1>Review plan {html.escape(plan_hash.removeprefix('sha256:')[:12])}</h1>",
            "<p class=note>Check the changes, preconditions and compensation below. The "
            "summary and risk reasons are the provider's words and are not verified.</p>",
            f"<pre>{html.escape(render_plan(record, approvals))}</pre>",
        ]
        if record.state is State.PENDING_APPROVAL:
            parts.append(
                f'<form method=post action="{html.escape(request.url.path)}">'
                f'<input type=hidden name=plan_hash value="{html.escape(plan_hash)}">'
                f'<input type=hidden name=token value="{token(approver, plan_hash)}">'
                "<p><label>Comment (optional)<br><textarea name=comment rows=2>"
                "</textarea></label></p>"
                f"<p class=note>Deciding as {html.escape(approver.id)} "
                f"({html.escape(approver.issuer)}).</p>"
                "<button name=decision value=approve>Approve</button>"
                "<button name=decision value=reject>Reject</button></form>"
            )
        else:
            parts.append(f"<p>This plan is {html.escape(str(record.state))}; nothing to do.</p>")
        return page(f"Plan {plan_hash[:19]}", "".join(parts))

    async def decide(request: Request) -> Response:
        approver = who(request)
        if isinstance(approver, HTMLResponse):
            return approver
        plan_hash = request.path_params["plan_hash"]
        form = parse_qs((await request.body()).decode("utf-8", "replace"))

        def one(name: str) -> str:
            values = form.get(name, [])
            return values[0] if len(values) == 1 else ""

        decision = one("decision")
        if one("plan_hash") != plan_hash or not hmac.compare_digest(
            one("token"), token(approver, plan_hash)
        ):
            return refuse(403, "This form is stale or was not issued to you. Reload the plan.")
        if decision not in ("approve", "reject"):
            return refuse(400, "Choose approve or reject.")
        with lock:
            try:
                plan = runtime.store.get(plan_hash).plan
                now = runtime.now()
                runtime.submit_approval(
                    Approval(
                        approval_id=f"url-{uuid.uuid4()}",
                        plan_hash=plan_hash,
                        decision="approve" if decision == "approve" else "reject",
                        approver=approver,
                        method="url",
                        scope=ApprovalScope(),
                        comment=one("comment") or None,
                        issued_at=now,
                        expires_at=min(now + approval_ttl, plan.expires_at),
                    ),
                    trusted_channel=True,
                )
            except StoreError:
                return refuse(404, "No such plan.")
            except (SealedPlanError, ValueError) as exc:
                return refuse(409, f"Not recorded: {exc}")
        return RedirectResponse(request.url.path, status_code=303, headers=_HEADERS)

    return Starlette(
        routes=[
            Route("/plans/{plan_hash}", show, methods=["GET"]),
            Route("/plans/{plan_hash}", decide, methods=["POST"]),
        ]
    )
