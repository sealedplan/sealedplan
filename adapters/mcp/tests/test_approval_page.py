"""The approval page, alone and reached from the MCP server through URL-mode elicitation."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from mcp.client import Client
from mcp_types import ElicitRequestParams, ElicitRequestURLParams, ElicitResult
from starlette.requests import Request
from starlette.testclient import TestClient

from sealedplan.actions import Context, action
from sealedplan.models import (
    Applied,
    Change,
    Effect,
    Plan,
    Precondition,
    Principal,
    ResourceRef,
)
from sealedplan.preconditions import ABSENT, Observation
from sealedplan.runtime import Runtime
from sealedplan.state import State
from sealedplan.store import SqliteStore
from sealedplan_mcp import EXTENSION_ID, create_server
from sealedplan_mcp.approval_page import approval_app

ISSUER = "https://idp.example.com"
AGENT = Principal(id="agent", issuer=ISSUER, kind="agent")
SERVICE = Principal(id="runtime", issuer=ISSUER, kind="service")
BASE = "https://approve.example.com"
PEOPLE = {
    "dana": Principal(id="dana", issuer=ISSUER, kind="human"),
    "erin": Principal(id="erin", issuer=ISSUER, kind="human"),
    "bot": Principal(id="bot", issuer=ISSUER, kind="service"),
}


@dataclass
class Notes:
    text: dict[str, str] = field(default_factory=lambda: {"motd": "hello", "payroll": "off"})


@action("notes.set", effect=Effect.IRREVERSIBLE, risk="medium")
class SetNote:
    """Replace a note."""

    def __init__(self, notes: Notes) -> None:
        self.notes = notes

    def plan(self, ctx: Context, name: str, text: str) -> Plan:
        ref = ResourceRef(type="example/note", id=f"note://{name}")
        return ctx.plan(
            summary=f"Set {name} to {text}",
            changes=[Change(resource=ref, op="update", after={"text": text})],
            preconditions=[
                Precondition(
                    id="note-text",
                    resource=ref,
                    kind="version",
                    expect=self.notes.text[name],
                    enforcement="check_then_act",
                )
            ],
            risk="high" if name == "payroll" else None,  # two people must approve
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        name = resource.id.removeprefix("note://")
        if name not in self.notes.text:
            return ABSENT
        return Observation(exists=True, version=self.notes.text[name])

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        self.notes.text[plan.params["name"]] = plan.params["text"]
        return ctx.applied(plan)


def header_identity(request: Request) -> Principal | None:
    """Test stand-in for a proxy-verified identity header."""
    return PEOPLE.get(request.headers.get("x-test-user", ""))


@pytest.fixture
def notes() -> Notes:
    return Notes()


@pytest.fixture
def rt(notes: Notes) -> Iterator[Runtime]:
    runtime = Runtime(SqliteStore(), SERVICE)
    runtime.register(SetNote(notes))
    yield runtime
    runtime.store.close()


@pytest.fixture
def web(rt: Runtime) -> TestClient:
    return TestClient(approval_app(rt, authenticate=header_identity), base_url=BASE)


def propose(rt: Runtime, text: str = "<script>alert(1)</script>", name: str = "motd") -> str:
    proposal = rt.propose(
        "notes.set", {"name": name, "text": text}, agent=AGENT, idempotency_key=name + text
    )
    return proposal.plan.plan_hash


def form_token(page: str) -> str:
    found = re.search(r'name=token value="([0-9a-f]+)"', page)
    assert found is not None, page
    return found.group(1)


def decide(web: TestClient, plan_hash: str, user: str, decision: str) -> Any:
    page = web.get(f"/plans/{plan_hash}", headers={"x-test-user": user})
    body = {"plan_hash": plan_hash, "token": form_token(page.text), "decision": decision}
    return web.post(
        f"/plans/{plan_hash}", data=body, headers={"x-test-user": user}, follow_redirects=False
    )


def test_page_needs_a_signed_in_person(web: TestClient, rt: Runtime) -> None:
    plan_hash = propose(rt)
    assert web.get(f"/plans/{plan_hash}").status_code == 401
    assert web.get(f"/plans/{plan_hash}", headers={"x-test-user": "bot"}).status_code == 403
    assert web.get("/plans/sha256:" + "0" * 64, headers={"x-test-user": "dana"}).status_code == 404


def test_page_shows_the_verified_plan_escaped(web: TestClient, rt: Runtime) -> None:
    plan_hash = propose(rt)
    page = web.get(f"/plans/{plan_hash}", headers={"x-test-user": "dana"})
    assert page.status_code == 200
    assert plan_hash in page.text
    assert "NOT ATOMIC" in page.text
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"


def test_approve_on_the_page_records_a_url_approval(web: TestClient, rt: Runtime) -> None:
    plan_hash = propose(rt)
    done = decide(web, plan_hash, "dana", "approve")
    assert done.status_code == 303
    assert rt.store.get(plan_hash).state is State.APPROVED
    (approval,) = rt.store.approvals(plan_hash)
    assert approval.method == "url"
    assert approval.approver.id == "dana"
    after = web.get(f"/plans/{plan_hash}", headers={"x-test-user": "dana"})
    assert "nothing to do" in after.text
    assert "name=token" not in after.text


def test_two_people_approve_on_the_page(web: TestClient, rt: Runtime) -> None:
    plan_hash = propose(rt, "on", name="payroll")
    assert decide(web, plan_hash, "dana", "approve").status_code == 303
    assert rt.store.get(plan_hash).state is State.PENDING_APPROVAL
    assert decide(web, plan_hash, "erin", "approve").status_code == 303
    assert rt.store.get(plan_hash).state is State.APPROVED


def test_reject_on_the_page(web: TestClient, rt: Runtime) -> None:
    plan_hash = propose(rt)
    decide(web, plan_hash, "dana", "reject")
    assert rt.store.get(plan_hash).state is State.REJECTED


def test_form_token_is_bound_to_the_person_and_the_plan(web: TestClient, rt: Runtime) -> None:
    plan_hash, other = propose(rt), propose(rt, "bye")
    page = web.get(f"/plans/{plan_hash}", headers={"x-test-user": "dana"})
    token = form_token(page.text)

    def post(path_hash: str, user: str, **extra: str) -> int:
        body = {"plan_hash": path_hash, "token": token, "decision": "approve", **extra}
        response = web.post(
            f"/plans/{path_hash}", data=body, headers={"x-test-user": user}, follow_redirects=False
        )
        return response.status_code

    assert post(plan_hash, "erin") == 403  # dana's form, submitted as erin
    assert post(other, "dana") == 403  # dana's form for another plan
    assert post(plan_hash, "dana", decision="maybe") == 400
    assert rt.store.get(plan_hash).state is State.PENDING_APPROVAL
    assert rt.store.get(other).state is State.PENDING_APPROVAL


def test_deciding_twice_is_refused(web: TestClient, rt: Runtime) -> None:
    plan_hash = propose(rt)
    page = web.get(f"/plans/{plan_hash}", headers={"x-test-user": "dana"})
    body = {"plan_hash": plan_hash, "token": form_token(page.text), "decision": "approve"}
    headers = {"x-test-user": "dana"}
    path = f"/plans/{plan_hash}"
    assert web.post(path, data=body, headers=headers, follow_redirects=False).status_code == 303
    again = web.post(path, data=body, headers=headers, follow_redirects=False)
    assert again.status_code == 409
    assert "Not recorded" in again.text


@pytest.mark.anyio
async def test_mcp_client_is_sent_to_the_page_and_the_retry_applies(
    rt: Runtime, notes: Notes, web: TestClient
) -> None:
    prompts: list[ElicitRequestParams] = []

    async def person(context: Any, params: ElicitRequestParams) -> ElicitResult:
        prompts.append(params)
        if len(prompts) == 1:  # the person opens the link, signs in and approves
            assert isinstance(params, ElicitRequestURLParams)
            plan_hash = params.url.removeprefix(f"{BASE}/plans/")
            assert decide(web, plan_hash, "dana", "approve").status_code == 303
        return ElicitResult(action="accept")  # only means "I opened the page"

    server = create_server(rt, agent=AGENT, approval_url=BASE + "/plans/{plan_hash}")
    async with Client(server, elicitation_callback=person) as client:
        caps = client.server_capabilities
        assert caps is not None
        assert caps.extensions is not None
        assert "url" in caps.extensions[EXTENSION_ID]["approval_modes"]
        result = await client.call_tool("notes_set", {"name": "motd", "text": "hi"})

    assert not result.is_error
    assert notes.text["motd"] == "hi"
    assert len(prompts) == 1


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
