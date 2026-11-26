from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest

from conftest import T0
from sealedplan.models import Plan
from sealedplan.providers.http import PutJson, Response, UrllibTransport
from sealedplan.runtime import Runtime
from sealedplan.state import State
from sealedplan.store import SqliteStore
from test_runtime import AGENT, ALICE, BOB, RUNTIME, Clock, approval

BASE = "https://api.example.com/v1"
PATH = "/flags/checkout"
URL = BASE + PATH
DOC = {"enabled": False, "rollout": 0, "owner": "payments"}


@dataclass
class FakeApi:
    """A JSON document store with strong ETags. ``enforce`` decides whether it honours
    ``If-Match`` the way RFC 9110 says, or ignores it as many APIs do."""

    docs: dict[str, dict[str, Any]] = field(default_factory=dict)
    revision: dict[str, int] = field(default_factory=dict)
    enforce: bool = True
    requests: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    fail_next_put: int | None = None
    timeout_after_put: bool = False
    before_put: Callable[[], None] | None = None

    def put_doc(self, url: str, body: dict[str, Any]) -> None:
        self.docs[url] = dict(body)
        self.revision[url] = self.revision.get(url, 0) + 1

    def etag(self, url: str) -> str:
        return f'"r{self.revision[url]}"'

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> Response:
        self.requests.append((method, url, dict(headers)))
        if method == "GET":
            if url not in self.docs:
                return Response(404)
            data = json.dumps({**self.docs[url], "updated_by": "server"}).encode()
            return Response(200, {"etag": self.etag(url)}, data)
        assert method == "PUT"
        assert body is not None
        if self.before_put:
            self.before_put()
        if self.fail_next_put:
            status, self.fail_next_put = self.fail_next_put, None
            return Response(status)
        if url not in self.docs:
            return Response(404)
        if self.enforce and headers.get("If-Match") != self.etag(url):
            return Response(412)
        self.put_doc(url, json.loads(body))
        if self.timeout_after_put:
            raise TimeoutError("connection reset after the write")
        return Response(200, {"etag": self.etag(url)})

    @property
    def puts(self) -> list[dict[str, str]]:
        return [h for m, _, h in self.requests if m == "PUT"]


@dataclass
class HttpEnv:
    api: FakeApi
    rt: Runtime
    store: SqliteStore

    def propose(self, path: str = PATH, **body: Any) -> Plan:
        params = {"path": path, "body": {**DOC, "enabled": True, "rollout": 10, **body}}
        return self.rt.propose(
            "http.put_json", params, agent=AGENT, sponsor=ALICE, idempotency_key=repr(params)
        ).plan

    def approved(self, **body: Any) -> Plan:
        plan = self.propose(**body)
        assert self.rt.submit_approval(approval(plan, BOB)) is State.APPROVED
        return plan

    def state(self, plan: Plan) -> State:
        return self.store.get(plan.plan_hash).state

    def someone_else_writes(self, **fields: Any) -> None:
        self.api.put_doc(URL, {**self.api.docs[URL], **fields})


def make(api: FakeApi, **kw: Any) -> HttpEnv:
    api.put_doc(URL, DOC)
    store = SqliteStore()
    rt = Runtime(store, RUNTIME, clock=Clock(T0))
    rt.register(PutJson(BASE, transport=api, headers={"Authorization": "Bearer test"}, **kw))
    return HttpEnv(api, rt, store)


@pytest.fixture
def http() -> HttpEnv:
    return make(FakeApi(), atomic=True)


# --- plan -----------------------------------------------------------------------------


def test_plan(http: HttpEnv) -> None:
    plan = http.propose()
    assert plan.action.name == "http.put_json"
    assert plan.effect.value == "COMPENSATABLE"
    # PUT replaces the whole document, so a field the body leaves out is a change too.
    assert plan.summary == (
        f"Replace the JSON document at {URL}; changes: enabled, rollout, updated_by"
    )
    [change] = plan.changes
    assert change.resource.id == URL
    assert change.before == {**DOC, "updated_by": "server"}
    assert change.after == {**DOC, "enabled": True, "rollout": 10}
    [pre] = plan.preconditions
    assert (pre.kind, pre.expect, pre.enforcement) == ("version", '"r1"', "atomic")
    assert plan.compensation is not None
    assert plan.compensation.strategy == "semantic"
    assert plan.compensation.params == {"body": {**DOC, "updated_by": "server"}}
    assert http.state(plan) is State.PENDING_APPROVAL
    assert http.api.puts == []


def test_check_then_act_unless_the_operator_says_atomic() -> None:
    env = make(FakeApi())
    [pre] = env.propose().preconditions
    assert pre.enforcement == "check_then_act"


def test_credentials_stay_out_of_the_plan(http: HttpEnv) -> None:
    plan = http.propose()
    assert "Bearer" not in plan.model_dump_json()
    assert all(h["Authorization"] == "Bearer test" for _, _, h in http.api.requests)


@pytest.mark.parametrize(
    "path",
    ["flags/x", "//evil.example.com/x", "/flags/../admin", "/flags/./x", "/x?y=1", "/x#y", ""],
)
def test_path_stays_under_base_url(http: HttpEnv, path: str) -> None:
    with pytest.raises(ValueError, match="path must"):
        http.propose(path=path)
    assert http.api.requests == []


def test_missing_document_cannot_be_planned(http: HttpEnv) -> None:
    with pytest.raises(ValueError, match="only replaces"):
        http.propose(path="/flags/new")


def test_weak_or_missing_etag_cannot_be_planned() -> None:
    def no_etag(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> Response:
        return Response(200, {"etag": 'W/"1"'}, b"{}")

    rt = Runtime(SqliteStore(), RUNTIME, clock=Clock(T0))
    rt.register(PutJson(BASE, transport=no_etag))
    with pytest.raises(ValueError, match="no strong ETag"):
        rt.propose("http.put_json", {"path": PATH, "body": {}}, agent=AGENT, idempotency_key="k")


@pytest.mark.parametrize(
    ("base", "headers"),
    [
        ("ftp://api.example.com", {}),
        ("https://api.example.com/v1?x=1", {}),
        (BASE, {"If-Match": "*"}),
        (BASE, {"content-type": "text/plain"}),
    ],
)
def test_bad_configuration(base: str, headers: dict[str, str]) -> None:
    with pytest.raises(ValueError, match=r"base_url|headers"):
        PutJson(base, transport=FakeApi(), headers=headers)


# --- apply ----------------------------------------------------------------------------


def test_apply_sends_if_match(http: HttpEnv) -> None:
    plan = http.approved()
    result = http.rt.execute(plan.plan_hash)
    assert result.state is State.APPLIED
    assert http.api.docs[URL] == {**DOC, "enabled": True, "rollout": 10}
    [put] = http.api.puts
    assert put["If-Match"] == '"r1"'
    assert put["Content-Type"] == "application/json"
    assert result.applied is not None
    assert result.applied.result == {"status": 200, "etag": '"r2"'}
    assert result.deviation == ()


def test_drift_refuses_apply(http: HttpEnv) -> None:
    plan = http.approved()
    http.someone_else_writes(rollout=50)
    result = http.rt.execute(plan.plan_hash)
    assert result.state is State.DRIFTED
    assert [(d.expected, d.observed) for d in result.drift] == [('"r1"', '"r2"')]
    assert http.api.docs[URL]["rollout"] == 50
    assert http.api.puts == []


def test_change_between_check_and_write_is_refused_by_the_api(http: HttpEnv) -> None:
    plan = http.approved()
    http.api.before_put = lambda: http.someone_else_writes(rollout=50)
    assert http.rt.execute(plan.plan_hash).state is State.DRIFTED
    assert http.api.docs[URL]["rollout"] == 50


def test_an_api_that_ignores_if_match_overwrites_in_the_window() -> None:
    """Why ``atomic`` defaults to False: the check before the write is all there is."""
    env = make(FakeApi(enforce=False))
    plan = env.approved()
    env.api.before_put = lambda: env.someone_else_writes(owner="growth")
    assert env.rt.execute(plan.plan_hash).state is State.APPLIED
    assert env.api.docs[URL]["owner"] == "payments"  # the other write was lost


def test_deleted_before_apply_is_drift(http: HttpEnv) -> None:
    plan = http.approved()
    del http.api.docs[URL]
    assert http.rt.execute(plan.plan_hash).state is State.DRIFTED


def test_rejected_request_is_failed(http: HttpEnv) -> None:
    plan = http.approved()
    http.api.fail_next_put = 403
    assert http.rt.execute(plan.plan_hash).state is State.FAILED
    assert http.api.docs[URL] == DOC


def test_server_error_is_unknown_then_reconciled_failed(http: HttpEnv) -> None:
    plan = http.approved()
    http.api.fail_next_put = 502
    assert http.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert http.rt.reconcile(plan.plan_hash) is State.FAILED


def test_lost_response_is_unknown_then_reconciled_applied(http: HttpEnv) -> None:
    plan = http.approved()
    http.api.timeout_after_put = True
    assert http.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert http.rt.reconcile(plan.plan_hash) is State.APPLIED


def test_reconcile_leaves_ambiguity_to_a_human(http: HttpEnv) -> None:
    plan = http.approved()
    http.api.timeout_after_put = True
    http.rt.execute(plan.plan_hash)
    http.someone_else_writes(rollout=99)
    assert http.rt.reconcile(plan.plan_hash) is State.UNKNOWN


# --- compensate -----------------------------------------------------------------------


def test_compensate_puts_the_previous_document_back(http: HttpEnv) -> None:
    plan = http.approved()
    http.rt.execute(plan.plan_hash)
    assert http.rt.compensate(plan.plan_hash).outcome == "succeeded"
    assert http.api.docs[URL] == {**DOC, "updated_by": "server"}
    assert http.api.puts[-1]["If-Match"] == '"r2"'
    assert http.state(plan) is State.COMPENSATED


def test_compensate_does_not_overwrite_a_later_change(http: HttpEnv) -> None:
    plan = http.approved()
    http.rt.execute(plan.plan_hash)
    http.someone_else_writes(rollout=75)
    assert http.rt.compensate(plan.plan_hash).outcome == "conflict"
    assert http.api.docs[URL]["rollout"] == 75
    assert len(http.api.puts) == 1


def test_compensate_race_is_a_conflict(http: HttpEnv) -> None:
    plan = http.approved()
    http.rt.execute(plan.plan_hash)
    http.api.before_put = lambda: http.someone_else_writes(rollout=75)
    assert http.rt.compensate(plan.plan_hash).outcome == "conflict"
    assert http.api.docs[URL]["rollout"] == 75


# --- the standard-library transport against a real socket -------------------------------


class _Handler(BaseHTTPRequestHandler):
    doc: ClassVar[dict[str, Any]] = {}
    revision: ClassVar[int] = 1

    def log_message(self, *args: Any) -> None:
        pass

    def _reply(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/v1/moved":
            self._reply(302, Location="http://elsewhere.invalid/")
        elif self.path == PATH.replace("/flags", "/v1/flags"):
            etag = f'"r{type(self).revision}"'
            self._reply(200, json.dumps(type(self).doc).encode(), ETag=etag)
        else:
            self._reply(404)

    def do_PUT(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.headers.get("If-Match") != f'"r{type(self).revision}"':
            self._reply(412)
            return
        type(self).doc = json.loads(body)
        type(self).revision += 1
        self._reply(204, ETag=f'"r{type(self).revision}"')


@pytest.fixture
def server() -> Iterator[str]:
    _Handler.doc, _Handler.revision = dict(DOC), 1
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/v1"
    httpd.shutdown()
    httpd.server_close()


def test_urllib_transport_end_to_end(server: str) -> None:
    rt = Runtime(SqliteStore(), RUNTIME, clock=Clock(T0))
    rt.register(PutJson(server, transport=UrllibTransport(timeout=5), atomic=True))
    params = {"path": PATH, "body": {**DOC, "enabled": True}}
    plan = rt.propose("http.put_json", params, agent=AGENT, idempotency_key="e2e").plan
    assert plan.preconditions[0].expect == '"r1"'
    rt.submit_approval(approval(plan, BOB))
    assert rt.execute(plan.plan_hash).state is State.APPLIED
    assert _Handler.doc["enabled"] is True


def test_urllib_transport_does_not_follow_redirects(server: str) -> None:
    reply = UrllibTransport(timeout=5)("GET", server + "/moved", {}, None)
    assert reply.status == 302
    assert reply.headers["location"] == "http://elsewhere.invalid/"
    assert UrllibTransport(timeout=5)("GET", server + "/nope", {}, None).status == 404
