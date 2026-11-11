from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from conftest import T0
from sealedplan.models import Plan, RiskLevel
from sealedplan.providers.k8s import KubeApiError, ScaleDeployment
from sealedplan.runtime import Runtime
from sealedplan.state import State
from sealedplan.store import SqliteStore
from test_runtime import AGENT, ALICE, BOB, RUNTIME, Clock, approval

NS, NAME, CLUSTER = "shop", "checkout", "test-cluster"
DEPLOY_ID = f"k8s://{CLUSTER}/{NS}/{NAME}"


@dataclass
class FakeKube:
    """Just enough of an API server: generation, resourceVersion and 409 on stale writes."""

    deployments: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    rv: int = 1000
    writes: list[int] = field(default_factory=list)
    fail_next: int | None = None  # HTTP status for the next real write
    timeout_after_write: bool = False
    before_write: Callable[[], None] | None = None

    def add(self, replicas: int, generation: int = 7) -> None:
        self.deployments[(NS, NAME)] = {
            "metadata": {"generation": generation, "resourceVersion": self._next_rv()},
            "spec": {"replicas": replicas},
            "status": {"readyReplicas": replicas},
        }

    def _next_rv(self) -> str:
        self.rv += 1
        return str(self.rv)

    def _get(self, namespace: str, name: str) -> dict[str, Any]:
        try:
            return self.deployments[(namespace, name)]
        except KeyError:
            raise KubeApiError(404, "not found") from None

    # someone else acting on the cluster

    def scale_by_someone_else(self, replicas: int) -> None:
        dep = self._get(NS, NAME)
        dep["spec"]["replicas"] = replicas
        dep["metadata"]["generation"] += 1
        dep["metadata"]["resourceVersion"] = self._next_rv()

    def status_update(self) -> None:
        dep = self._get(NS, NAME)
        dep["status"]["readyReplicas"] -= 1
        dep["metadata"]["resourceVersion"] = self._next_rv()

    # KubeApi

    def read_deployment(self, namespace: str, name: str) -> Mapping[str, Any]:
        return copy.deepcopy(self._get(namespace, name))

    def replace_scale(
        self, namespace: str, name: str, replicas: int, *, resource_version: str, dry_run: bool
    ) -> Mapping[str, Any]:
        if not dry_run:
            if self.before_write:
                self.before_write()
            if self.fail_next:
                status, self.fail_next = self.fail_next, None
                raise KubeApiError(status)
        dep = self._get(namespace, name)
        if dep["metadata"]["resourceVersion"] != resource_version:
            raise KubeApiError(409, "the object has been modified")
        scale = {
            "kind": "Scale",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"replicas": replicas},
        }
        if dry_run:
            return scale
        if dep["spec"]["replicas"] != replicas:
            dep["spec"]["replicas"] = replicas
            dep["metadata"]["generation"] += 1
        dep["metadata"]["resourceVersion"] = self._next_rv()
        self.writes.append(replicas)
        if self.timeout_after_write:
            raise TimeoutError("connection reset after the write")
        return scale

    @property
    def replicas(self) -> int:
        return int(self._get(NS, NAME)["spec"]["replicas"])

    @property
    def generation(self) -> int:
        return int(self._get(NS, NAME)["metadata"]["generation"])


@dataclass
class K8sEnv:
    kube: FakeKube
    rt: Runtime
    store: SqliteStore

    def propose(self, replicas: int = 6) -> Plan:
        params = {"namespace": NS, "name": NAME, "replicas": replicas}
        key = f"scale-{replicas}"
        return self.rt.propose(
            "k8s.scale_deployment", params, agent=AGENT, sponsor=ALICE, idempotency_key=key
        ).plan

    def approved(self, replicas: int = 6) -> Plan:
        plan = self.propose(replicas)
        assert self.rt.submit_approval(approval(plan, BOB)) is State.APPROVED
        return plan

    def state(self, plan: Plan) -> State:
        return self.store.get(plan.plan_hash).state


@pytest.fixture
def k8s() -> K8sEnv:
    kube = FakeKube()
    kube.add(replicas=3)
    store = SqliteStore()
    rt = Runtime(store, RUNTIME, clock=Clock(T0))
    rt.register(ScaleDeployment(kube, CLUSTER))
    return K8sEnv(kube, rt, store)


# --- plan -----------------------------------------------------------------------------


def test_plan_matches_the_spec_example(k8s: K8sEnv) -> None:
    plan = k8s.propose()
    assert plan.action.to_obj() == {
        "name": "k8s.scale_deployment",
        "version": "1.0.0",
        "provider": "sealedplan-k8s",
    }
    [change] = plan.changes
    assert change.resource.id == DEPLOY_ID
    assert (change.before, change.after) == ({"spec": {"replicas": 3}}, {"spec": {"replicas": 6}})
    [pre] = plan.preconditions
    assert (pre.id, pre.kind, pre.expect, pre.enforcement) == (
        "deploy-generation",
        "version",
        "7",
        "atomic",
    )
    assert plan.compensation is not None
    assert plan.compensation.params == {"replicas": 3}
    assert plan.blast_radius is not None
    assert plan.blast_radius.scopes == [f"k8s://{CLUSTER}/{NS}"]
    assert [e.kind for e in plan.evidence or []] == ["k8s.server-dry-run"]
    assert plan.summary == "Scale shop/checkout from 3 to 6 replicas"
    assert k8s.state(plan) is State.PENDING_APPROVAL


def test_planning_changes_nothing(k8s: K8sEnv) -> None:
    k8s.propose()
    assert (k8s.kube.replicas, k8s.kube.generation, k8s.kube.writes) == (3, 7, [])


def test_scale_to_zero_is_high_risk(k8s: K8sEnv) -> None:
    plan = k8s.propose(0)
    assert plan.risk.level is RiskLevel.HIGH
    assert plan.risk.reasons == ["scales to zero: the workload stops serving"]


@pytest.mark.parametrize("replicas", [-1, True, "6"])
def test_bad_replicas(k8s: K8sEnv, replicas: Any) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        k8s.propose(replicas)


def test_missing_deployment(k8s: K8sEnv) -> None:
    k8s.kube.deployments.clear()
    with pytest.raises(ValueError, match="not found"):
        k8s.propose()


# --- apply ----------------------------------------------------------------------------


def test_apply(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    result = k8s.rt.execute(plan.plan_hash)
    assert result.state is State.APPLIED
    assert (k8s.kube.replicas, k8s.kube.generation, k8s.kube.writes) == (6, 8, [6])
    assert result.applied is not None
    assert result.applied.result == {"replicas": 6}
    assert result.applied.observed is not None
    assert result.applied.observed[DEPLOY_ID]["version"] == "8"


def test_status_churn_is_not_drift(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.status_update()
    k8s.kube.status_update()
    assert k8s.rt.execute(plan.plan_hash).state is State.APPLIED
    assert k8s.kube.replicas == 6


def test_drift_refuses_apply(k8s: K8sEnv) -> None:
    """Approved 3 -> 6, then an autoscaler moves it to 4: the approved plan must not run."""
    plan = k8s.approved()
    k8s.kube.scale_by_someone_else(4)
    result = k8s.rt.execute(plan.plan_hash)
    assert result.state is State.DRIFTED
    assert [(d.id, d.expected, d.observed) for d in result.drift] == [
        ("deploy-generation", "7", "8")
    ]
    assert (k8s.kube.replicas, k8s.kube.writes) == (4, [])


def test_change_between_check_and_write_is_refused_by_the_server(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.before_write = lambda: k8s.kube.scale_by_someone_else(4)
    assert k8s.rt.execute(plan.plan_hash).state is State.DRIFTED
    assert (k8s.kube.replicas, k8s.kube.writes) == (4, [])


def test_deleted_before_apply_is_drift(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.deployments.clear()
    assert k8s.rt.execute(plan.plan_hash).state is State.DRIFTED


def test_rejected_request_is_failed(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.fail_next = 403
    assert k8s.rt.execute(plan.plan_hash).state is State.FAILED
    assert k8s.kube.replicas == 3


def test_server_error_is_unknown_then_reconciled_failed(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.fail_next = 503
    assert k8s.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert k8s.rt.reconcile(plan.plan_hash) is State.FAILED


def test_lost_response_is_unknown_then_reconciled_applied(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.timeout_after_write = True
    assert k8s.rt.execute(plan.plan_hash).state is State.UNKNOWN
    assert k8s.rt.reconcile(plan.plan_hash) is State.APPLIED
    assert k8s.kube.writes == [6]


def test_reconcile_leaves_ambiguity_to_a_human(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.kube.timeout_after_write = True
    k8s.rt.execute(plan.plan_hash)
    k8s.kube.scale_by_someone_else(9)
    assert k8s.rt.reconcile(plan.plan_hash) is State.UNKNOWN
    assert k8s.state(plan) is State.UNKNOWN


# --- compensate -----------------------------------------------------------------------


def test_compensate_restores_previous_replicas(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.rt.execute(plan.plan_hash)
    assert k8s.rt.compensate(plan.plan_hash).outcome == "succeeded"
    assert (k8s.kube.replicas, k8s.kube.writes) == (3, [6, 3])
    assert k8s.state(plan) is State.COMPENSATED


def test_compensate_does_not_overwrite_a_later_change(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.rt.execute(plan.plan_hash)
    k8s.kube.scale_by_someone_else(10)
    assert k8s.rt.compensate(plan.plan_hash).outcome == "conflict"
    assert (k8s.kube.replicas, k8s.kube.writes) == (10, [6])
    assert k8s.state(plan) is State.COMPENSATION_FAILED


def test_compensate_race_is_a_conflict(k8s: K8sEnv) -> None:
    plan = k8s.approved()
    k8s.rt.execute(plan.plan_hash)
    k8s.kube.before_write = lambda: k8s.kube.scale_by_someone_else(10)
    assert k8s.rt.compensate(plan.plan_hash).outcome == "conflict"
    assert k8s.kube.replicas == 10
