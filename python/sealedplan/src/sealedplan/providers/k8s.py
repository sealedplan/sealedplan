"""Reference action: scale a Kubernetes Deployment (the SPEC §5.2 example).

The action talks to the cluster through :class:`KubeApi`, two calls on the Deployment
and its ``scale`` subresource, so this package needs no Kubernetes client. A backend
maps them onto ``read_namespaced_deployment`` and ``replace_namespaced_deployment_scale``
(or the equivalent REST calls) and raises :class:`KubeApiError` with the HTTP status.

Drift uses ``metadata.generation`` as the version token, not ``resourceVersion``.
``resourceVersion`` changes on every status update (a pod becoming ready), so nearly
every plan would drift before approval. ``generation`` changes only when the spec does:
someone else scaling, an autoscaler, a rollout. Enforcement is still atomic: ``apply``
reads the Deployment, compares ``generation``, and writes the scale carrying that read's
``resourceVersion``, so the API server refuses the write (409) if anything changed in
between.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from sealedplan.actions import (
    ApplyFailedError,
    CompensationConflictError,
    Context,
    PreconditionFailedError,
    action,
)
from sealedplan.canonical import digest
from sealedplan.models import (
    Applied,
    BlastRadius,
    Change,
    Compensation,
    Effect,
    Evidence,
    Plan,
    Precondition,
    ResourceRef,
    RiskLevel,
)
from sealedplan.preconditions import ABSENT, Observation, PreconditionResult
from sealedplan.state import State

RESOURCE_TYPE = "apps/v1/Deployment"
PRECONDITION_ID = "deploy-generation"

# The API server rejected the request outright, so nothing changed. Any other error
# (timeouts, 5xx) may come after the write was committed and leaves the plan UNKNOWN.
_REJECTED = frozenset({400, 401, 403, 422, 429})


class KubeApiError(Exception):
    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(f"{status} {message}".strip())
        self.status = status


class KubeApi(Protocol):
    def read_deployment(self, namespace: str, name: str) -> Mapping[str, Any]:
        """The Deployment object. Raises ``KubeApiError(404)`` if it does not exist."""
        ...

    def replace_scale(
        self, namespace: str, name: str, replicas: int, *, resource_version: str, dry_run: bool
    ) -> Mapping[str, Any]:
        """Replace the scale subresource with ``metadata.resourceVersion`` set, so a
        stale version gets 409. ``dry_run`` is server-side (``dryRun=All``). Returns the
        Scale object."""
        ...


@action(
    "k8s.scale_deployment",
    effect=Effect.REVERSIBLE,
    risk="medium",
    version="1.0.0",
    provider="sealedplan-k8s",
)
class ScaleDeployment:
    def __init__(self, api: KubeApi, cluster: str) -> None:
        self.api = api
        self.cluster = cluster

    # --- helpers ----------------------------------------------------------------------

    def _ref(self, namespace: str, name: str) -> ResourceRef:
        return ResourceRef(type=RESOURCE_TYPE, id=f"k8s://{self.cluster}/{namespace}/{name}")

    def _locate(self, resource: ResourceRef) -> tuple[str, str]:
        prefix = f"k8s://{self.cluster}/"
        if resource.type != RESOURCE_TYPE or not resource.id.startswith(prefix):
            raise ValueError(f"not a Deployment in cluster {self.cluster}: {resource.id}")
        namespace, _, name = resource.id.removeprefix(prefix).partition("/")
        return namespace, name

    def _read(self, namespace: str, name: str) -> Mapping[str, Any] | None:
        try:
            return self.api.read_deployment(namespace, name)
        except KubeApiError as exc:
            if exc.status == 404:
                return None
            raise

    @staticmethod
    def _facts(dep: Mapping[str, Any]) -> tuple[str, str, int]:
        """``(generation, resourceVersion, spec.replicas)``."""
        meta = dep["metadata"]
        return str(meta["generation"]), str(meta["resourceVersion"]), int(dep["spec"]["replicas"])

    # --- the action -------------------------------------------------------------------

    def plan(self, ctx: Context, namespace: str, name: str, replicas: int) -> Plan:
        if isinstance(replicas, bool) or not isinstance(replicas, int) or replicas < 0:
            raise ValueError("replicas must be a non-negative integer")
        dep = self._read(namespace, name)
        if dep is None:
            raise ValueError(f"deployment {namespace}/{name} not found")
        generation, resource_version, current = self._facts(dep)
        dry_run = self.api.replace_scale(
            namespace, name, replicas, resource_version=resource_version, dry_run=True
        )
        ref = self._ref(namespace, name)
        risk, reasons = None, []
        if replicas == 0 and current > 0:
            risk, reasons = RiskLevel.HIGH, ["scales to zero: the workload stops serving"]
        return ctx.plan(
            summary=f"Scale {namespace}/{name} from {current} to {replicas} replicas",
            changes=[
                Change(
                    resource=ref,
                    op="update",
                    before={"spec": {"replicas": current}},
                    after={"spec": {"replicas": replicas}},
                )
            ],
            preconditions=[
                Precondition(
                    id=PRECONDITION_ID,
                    resource=ref,
                    kind="version",
                    expect=generation,
                    enforcement="atomic",
                )
            ],
            risk=risk,
            risk_reasons=reasons,
            blast_radius=BlastRadius(resources=1, scopes=[f"k8s://{self.cluster}/{namespace}"]),
            compensation=Compensation(
                strategy="restore",
                summary=f"Scale {namespace}/{name} back to {current} replicas",
                params={"replicas": current},
            ),
            evidence=[
                Evidence(
                    kind="k8s.server-dry-run",
                    media_type="application/json",
                    digest=digest(dict(dry_run)),
                )
            ],
        )

    def observe(self, ctx: Context, resource: ResourceRef) -> Observation:
        dep = self._read(*self._locate(resource))
        if dep is None:
            return ABSENT
        generation, _, replicas = self._facts(dep)
        return Observation(True, generation, {"spec": {"replicas": replicas}})

    def apply(self, ctx: Context, plan: Plan) -> Applied:
        namespace, name = plan.params["namespace"], plan.params["name"]
        pre = next(p for p in plan.preconditions if p.id == PRECONDITION_ID)

        def drifted(observed: str) -> PreconditionFailedError:
            return PreconditionFailedError(
                [PreconditionResult(pre.id, False, pre.expect, observed)]
            )

        dep = self._read(namespace, name)
        if dep is None:
            raise drifted("absent")
        generation, resource_version, _ = self._facts(dep)
        if generation != pre.expect:
            raise drifted(generation)
        try:
            scale = self.api.replace_scale(
                namespace,
                name,
                plan.params["replicas"],
                resource_version=resource_version,
                dry_run=False,
            )
        except KubeApiError as exc:
            if exc.status == 409:
                raise drifted("changed during apply") from exc
            if exc.status == 404:
                raise drifted("absent") from exc
            if exc.status in _REJECTED:
                raise ApplyFailedError(str(exc)) from exc
            raise
        return ctx.applied(plan, result={"replicas": scale["spec"]["replicas"]})

    def compensate(self, ctx: Context, plan: Plan, applied: Applied) -> None:
        assert plan.compensation is not None
        assert plan.compensation.params is not None
        namespace, name = plan.params["namespace"], plan.params["name"]
        target, previous = plan.params["replicas"], plan.compensation.params["replicas"]
        dep = self._read(namespace, name)
        if dep is None:
            raise CompensationConflictError(f"deployment {namespace}/{name} no longer exists")
        _, resource_version, replicas = self._facts(dep)
        if replicas != target:
            raise CompensationConflictError(f"replicas are now {replicas}, not {target}")
        try:
            self.api.replace_scale(
                namespace, name, previous, resource_version=resource_version, dry_run=False
            )
        except KubeApiError as exc:
            if exc.status == 409:
                raise CompensationConflictError("deployment changed during compensation") from exc
            raise

    def reconcile(self, ctx: Context, plan: Plan, applied: Applied | None) -> State:
        """Decide an UNKNOWN apply from the Deployment as it is now."""
        dep = self._read(plan.params["namespace"], plan.params["name"])
        if dep is None:
            return State.UNKNOWN
        generation, _, replicas = self._facts(dep)
        expected = int(next(p for p in plan.preconditions if p.id == PRECONDITION_ID).expect or 0)
        if replicas == plan.params["replicas"] and int(generation) <= expected + 1:
            return State.APPLIED  # our write, and nothing after it
        if int(generation) == expected:
            return State.FAILED  # the spec is untouched, so the write never landed
        return State.UNKNOWN  # someone else changed it too; a human decides
