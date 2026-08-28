"""Deployment artifact verification.

No container runtime is available in CI, so the image itself cannot be
built or booted here -- that is recorded as environment-blocked rather than
claimed as verified. What *can* be executed is:

  * the entrypoint script's real behaviour for every role (this is the part
    most likely to be silently broken, and it is plain bash)
  * that every path the Dockerfile references actually exists
  * that the Kubernetes/compose manifests parse and carry the security
    settings they claim

Those are assertions, not inspections: a regression in any of them fails
this file.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DOCKERFILE = os.path.join(ROOT, "Dockerfile")
ENTRYPOINT = os.path.join(ROOT, "scripts", "container-entrypoint.sh")
COMPOSE = os.path.join(ROOT, "docker-compose.yml")
K8S_DIR = os.path.join(ROOT, "deploy", "k8s")


def _run_entrypoint(role, env=None, args=(), timeout=90):
    environment = dict(os.environ)
    environment.setdefault("IRONCLAD_SIGNING_KEY", "test-key-that-is-long-enough-32ch")
    if env is not None:
        environment.update(env)
    return subprocess.run(
        ["bash", ENTRYPOINT, role, *args],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=timeout,
    )


@pytest.fixture()
def sqlite_env():
    directory = tempfile.mkdtemp()
    yield {
        "IRONCLAD_DATABASE_URL": f"sqlite:///{directory}/deploy.db",
        "IRONCLAD_SCAN_ROOT": directory,
    }
    shutil.rmtree(directory, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Entrypoint behaviour (real execution)
# --------------------------------------------------------------------------- #
def test_entrypoint_migrate_applies_migrations(sqlite_env):
    result = _run_entrypoint("migrate", env=sqlite_env)
    assert result.returncode == 0, result.stderr
    assert "0001_initial.sql" in result.stdout
    assert "0002_scan_policy_document.sql" in result.stdout


def test_entrypoint_migrate_is_idempotent(sqlite_env):
    assert _run_entrypoint("migrate", env=sqlite_env).returncode == 0
    second = _run_entrypoint("migrate", env=sqlite_env)
    assert second.returncode == 0, second.stderr
    assert "none (already up to date)" in second.stdout, second.stdout


def test_entrypoint_worker_drains_and_exits(sqlite_env):
    """`worker` must not hang on an empty queue -- it is the container CMD."""
    _run_entrypoint("migrate", env=sqlite_env)
    result = _run_entrypoint("worker", env=sqlite_env, args=["--max-jobs", "1"], timeout=60)
    assert result.returncode == 0, result.stderr
    assert "Worker stopped" in result.stdout


def test_entrypoint_unknown_role_exits_2(sqlite_env):
    result = _run_entrypoint("nonsense", env=sqlite_env)
    assert result.returncode == 2, result.returncode
    assert "unknown role" in (result.stdout + result.stderr)


def test_entrypoint_fails_fast_without_a_database_url(sqlite_env):
    env = {k: v for k, v in sqlite_env.items() if k != "IRONCLAD_DATABASE_URL"}
    env["IRONCLAD_DATABASE_URL"] = ""
    result = _run_entrypoint("migrate", env=env)
    assert result.returncode != 0, "must fail fast rather than start with no database"
    assert "IRONCLAD_DATABASE_URL" in (result.stdout + result.stderr)


def test_entrypoint_declares_every_documented_role():
    with open(ENTRYPOINT, encoding="utf-8") as fh:
        text = fh.read()
    for role in ("api", "worker", "migrate", "shell"):
        assert f"{role})" in text, f"entrypoint is missing role {role!r}"
    assert "set -euo pipefail" in text, "entrypoint must fail loudly"


# --------------------------------------------------------------------------- #
# Dockerfile
# --------------------------------------------------------------------------- #
def test_dockerfile_references_only_paths_that_exist():
    with open(DOCKERFILE, encoding="utf-8") as fh:
        text = fh.read()
    for ref in ("pyproject.toml", "README.md", "scripts/container-entrypoint.sh", "docs"):
        assert os.path.exists(os.path.join(ROOT, ref)), f"Dockerfile references missing path {ref}"
    # The COPY targets must match what the entrypoint expects at runtime.
    assert "COPY --chown=ironclad:ironclad scripts/" in text
    assert 'ENTRYPOINT ["/app/scripts/container-entrypoint.sh"]' in text


def test_dockerfile_runs_as_non_root():
    with open(DOCKERFILE, encoding="utf-8") as fh:
        text = fh.read()
    assert "useradd --system" in text
    # The USER directive must come after the installs and be the last
    # privilege-relevant instruction, otherwise later RUNs re-escalate.
    user_index = text.rindex("\nUSER ironclad")
    assert user_index > text.index("RUN python -m pip install")
    assert "USER root" not in text[user_index:]


def test_dockerfile_has_a_healthcheck_against_ready():
    with open(DOCKERFILE, encoding="utf-8") as fh:
        text = fh.read()
    assert "HEALTHCHECK" in text
    assert "/ready" in text, "healthcheck must probe /ready, not /health"


def test_dockerfile_is_multistage():
    with open(DOCKERFILE, encoding="utf-8") as fh:
        text = fh.read()
    assert text.count("\nFROM ") >= 1 and "AS builder" in text and "AS runtime" in text


# --------------------------------------------------------------------------- #
# Kubernetes manifests
# --------------------------------------------------------------------------- #
def _load_manifests():
    documents = []
    for name in sorted(os.listdir(K8S_DIR)):
        if not name.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(K8S_DIR, name), encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if doc:
                    documents.append((name, doc))
    return documents


def test_k8s_manifests_parse():
    documents = _load_manifests()
    assert documents, "no manifests parsed"
    kinds = {doc["kind"] for _, doc in documents}
    assert {"Namespace", "ConfigMap", "Secret", "Deployment", "Service"} <= kinds, kinds


def test_k8s_pods_are_hardened():
    """Every pod spec must carry the settings the docs claim."""
    checked = 0
    for name, doc in _load_manifests():
        if doc.get("kind") not in ("Deployment", "CronJob"):
            continue
        if doc["kind"] == "Deployment":
            spec = doc["spec"]["template"]["spec"]
        else:
            spec = doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        assert spec["securityContext"]["runAsNonRoot"] is True, name
        assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault", name
        for container in spec["containers"]:
            sc = container["securityContext"]
            assert sc["allowPrivilegeEscalation"] is False, f"{name}/{container['name']}"
            assert sc["readOnlyRootFilesystem"] is True, f"{name}/{container['name']}"
            assert sc["capabilities"]["drop"] == ["ALL"], f"{name}/{container['name']}"
            assert "resources" in container, f"{name}/{container['name']} has no resource limits"
            assert "limits" in container["resources"], f"{name}/{container['name']} has no limits"
            checked += 1
    assert checked >= 3, f"expected API + worker + migrate containers, checked {checked}"


def test_k8s_api_has_probes_and_the_worker_does_not_need_them():
    deployments = {doc["metadata"]["name"]: doc for _, doc in _load_manifests()
                   if doc.get("kind") == "Deployment"}
    api = deployments["ironclad-api"]["spec"]["template"]["spec"]["containers"][0]
    assert api["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert api["livenessProbe"]["httpGet"]["path"] == "/health"
    # A worker serves no HTTP, so a readiness probe would be meaningless.
    worker = deployments["ironclad-worker"]["spec"]["template"]["spec"]["containers"][0]
    assert "readinessProbe" not in worker


def test_k8s_secret_is_a_template_with_no_real_credentials():
    secret = next(doc for _, doc in _load_manifests() if doc.get("kind") == "Secret")
    values = " ".join(str(v) for v in secret.get("stringData", {}).values())
    assert "REPLACE_ME" in values, "the committed Secret must contain placeholders only"
    assert len(values) < 200, "the committed Secret looks like it holds real material"


def test_k8s_namespace_enforces_restricted_pod_security():
    namespace = next(doc for _, doc in _load_manifests() if doc.get("kind") == "Namespace")
    labels = namespace["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"


def test_k8s_scan_volume_is_read_only():
    api = next(doc for _, doc in _load_manifests()
               if doc.get("kind") == "Deployment"
               and doc["metadata"]["name"] == "ironclad-api")
    mounts = api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    work = next(m for m in mounts if m["mountPath"] == "/work")
    assert work["readOnly"] is True, "scanned repositories must be mounted read-only"


# --------------------------------------------------------------------------- #
# Compose
# --------------------------------------------------------------------------- #
def test_compose_separates_api_worker_and_database():
    with open(COMPOSE, encoding="utf-8") as fh:
        compose = yaml.safe_load(fh)
    services = compose["services"]
    assert {"api", "worker", "db"} <= set(services), sorted(services)
    # The database must not be published to the host.
    assert "ports" not in services["db"], "PostgreSQL must not be exposed to the host"
    assert services["api"]["command"] == ["api"]
    assert services["worker"]["command"] == ["worker"]


def test_compose_mounts_the_scan_root_read_only():
    with open(COMPOSE, encoding="utf-8") as fh:
        compose = yaml.safe_load(fh)
    for service in ("api", "worker"):
        volumes = compose["services"][service]["volumes"]
        work = next(v for v in volumes if v.endswith("/work") or ":/work:ro" in v)
        assert work.endswith(":ro"), f"{service} must mount /work read-only: {work}"


def test_compose_requires_secrets_rather_than_defaulting_them():
    with open(COMPOSE, encoding="utf-8") as fh:
        text = fh.read()
    # `${VAR:?message}` fails fast; a silent default would ship an insecure key.
    assert "${POSTGRES_PASSWORD:?" in text
    assert "${IRONCLAD_SIGNING_KEY:?" in text


def test_compose_worker_has_resource_limits():
    with open(COMPOSE, encoding="utf-8") as fh:
        compose = yaml.safe_load(fh)
    limits = compose["services"]["worker"]["deploy"]["resources"]["limits"]
    assert "cpus" in limits and "memory" in limits
