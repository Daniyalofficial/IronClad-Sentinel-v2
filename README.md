# IronClad Sentinel

**Self-hosted application security platform.** SAST, secrets, dependency
vulnerabilities, infrastructure-as-code, SBOM and license compliance —
turned into findings engineering teams can actually act on. Zero telemetry,
zero phone-home, and the scanning path never executes the code it reads.

> Your company has thousands of signals across dozens of systems. IronClad
> Sentinel analyses them and turns security findings into actionable,
> explainable security intelligence for engineering teams.

Two ways to run it:

* **CLI** — a single offline scanner for laptops, pre-commit hooks and CI.
  No database, no network.
* **Server** — API + dashboard + worker with organizations, users, roles,
  policies, baselines, audit and integrations, backed by SQLite or
  PostgreSQL.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[server,dev]"

ironclad doctor                        # verify the installation
ironclad scan . --policy policy.yaml   # scan and gate
ironclad sbom . --out sbom.json        # CycloneDX 1.5
```

Run the whole product story end to end (generates a vulnerable repo, fails
the gate, baselines the backlog, fixes the code, passes the gate):

```bash
bash demo/run_demo.sh
```

Run the server:

```bash
export IRONCLAD_DATABASE_URL="sqlite:///./.ironclad/ironclad.db"
ironclad server init --org-name "Acme Corp" --admin-email you@acme.com \
  --admin-password "$ADMIN_PASSWORD"
ironclad serve                # API + dashboard on :8000
ironclad server worker        # background scan worker (separate process)
```

Dashboard at `/ui`. The interactive API docs at `/docs` (and `/openapi.json`)
are **disabled by default**; opt in with `IRONCLAD_ENABLE_DOCS=1` while
developing.

---

## What it detects

| Engine | What it does |
|---|---|
| **Python AST + taint** | Real source → sanitizer → sink analysis: SQL injection, command injection, `eval`/`exec`, path traversal, SSRF, XSS, open redirect, template injection, XXE, unsafe deserialization, weak TLS, insecure randomness, debug flags, assert-based auth |
| **Multi-language rules** | 9 YAML packs, **66 rules** across Python, JS/TS, Java, Go, Ruby, PHP, C#, SQL, shell, Terraform, Kubernetes, Dockerfiles. Extend without touching code |
| **Secrets** | Provider patterns (AWS, GitHub, Stripe, Slack, Google, DB URIs, PEM keys), Shannon-entropy detection, and a name-based credential rule that catches weak literals an entropy detector misses. **Secret values are never emitted** |
| **Dependencies** | **8 ecosystems, 20 manifest parsers**: Python, npm, Go, Rust, Java (Maven + Gradle), PHP, Ruby, NuGet. Ranges handled conservatively; malformed manifests reported, not silently skipped |
| **IaC** | Dockerfiles, Kubernetes and Terraform: privileged containers, host networking, root users, world-open ingress, disabled encryption, exposed ports, secrets in ENV/ARG, floating tags |
| **SBOM** | CycloneDX 1.5 **and** SPDX 2.3 from one component model, deterministic output, both schema-validated |
| **Licenses** | SPDX expression parsing (`OR`/`AND`/`WITH`), allow/warn/block policy. Unknown is **never** assumed permissive |

Reports: **JSON, SARIF 2.1.0, HTML, Markdown, JUnit XML, CycloneDX** — all
rendered from one `ScanResult`, so they cannot disagree.

## Policy and gradual adoption

```bash
ironclad policy init --out policy.yaml     # commented starting point
ironclad policy validate policy.yaml
ironclad scan . --policy policy.yaml       # deterministic pass/fail
```

A policy sets severity gates, `fail_on`, a risk-score cap, license
allow/warn/block lists, blocked packages, a confidence floor and rule
severity overrides. Evaluation is deterministic: the same scan plus the
same policy always produces the same decision.

First scan of a real codebase surfaces a backlog. Snapshot it and gate only
on new findings:

```bash
ironclad baseline create . --out .ironclad/baseline.json \
  --reason "TICKET-1234" --expires-in-days 90 --created-by secops@acme.com
ironclad scan . --policy policy.yaml --baseline .ironclad/baseline.json
```

Baselines carry a reason, an author and an **expiry**. Accepted findings
stop gating; expired ones start gating again. Critical findings cannot be
baselined without a reason unless you pass `--force`.

## Server

```
POST /scan ──► jobs table ──► worker ──► scanner ──► database ──► events / reports
```

The API never blocks on a scan: `POST /scan` returns **202** immediately.

| Capability | Detail |
|---|---|
| Storage | 19 tables (18 application tables plus the `schema_migrations` ledger), checksummed SQL migrations for SQLite **and** PostgreSQL. Schema is never created by application code |
| Authentication | PBKDF2-HMAC-SHA256 (210k iterations), tokens stored as digests, self-clearing lockout |
| Authorization | 5 roles (`owner > admin > security > developer > viewer`), 20 explicit permissions, deny by default |
| Multi-tenancy | Every tenant-owned row is `org_id`-scoped; a foreign row is a **404**, never a 403 |
| Jobs | Durable queue, at-least-once, exponential-backoff retries, stale-claim recovery |
| Events | 15 typed contracts, validated at publish time, persisted |
| Audit | Append-only, credential-redacted, filterable |
| Observability | JSON structured logs with request/correlation ids, Prometheus metrics at `/metrics` |
| Integrations | Webhook (HMAC-signed), GitHub (SARIF upload), GitLab, Slack/Teams, Jira — real deliveries, bounded retries |

Full endpoint reference: [`docs/API.md`](docs/API.md).

## CI/CD

```yaml
- run: ironclad scan . --policy policy.yaml --format sarif --output-dir reports
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: reports/ironclad-report.sarif.json }
```

Exit codes are a published contract (`ironclad/core/exit_codes.py`):
`0` pass, `1` gate failed, `2` usage, `3` config, `4` target, `5` internal.

Ready-made configs: `integrations/github-actions/`, `integrations/gitlab-ci/`,
`integrations/pre-commit/`.

## Deployment

```bash
docker compose up -d --build          # Postgres + API + worker
kubectl apply -f deploy/k8s/          # namespace, API, worker, HPA, ingress
```

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for all three topologies, the
configuration reference, and backup/restore.

## Performance

Measured on this repository's CI hardware
(`python benchmarks/scale_benchmark.py`):

| Files | Wall clock | Files/sec | Peak RSS |
|---:|---:|---:|---:|
| 1,000 | 0.52 s | 1,917 | 21 MB |
| 10,000 | 4.67 s | 2,142 | 26 MB |
| 100,000 | 47.1 s | 2,122 | 72 MB |

Throughput is flat and memory grows slowly — there is no quadratic pass.
Detection accuracy on the labelled corpus: precision **1.00**, recall
**1.00** (`benchmarks/corpus_metrics.py`). Read that number with the caveat
in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md): the corpus is small and
synthetic.

## Tests

```bash
pytest -q                                     # 452 tests
python benchmarks/corpus_metrics.py           # detection accuracy
ironclad scan ironclad --fail-on high         # self-scan must stay clean
```

`ironclad scan ironclad` reports **0 findings, grade A+** across 81 files.
Running it found two real precision bugs, both fixed and now covered by
regression tests.

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data flow, the single-`Finding` decision, engine boundaries |
| [API.md](docs/API.md) | Every endpoint, permissions, error contract, tenancy semantics |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Three topologies, configuration reference, migrations, backup |
| [SECURITY.md](docs/SECURITY.md) | How the product itself is secured, and its known limitations |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, actors, 10 entry points — each with the test that proves the control |
| [DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md) | Backup, restore, failure modes, RTO/RPO |
| [BENCHMARKS.md](docs/BENCHMARKS.md) | Measured scale and accuracy numbers |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | The rules for changing this codebase |
| [PROGRESS.md](docs/PROGRESS.md) | Honest completion matrix — including what is **not** finished |
| [CHANGELOG.md](docs/CHANGELOG.md) | What changed, and the 15 bugs found and fixed |
| [PRICING_AND_GTM.md](docs/PRICING_AND_GTM.md) | Positioning, tiering, pilot guide |

## Licensing model

Offline Ed25519-signed license tokens (`ironclad/licensing/`). No license
server, no outbound call at verification time: collect payment → run one
local command → send a file. Trial mode runs the AST, rule-engine and
secrets scanners with no time or size limit.

## What this is not

Stated plainly, because a scanner that overstates its guarantees is worse
than one that under-delivers — the full list is in
[`docs/PROGRESS.md`](docs/PROGRESS.md):

* Taint analysis is **intra-procedural**; flows crossing a function
  boundary are missed.
* Deep analysis is **Python-only**. Other languages are regex rules.
* The bundled advisory database is **44 packages** — a demonstration
  dataset, not a feed. Point `advisory_path` at your own overlay.
* **No OIDC/OAuth2**, no rate limiting, no mail transport for password
  reset. Local auth and API tokens only.
* PostgreSQL is supported but the test suite proves **SQLite**.
* The dashboard is read-only; triage happens through the API.

No telemetry, no analytics, no auto-update, no live feed at scan time. If a
feature request would require any of those, it does not belong in this
product.
