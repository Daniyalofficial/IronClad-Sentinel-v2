# Contributing

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[server,dev]"
pytest -q
```

The scanner core needs only `click`, `PyYAML`, `rich`, `Jinja2` and
`cryptography`. The `[server]` extra (FastAPI, SQLAlchemy, uvicorn,
pydantic) is only needed for the API, dashboard and worker.

## Running everything locally

```bash
pytest -q                                             # full suite
python benchmarks/corpus_metrics.py --fail-below 0.95 # detection quality
python benchmarks/scale_benchmark.py --tiers 1000     # throughput
ironclad scan ironclad --fail-on high                 # self-scan must stay clean
bash demo/run_demo.sh                                 # end-to-end story
```

## The rules for changing this codebase

### 1. A rule is not done until it has three fixtures

Every detector needs a **vulnerable** case that must fire, a **safe** case
that must not, and an **edge** case (sanitised, constant-only, aliased
import, cross-function). Precision is the product: a scanner with a high
false-positive rate gets disabled in week one.

* Flow detectors: `tests/security_corpus/flows/` + `tests/test_python_flows.py`
* Rule packs: a `must-fire` and a `must-not-fire` snippet per rule in
  `tests/test_rule_packs_extended.py`
* Then run `python benchmarks/corpus_metrics.py` and make sure precision
  did not drop.

### 2. Never mark something complete because code exists

If a feature is partial, say so in the docstring and in
`docs/PROGRESS.md`. A documented limitation is fine; an implied guarantee
that is not true is not.

### 3. Migrations, not `create_all()`

Schema changes go in a new numbered file under
`ironclad/platform/migrations/sqlite/` **and** `.../postgres/`. Never edit
an applied migration — it is checksummed and will fail loudly. Add a new
one.

### 4. Tenant scoping is not optional

Any new table that holds tenant data needs an `org_id` column, and queries
must start from `ironclad.platform.tenancy.org_query()`. It refuses a model
with no `org_id` on purpose.

### 5. Secrets never leave the process

* Do not put a secret value in a finding, a log line, an audit record or an
  API response. `ironclad.platform.audit.redact_secrets` and
  `ironclad.scanners.secrets._redact` exist for this; use them.
* Do not add a default for `IRONCLAD_SIGNING_KEY` or `POSTGRES_PASSWORD`.

### 6. Keep the scanner offline

The scanning path must not open a socket. The only outbound code is an
explicitly configured integration or the opt-in `remote` advisory source.
If a change would make `ironclad scan` touch the network by default, it
does not belong in the product.

## Architecture map

```
ironclad/
  cli.py                 click CLI (scan, policy, baseline, sbom, server, serve, ...)
  core/
    config.py            config precedence chain
    walker.py            single-pass file discovery and classification
    models.py            Finding / ScanResult - the one schema every engine feeds
    engine.py            orchestration: discover -> engines -> filter -> baseline
    policy.py            policy document, validation, deterministic evaluation
    baseline.py          baseline v2 with reasons and expiry
    spdx_expr.py         SPDX license expression parsing and classification
    exit_codes.py        the published exit-code contract
  scanners/
    ast_python.py        Python AST + intra-procedural taint
    python_flows.py      source -> sanitizer -> sink detectors
    rule_engine.py       multi-language YAML rule engine
    secrets.py           provider patterns, entropy, hardcoded credentials
    dependency.py        8 ecosystems, 20 manifest parsers
    advisories.py        pluggable advisory sources (bundled/directory/remote)
    sbom.py              CycloneDX 1.5 + license compliance
    spdx.py              SPDX 2.3
    iac.py, iac_extended.py   Docker/K8s/Terraform
  reporting/             json, sarif, html, markdown, junit, cyclonedx
  platform/
    database.py          engine + checksummed migration runner
    migrations/          sqlite/ and postgres/ DDL
    models.py            SQLAlchemy models (map the schema, never create it)
    security.py          PBKDF2 hashing, tokens, lockout
    rbac.py              5 roles, 19 permissions, deny by default
    tenancy.py           the only supported way to start a query
    scanning.py          engine -> database bridge, scan-root confinement
    jobs.py, worker_jobs.py   durable queue + handlers
    events.py            typed event contracts
    audit.py             append-only audit with redaction
    observability.py     structured logs, request ids, Prometheus metrics
    integrations/        webhook, GitHub, GitLab, Slack/Teams, Jira
  api/                   FastAPI app, deps, routes, schemas
  web/                   Jinja2 dashboard (no JS build step)
  rules/packs/           9 YAML packs, 66 rules
  data/                  bundled advisory + license databases
```

## Definition of done

A change is done when:

1. `pytest -q` passes (currently 410 tests)
2. the new behaviour has a test that would fail without it
3. `ironclad scan ironclad` is still clean
4. `python benchmarks/corpus_metrics.py` has not regressed precision/recall
5. new endpoints have a permission declared and a test for the denied case
6. new tables have a migration for **both** dialects and an `org_id`
7. docs reflect reality, including limitations

## Commit and PR conventions

Conventional-commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `perf:`,
`refactor:`. Describe the *reason* in the body, especially for anything a
reviewer would otherwise "fix" back — several comments in this codebase
explain why an apparently suboptimal choice is deliberate.

## CI pipeline

The full three-job pipeline (test + scanner quality, API/PostgreSQL,
end-to-end demo and packaging) is staged at **`deploy/ci/verify.yml`**.

It is not at `.github/workflows/verify.yml` because the automation account
used for this branch does not have the GitHub App `workflows` permission,
and GitHub refuses pushes that create or update workflow files without it.
Installing it is a one-line copy by anyone who does have that permission:

```bash
cp deploy/ci/verify.yml .github/workflows/verify.yml
git commit -m "ci: install the full verification pipeline" .github/workflows/verify.yml
```

Until it is installed, the repository runs the original single-job
`verify.yml` from `main`, which covers the test suite, CLI smoke tests, SBOM
generation and a throughput benchmark — but **not** the API/PostgreSQL job
or the end-to-end demo job.

Everything the new pipeline checks can be run locally in the same order:

```bash
pytest -q
python benchmarks/corpus_metrics.py --fail-below 0.95
python benchmarks/scale_benchmark.py --tiers 1000
ironclad scan ironclad --fail-on high
bash demo/run_demo.sh
python -m build --wheel
```
