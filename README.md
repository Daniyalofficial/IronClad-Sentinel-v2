# IronClad Sentinel

**Offline, self-hosted Application Security scanning platform.**
Zero telemetry. Zero external API calls. Zero "phone home." Runs entirely
inside your own network, air-gapped environment, or laptop.

Built for security/AppSec teams who need SAST + secrets + dependency-CVE
+ Infrastructure-as-Code + SBOM/license-compliance scanning but whose
policies (finance, healthcare, defense, or just sane engineering) forbid
shipping proprietary source code to a third-party SaaS scanner.

---

## Why this exists

Every mainstream competitor in this space (Snyk, Semgrep Cloud, Checkov
Cloud, etc.) is, at its core, a SaaS product: your source code, or at
minimum metadata about it, transits their servers. For a large class of
enterprise buyers -- regulated industries, defense contractors, anyone
handling customer PII -- that's a non-starter regardless of how good the
detection engine is.

IronClad Sentinel is architected around one hard constraint from day
one: **the tool must fully function with the network cable unplugged.**
Every engine, every rule, every report format, and even license
verification are 100% local computation. That constraint becomes the
sales pitch: "the only enterprise-grade scanner your security team will
actually approve to touch the crown-jewel repo."

## What's inside

| Engine | What it does |
|---|---|
| **Deep Python AST analyzer** | Real taint analysis (not just regex): tracks untrusted input from request params/env/stdin into SQL execution, shell exec, `eval`, deserialization sinks. Also flags structural issues (assert-based auth checks, debug flags, weak hashes, disabled TLS verification, mutable default args). |
| **Multi-language rule engine** | A YAML rule DSL (like Semgrep, but simpler and fully offline) with bundled packs for JavaScript/TypeScript, Java, Go, Ruby, PHP, C#, Terraform, Kubernetes YAML, SQL, Shell, Dockerfiles, and generic secret patterns. Easy to extend with your own `.yml` rule packs. |
| **Secrets detector** | Known-provider token regexes (AWS, GitHub, Stripe, Slack, Google, DB connection strings, PEM private keys) PLUS a Shannon-entropy-based generic detector that catches custom/internal secrets no vendor regex would recognize. |
| **Dependency vulnerability scanner** | Parses `requirements.txt`, `package.json`, `go.mod` and matches installed versions against a bundled, curated offline advisory database (`ironclad/data/vuln_db.json`) -- update this file during your own controlled release process; the tool never fetches it live. |
| **IaC misconfiguration scanner** | Dedicated Dockerfile analysis (missing USER, privileged patterns, curl\|sh, hardcoded secrets in ENV/ARG, floating tags, missing HEALTHCHECK) plus Kubernetes/Terraform rules via the rule engine. |
| **SBOM generator** | Produces a CycloneDX 1.5 JSON SBOM from discovered manifests -- the format most enterprise procurement/compliance processes now require. |
| **License compliance checker** | Flags dependencies under strong-copyleft licenses (GPL/AGPL) that commonly trigger legal review. |

Reports export as **JSON, SARIF 2.1.0** (native GitHub Code Scanning /
Azure DevOps ingestion), **HTML** (dark-themed, shareable), **Markdown**
(perfect for PR comments), and **JUnit XML** (renders in virtually every
CI system's native test-results UI).

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Generate the intentionally-vulnerable demo fixture (not committed to
# git -- generated at runtime so no secret-shaped string ever lives in
# git history/trips GitHub push protection) and scan it
python demo/generate_vulnerable_app.py
ironclad scan demo/vulnerable_app --format json,html,sarif --output-dir /tmp/reports

# Generate an SBOM
ironclad sbom demo/vulnerable_app --out sbom.json

# Check license status
ironclad license status
```

Trial mode (no license file installed) runs the AST + rule-engine +
secrets scanners with no time limit and no size limit -- enough for a
real evaluation. A full license additionally unlocks the
dependency/IaC/license-compliance engines and is what you'd actually
gate CI enforcement on.

## CI/CD integration

Drop-in configs are provided for:
- `integrations/github-actions/ironclad-scan.yml` -- uploads SARIF straight into GitHub's native Security tab.
- `integrations/gitlab-ci/.gitlab-ci.yml` -- surfaces JUnit results in GitLab's native pipeline UI.
- `integrations/pre-commit/pre-commit-hook.sh` -- blocks commits introducing new high/critical findings, fully local.

## Baseline / gradual adoption

First scans of a real codebase often surface a big backlog. Snapshot it
once and gate CI only on *new* findings going forward:

```bash
ironclad scan . --update-baseline --baseline .ironclad/baseline.json
# later, in CI:
ironclad scan . --baseline .ironclad/baseline.json --fail-on high
```

## Licensing model (how this makes money)

IronClad Sentinel ships with an **offline Ed25519-signed license system**
(`ironclad/licensing/keygen.py`). There is no license server and no
recurring hosting cost for you:

1. Run `python -m ironclad.licensing.keygen init-keypair` **once**, ever,
   on a machine you control. Keep the private key secret; the public key
   ships inside the product.
2. When someone pays, run `issue-license` to generate a small signed
   `license.json` and email it to them.
3. The customer drops it at `~/.ironclad/license.json`. Every run
   verifies the signature locally against the bundled public key -- no
   internet connection required on either side, ever.

This means your entire revenue operation is: collect payment -> run one
local command -> send a file. No infrastructure to maintain, no uptime
SLA to worry about, and it's a genuine sales advantage (buyers in
regulated industries specifically prefer license enforcement that
doesn't require an outbound network call).

See `docs/PRICING_AND_GTM.md` for a suggested tiering/pricing model and
sales positioning.

## Packaging & distribution

```bash
bash scripts/build_release.sh
```

Produces both a standard Python wheel (for customers with their own
Python/pip setup or internal package index) and a single-file
PyInstaller binary with zero Python dependency at all -- the strongest
"just hand me a binary" option for locked-down customer environments.

Customers install with:

```bash
bash scripts/customer_install.sh ironclad_sentinel-1.0.0-py3-none-any.whl license.json
```

## Extending detection

Add your own rule packs (no code changes required) by dropping YAML
files following the schema documented in `ironclad/rules/schema.py` into
a directory referenced by `custom_rules_dirs` in `.ironclad.yml`. See
`.ironclad.example.yml` for the full configuration surface.

## Running the test suite

```bash
pip install -e . pytest
python -m pytest tests/ -v
```

## Project layout

```
ironclad/
  cli.py                    entrypoint (click-based CLI)
  core/                     config, file discovery, data models, orchestration engine, baseline diffing
  scanners/                 the six detection engines
  rules/                    YAML rule DSL loader + bundled rule packs
  reporting/                JSON/SARIF/HTML/Markdown/JUnit renderers
  licensing/                offline Ed25519 license issuance & verification
  data/                     bundled offline vulnerability + license databases
demo/generate_vulnerable_app.py  generates the intentionally-vulnerable app fixture at runtime (gitignored output)
integrations/               GitHub Actions, GitLab CI, pre-commit hook templates
scripts/                    build & customer installation scripts
tests/                      pytest suite (39+ tests across every engine)
docs/                       pricing/GTM notes, architecture notes
```

## Explicitly out of scope (by design)

- No telemetry, analytics, or crash reporting of any kind.
- No auto-update mechanism that phones home.
- No live vulnerability-feed API calls at scan time (update
  `ironclad/data/vuln_db.json` yourself during releases).
- No license-server dependency for verification.

If a feature request would require any of the above, it doesn't belong
in this product -- that constraint *is* the product.
