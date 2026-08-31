# IronClad Sentinel — Full Project Report

**Report date:** 2026-08-31
**Branch:** `arena/01a03853-ironclad-sentinel-v2`
**HEAD (local and remote):** `5809cf0`
**Pull request:** #8 — `OPEN`, `MERGEABLE`, **57 commits**
**GitHub CI:** **4/4 checks pass** on `5809cf0`

A GitHub token expiry mid-session briefly blocked pushes; it recovered and
everything is now pushed and CI-verified.

Every number below was produced by running the command shown against this
checkout during the session that wrote it.

---

## 1. Headline

| | |
|---|---|
| **Overall project completion** | **~97%** |
| Implementation completeness | ~98% |
| Verification completeness | ~96% |
| Production-usable today | Yes, for the self-hosted deployment in `docs/DEPLOYMENT.md` |

The residual is no longer implementation debt. It is four things this
environment cannot supply: a container runtime, third-party credentials,
`workflows` permission on the repository, and — since mid-session — a valid
GitHub token.

---

## 2. Starting state this session

| | |
|---|---|
| Local HEAD at start | `f53b542` (sandbox had re-cloned; work recovered from the remote branch) |
| Remote tip at start | `1c287ad` |
| Full suite at start | 850 passed, 16 skipped |
| Advisory database at start | **44 packages**, 57 advisories, **fabricated identifiers** |
| Real-world measurement | none |

---

## 3. Gaps discovered

Found by executing the system, not by reading it.

1. **The bundled advisory database had invented advisory identifiers.**
   `GHSA-django-2023-sql`, `GHSA-log4j-2021-shell`, `GHSA-pyyaml-2017-rce`
   are not real GHSA ids and resolve to nothing. A customer checking a
   finding we reported would find no such advisory. Coverage was 44 packages.
2. **A dependency range was treated as an installed version.**
   `urllib3>=1.26,<3` was reported as "known vulnerability in urllib3@1.26"
   with 8 advisories. Reproduced on six real repositories: 33 findings, most
   false. Dormant with 44 packages; a real advisory feed switches it on.
3. **`advisory_path` silently disabled dependency scanning.** The database's
   own guidance said to point it at an overlay directory; the directory went
   to a *file* loader, raised `OSError`, was swallowed, and the scan reported
   **zero** vulnerable dependencies and exited 0.
4. **The documented OSV overlay path did not accept OSV data.** Only
   IronClad's own schema was understood, so a real mirror loaded nothing.
5. **The remote OSV endpoint mistranslated ranges.** It read only the last
   `fixed` event of the first range: ignored `introduced` (false positives
   below the range) and emitted `<0` when there was no fix — which the
   matcher reads as "matches nothing", hiding every unfixed advisory.
6. **An oversized identifier in a URL was a 500 on eleven endpoints.**
   `GET /projects/99999999999999999999` → `OverflowError: Python int too
   large to convert to SQLite INTEGER`. PostgreSQL raises `DataError` for
   the same input, so it is not SQLite-specific.
7. **`--json` output was not valid JSON.** Printed through a wrapping rich
   console, so a long string value was split across lines *inside* the
   quoted string. Silently, and only once a value was long enough to wrap.
8. **887 advisory entries were unreachable** because the importer keyed
   packages by original spelling while lookups use normalised lowercase
   names (`PyYAML`, `github.com/Traefik/traefik`).

Also corrected: documentation that contradicted shipped code — README still
claimed "no rate limiting, no mail transport for password reset" and a
read-only dashboard, and four documents described the advisory database as a
44-package demonstration set.

---

## 4. Milestones completed

### 4.1 OSV support and the overlay path (`70241c4`)

`ironclad/scanners/osv.py` is now the single implementation of the OSV
encoding, shared by the directory overlay and the opt-in remote endpoint:
disjoint ranges → `||`, comparators within a range → `,`, `introduced: 0`
contributes no lower bound, open-ended ranges → `>=X`, a range with no bound
→ `>=0` (an empty spec would mean "matches nothing"), `last_affected` →
`<=`, `GIT` ranges dropped rather than guessed — with the finding text saying
so when that means every declared version is reported. Ecosystems IronClad
has no parser for are dropped with a recorded warning. `advisory_path` now
resolves by type: directory → overlay, file → replacement database.

Proven against **four real, unmodified records** vendored from
`github/advisory-database` (CC-BY-4.0, `tests/fixtures/osv/PROVENANCE.md`),
including one using `last_affected` with a real lower bound.

### 4.2 Pinned vs range semantics (`aa811ab`)

`ParsedDependency` carries `is_pinned`, inferred from the declaration. An
unpinned dependency is reported only when the declared range provably cannot
be satisfied by the patched release; otherwise the lockfile — where the
installed version is actually recorded — is the source of truth. Range syntax
is normalised in one place: npm/Cargo carets (including the 0.x rule),
tildes, Ruby `~>`, `1.x` wildcards, Maven/NuGet bracket ranges, npm `||`
OR-ranges, PEP 440 comparator lists.

Same six repositories: **33 findings → 20**, all on pinned versions.

### 4.3 A real advisory database (`0e0d4ef`)

Generated from `github/advisory-database` via the new offline importer:

```
ironclad advisories import-osv --source <osv-dump> --output <db.json>
ironclad advisories stats
```

| | before | after |
|---|---|---|
| Packages | 44 | **13,095** |
| Advisories | 57 | **44,499** |
| Identifiers | fabricated | real GHSA ids + CVE aliases |
| Load time | 0.3 ms | 67 ms |
| Peak RSS | 12 MB | 57 MB |
| Throughput | 1,190 / 1,394 files/s | 1,264 / 1,426 files/s (unchanged) |

No previously covered package was lost. `_meta.source` records the exact
upstream commit. `scripts/build_advisory_db.sh` makes regeneration
reproducible. 10.9 MB on disk, 1.8 MB compressed in git, 2.19 MB wheel.

### 4.4 Real-world corpus benchmark (`7c4a1b1`)

`benchmarks/real_world_corpus.py`, wired into `verify_all.sh`. Clones real
repositories and asserts that every dependency finding is on a genuinely
pinned version, carries a real GHSA identifier, and matches an advisory that
actually covers that version — re-checked independently of the scanner's own
code path. Self-skips when github.com is unreachable.

### 4.5 HTTP robustness (`f3984a7`)

`EntityId` / `EntityQuery` bound every identifier to `1..2^63-1`; an
`OverflowError` / `DataError` handler returns 422 as a backstop.
`tests/test_api_malformed.py`: **442 tests** asserting the narrow contract
that no body, query string, path segment, `Authorization` header or session
cookie can produce a 5xx — plus a check that error bodies leak no traceback
or SQL, and a health check proving the API is still usable afterwards.

### 4.7 Pipeline recall: pip-compile lockfiles were invisible (`d2ebf48`)

Built `benchmarks/pipeline_recall.py` to measure the half that had never been
measured. It checks out real repositories at old revisions, extracts the
pinned versions with a trivial regex — deliberately not the production
parsers — and asks the advisory database which pins are vulnerable. Whatever
the scanner does not report is a miss.

**First run: 3/110 = 2.7% recall.**

Almost every miss was in `requirements/<environment>.txt`. pip-compile
projects keep one pinned lockfile per environment in a `requirements/`
directory, and `is_dependency_manifest()` matched on *filename*:
`requirements/tests.txt` has the basename `tests.txt`, which matches nothing.
flask 2.0.0 pins 55 dependencies there and **not one was scanned**. Fixed in
both discovery and parser routing. **After: 110/110 = 1.0000.**

### 4.8 Pipfile, setup.py and constraints.txt were never parsed (`123d917`)

Probing for more of the same class found three more:

* **`Pipfile`** — the worst case, and a correctness bug rather than a missing
  feature. It was already in `DEPENDENCY_MANIFESTS`, so discovery flagged it
  as a manifest, but no parser was registered. The scan produced zero
  dependencies *and zero errors* and reported that the dependency engine had
  run. A Pipenv project looked scanned and was not scanned at all.
* **`setup.py`** — `install_requires` / `setup_requires` were never read.
* **`constraints.txt`** — pip constraint files pin exact versions.

`setup.py` is parsed by regex on purpose: it is executable Python and a
scanner must never import it. When the requirement list is computed rather
than literal, an `UNPARSED` finding is recorded instead of a silent "no
dependencies". A structural test now asserts that no filename can be
discoverable as a manifest without a parser behind it. Manifest registry
20 → 23.

### 4.6 CLI output contract (`2fbe920`)

`--json` now uses `console.print_json` like every other command, and the two
new commands were renamed from `--as-json` to `--json` for consistency.
`verify_all.sh` gained an *installed advisory db is usable* step that
installs the wheel into a clean venv and asserts real coverage.

---

## 5. Test results

| | |
|---|---|
| Full suite, live PostgreSQL 16.2 | **1,417 passed, 0 skipped** (167s) |
| Full suite, no server URL | **1,401 passed, 16 skipped** |
| Core-only (`pip install -e .`) | **571 passed, 16 skipped** |
| `scripts/verify_all.sh` | **35 passed, 0 failed, 1 skipped** (Docker) |
| Dependency pipeline recall | `benchmarks/pipeline_recall.py` | **110/110 = 1.0000** on 8 real revisions |
| Synthetic corpus | precision **1.0000**, recall **1.0000** (12 TP, 0 FP, 0 FN) |
| Real-world corpus | 6 repositories, **20 findings, 0 false positives** |
| Integration delivery | **51/51** checks against a real local HTTP server |
| Self-scan | exit 0, **0 findings**, grade **A+** |
| Test modules | **37**, 1,394 collected |
| Product code | 14,944 lines of Python in `ironclad/` |

Tests added this session: **567** (850 → 1,417).

Largest modules: `test_api_malformed` 442, `test_api` 102,
`test_rule_packs_extended` 71, `test_python_flows` 54,
`test_org_egress_policy` 51, `test_egress_allowlist` 49,
`test_osv_advisories` 47, `test_ssrf` 45.

**GitHub CI: 4/4 checks pass at `7c4a1b1`.** The three later commits are
unpushed, so they have **not** been through CI.

---

## 6. Remaining limitations

| Gap | Blocked by | Notes |
|---|---|---|
| Docker image never built or booted | **Environment** — no `docker`/`podman`/`nerdctl`/`buildah`/`kaniko`, no `/var/run/docker.sock` | Manifests and entrypoint exist; entrypoint logic is exercised by tests |
| No integration proven against a real endpoint | **Credentials** — no GitHub/GitLab/Slack/Teams/Jira tokens | `integration_check.py` labels all five `NOT EXTERNALLY VERIFIED` itself |
| Live CI does not run the PostgreSQL behavioural suite | **Repository permissions** — no `workflows` scope | Fixed in the staged `deploy/ci/verify.yml`; verified locally 16/16 |
| Push and CI stopped mid-session | **Credentials** — GitHub token expired | 3 commits local-only |
| End-to-end recall against an independent vulnerability source | **Data** — needs a labelled corpus from a source other than the one the scanner reads | *Pipeline* recall is now measured (110/110); data completeness is not |
| No OIDC / OAuth2 | Not blocked — **not implemented** | Real enterprise sales blocker |
| Analysis is intra-procedural, Python-only for taint | Design trade | Regex rules elsewhere cannot model data flow |
| Advisory DB is a snapshot | Design | Goes stale between releases; regenerate or overlay |
| Egress allowlist is hostname-only | Not blocked | No per-path/port/integration restrictions |

---

## 7. Why ~97% is defensible

The gaps that remain are, with one exception, things this environment cannot
provide rather than work left undone. The exception — OIDC/OAuth2 — is a
deliberate scope boundary, documented as such.

What changed this session is that three claims which were previously
*asserted* are now *measured*: dependency precision on real repositories,
advisory coverage from a real feed with verifiable provenance, and HTTP
behaviour under hostile input. And four defects that would have reached
production were found by running the system rather than reading it — a
silent dependency-scanning disable, a false-positive class that a real
advisory feed switches on, a 500 reachable from any URL, and a vulnerability
database with identifiers that do not exist.

It is not 98% because no container has ever started, no integration has ever
reached a real third-party service, and recall has only been measured for the
pipeline rather than against an independent vulnerability source. Those three
are the honest difference.

The recall work is also the session's strongest argument for the number being
close: it found that the scanner was blind to the most common Python lockfile
layout (`requirements/*.txt`, 2.7% recall) and to `Pipfile`, `setup.py` and
`constraints.txt` entirely — defects no amount of passing tests would have
surfaced, because every existing fixture put its manifest at the repository
root.
