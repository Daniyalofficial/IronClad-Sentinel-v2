# Architecture Notes

## Data flow

```
                          ironclad scan <target>
                                  |
                                  v
                   ironclad.core.config.IronCladConfig
                    (defaults <- .ironclad.yml <- CLI flags)
                                  |
                                  v
                     ironclad.core.walker.discover()
              (single filesystem walk -> FileSet, classified
               by language + dependency-manifest + IaC-kind)
                                  |
        +---------+---------+----+----+---------+----------+
        |         |         |         |         |          |
        v         v         v         v         v          v
   AST-Python  Rule-Engine Secrets  Dependency   IaC   License-Compliance
   (ast module) (regex DSL) (regex+  (manifest   (Dockerfile  (manifest ->
                             entropy) parsing +   line parser  license DB)
                                      offline DB) + rule pack)
        |         |         |         |         |          |
        +---------+---------+----+----+---------+----------+
                                  |
                                  v
                    List[Finding]  (normalized schema)
                                  |
                  filter (min_severity, ignore_rule_ids)
                                  |
                    de-duplicate by content fingerprint
                                  |
                    baseline diff (suppress known findings)
                                  |
                                  v
                            ScanResult
                     (risk score, grade, stats)
                                  |
                +--------+--------+--------+--------+
                v        v        v        v        v
              JSON     SARIF     HTML   Markdown   JUnit
```

## Why a single `Finding` schema matters

Every engine ultimately constructs `ironclad.core.models.Finding`
objects. This is the single most important architectural decision in
the codebase:

- **De-duplication works across engines for free.** If the rule engine
  and the AST analyzer both notice the same `eval()` call for different
  reasons, the content-based fingerprint (rule_id + file + normalized
  snippet + category) collapses them to one finding rather than
  reporting the same line twice.
- **Baseline diffing is engine-agnostic.** A baseline snapshot doesn't
  care which engine originally found something; it just needs a stable
  fingerprint, so adding a 7th engine later doesn't require touching
  the baseline logic at all.
- **All 5 report formats are pure functions of `ScanResult`.** Adding a
  6th format (e.g. a Jira-ticket-creation payload, or a CSV export for
  spreadsheet-oriented auditors) is a self-contained new file in
  `ironclad/reporting/` with zero changes anywhere else.

## Fingerprinting strategy (why not line-number based)

Naive scanners fingerprint findings by `(file, line_number)`. This
breaks the moment someone adds an unrelated line above the flagged code
-- the finding "moves" and looks like a brand new issue, defeating
baseline suppression and creating noisy "N new findings" reports for
zero actual code change.

`Finding.compute_fingerprint()` instead hashes
`(rule_id, file_path, normalized_snippet[:400], category)` where the
snippet has all whitespace stripped. This means:
- Editing whitespace/formatting elsewhere in the file doesn't change
  the fingerprint.
- The finding survives as long as the actual flagged code snippet is
  unchanged, even if its line number shifts.
- Genuinely different code that happens to land on the same line number
  after an edit gets a *different* fingerprint, correctly treated as a
  new finding.

This is a deliberate, non-trivial design choice that materially reduces
false "regression" noise in CI compared to naive competitors -- worth
highlighting in sales conversations with teams that have been burned by
noisy line-based diffing in other tools.

## Extending with a 7th engine

1. Create `ironclad/scanners/my_engine.py` exposing a function that
   takes whatever inputs it needs (a `DiscoveredFile`, or the full
   `FileSet`) and returns `List[Finding]`.
2. Wire it into `ironclad/core/engine.run_scan()` behind a new
   `enabled_engines` name.
3. Add the engine name to `IronCladConfig.enabled_engines` default list
   and to the CLI's trial-mode allowlist decision in `cli.py` if it
   should be trial-available.
4. Nothing else needs to change -- reporting, baseline diffing, CLI
   flags, and de-duplication all work automatically because they only
   depend on the `Finding` schema.

## Performance characteristics

- The filesystem is walked exactly once regardless of how many engines
  are enabled (`ironclad.core.walker.discover`), which is the main
  reason this scans large monorepos fast compared to tools that shell
  out to N separate CLI processes each doing their own tree walk.
- The AST engine parses each Python file exactly once and runs both the
  structural visitor and per-function taint visitors over the same
  parsed tree -- no re-parsing.
- The rule engine pre-filters which rules are even attempted per file
  by language before touching file content, so a repo with 40 rule
  packs loaded doesn't pay for languages it doesn't contain.
- All engines are pure-Python with no subprocess spawning (unlike
  wrapping external CLI tools), which avoids per-file process-spawn
  overhead entirely.

---

## Platform layer (added in 1.1.0)

The scanner above is unchanged. The platform wraps it without the scanner
knowing: `ironclad.platform.scanning.perform_scan` is the *only* bridge, and
it is what the CLI, the API and the worker all call.

```
        CLI (ironclad scan)          POST /scan (API)
                 \                        |
                  \                       v
                   \              jobs table (queued)
                    \                     |
                     \                    v
                      \----->  worker claims the job
                                    |
                                    v
                    core.engine.run_scan(config, policy)
                                    |
                                    v
                        platform.scanning.perform_scan
                        ├── persist Scan / Finding rows
                        ├── resolve previous findings
                        ├── build + persist SBOM/components
                        ├── evaluate policy (deterministic)
                        └── publish typed events
                                    |
                        ┌───────────┼────────────┐
                        v           v            v
                    database     events     integrations
```

### Why the queue is a table and not a broker

A durable queue in the database gives retries, crash recovery, backoff and
"what is stuck?" visibility without requiring Redis in a single-node
install. `JobQueue.claim()` uses a single `UPDATE … WHERE id = (SELECT …)`
so two workers cannot claim the same row, and the claim is **committed
before the handler runs** — otherwise a rollback on handler failure would
un-claim the job and an always-failing job would retry forever. That is not
hypothetical; it is a bug this design had and a test now prevents.

The interface is deliberately narrow (`enqueue` / `claim` / `finish`), so a
Redis/RQ or Celery backend can replace it without touching the API or the
scanner.

### Why one session per request

`ironclad.api.deps.get_db` opens one session, attaches it to the request
context, and closes it at the end. That is what makes
`context.audit(...)` write into the *same transaction* as the change it
describes. An audit record committed separately from the mutation it
records is how you end up with an audit log that lies.

### Multi-tenancy is enforced at the query layer

`org_query()` refuses a model with no `org_id` column. That converts "did
the author remember the filter?" from a review question into an import-time
error. A row belonging to another organization returns `None`, which the API
turns into a **404** rather than a 403 — a 403 is an existence oracle.

### Events are contracts, not notifications

`events.EVENT_SCHEMAS` declares the required payload keys per event type,
and publishing a payload that violates it raises. A consumer therefore never
has to guess whether `scan_id` is present. Handlers cannot fail the
publisher: exceptions are caught and surfaced through `EventBus.errors` and
the `integration.failed` event.

### Migrations, not `create_all()`

Schema lives in numbered SQL files, one folder per dialect, each applied in
its own transaction and checksummed. Editing an applied migration raises
rather than letting environments drift. `tests/test_database.py` asserts the
two dialect folders stay in sync, so PostgreSQL cannot silently fall behind
SQLite.

## Where the guarantees are tested

| Guarantee | Test |
|---|---|
| One `Finding` schema across all engines | `tests/test_engine_and_reports.py` |
| Deterministic policy decisions | `tests/test_policy.py::test_evaluation_is_deterministic` |
| Baseline gates only new findings | `tests/test_baseline_v2.py` |
| Cross-tenant isolation | 6 tests in `tests/test_api.py` |
| Scan-root confinement incl. symlink escape | `tests/test_security.py` |
| Secrets never emitted | `tests/test_secrets.py`, `tests/test_security.py` |
| Migrations idempotent and tamper-evident | `tests/test_database.py` |
| Self-scan stays clean | `tests/test_security.py::test_self_scan_is_clean` |
| Detection accuracy | `benchmarks/corpus_metrics.py` (gated in CI) |
