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
