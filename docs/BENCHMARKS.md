# Benchmarks

> **Historical measurements:** The numbers below were recorded on an earlier
> revision/hardware. See [UPGRADE_VALIDATION_2026-09-25.md](UPGRADE_VALIDATION_2026-09-25.md)
> for a measured run on the current upgrade; do not compare different machines
> as a release performance guarantee.

All numbers below were measured by running the scripts in `benchmarks/`
on this repository's own CI hardware, not estimated. Re-run them yourself:

```bash
python benchmarks/scale_benchmark.py --tiers 1000,10000,100000
python benchmarks/scan_benchmark.py tests/security_corpus
python benchmarks/corpus_metrics.py
```

Machine characteristics matter more than the absolute numbers, so treat
these as a *shape* (linear vs. superlinear) rather than a promise.

## Scale

`benchmarks/scale_benchmark.py` generates a synthetic repository with a
realistic mix — 70% Python modules (5% of which contain real vulnerability
patterns), the rest JavaScript noise plus manifests and IaC — then scans it.

| Files | Wall clock | Files/sec | Lines scanned | Peak RSS | Findings |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.52 s | 1,917 | 11,953 | 21 MB | 152 |
| 10,000 | 4.67 s | 2,142 | 119,413 | 26 MB | 1,412 |
| 100,000 | 47.1 s | 2,122 | 1,194,013 | 72 MB | 14,012 |

What this shows:

* **Throughput is flat**, not decaying: ~2,100 files/sec at 100k files, the
  same as at 1k. There is no quadratic pass.
* **Memory grows slowly**: 21 MB → 72 MB for a 100× increase in input.
  The engine holds findings, not the file contents.
* **Finding count scales with the planted ratio** (5% vulnerable modules →
  ~14 findings per 100 files), so the run is doing real work rather than
  skipping files.

Measured on: Linux, Python 3.11, single process, all engines enabled,
cold filesystem cache for the largest tier.

## Small-corpus throughput

```bash
python benchmarks/scan_benchmark.py tests/security_corpus
```

Reports `files_scanned`, `findings`, `elapsed_seconds` and
`files_per_second` for the 24-file labelled corpus. It is a smoke-level
measurement, not a performance gate: a benchmark that fails only on slower
CI hardware teaches people to ignore it.

## Detection accuracy

### Independently labelled Python SAST (current release gate: **FAILED**)

The full **26/26** pinned, human-authored Python subset of the independent
RealVuln Benchmark v3.1.0 was scored using its published file/CWE/±10-line
matching. With the shipped `ast-python` and `rule-engine` engines: **91 TP,
112 FP, 612 FN, 119 TN; 44.83% precision and 12.94% recall**, versus the
agreed ≥95% precision and ≥90% recall enterprise gates. An earlier revision
had 83 TP, 112 FP and 620 FN. Modelling Flask JSON and GraphQL resolver
inputs, distinguishing SQLAlchemy `text()` from unrelated calls, excluding
bound SQL values, and locating built queries at their interpolation site
matched eight additional third-party labels **without reducing the raw FP
count**. This is a bounded improvement, not a passing result. Even a
deliberately generous declared-CWE sensitivity analysis (91 TP, 112 FP,
324 FN) reaches only 44.83% precision and 21.93% recall. These are
benchmark labels and matcher results, not a human adjudication of every
alert. Other shipped scanners have not yet been independently measured; the
internal corpus below does **not** supersede the failing independent
measurement.

See the pinned manifest, target revisions, methodology, per-repository
results and caveats in
[INDEPENDENT_SAST_RESULTS_2026-09-27.json](INDEPENDENT_SAST_RESULTS_2026-09-27.json),
reproduce with [realvuln_probe.py](../benchmarks/realvuln_probe.py), and
read the [enterprise release gate](ENTERPRISE_RELEASE_GATE_2026-09-27.md).

### Small internal fixtures (historical regression measure)

`benchmarks/corpus_metrics.py` scores the labelled corpus
(`tests/security_corpus`), where every fixture is labelled by filename
(`vuln_*` must fire, `safe_*` must not):

| Metric | Value |
|---|---|
| True positives | 11 |
| False negatives | 0 |
| False positives | 0 |
| Crashes | 0 |
| Precision | 1.00 |
| Recall | 1.00 |

Recorded in `docs/CORPUS_RESULTS.json`. Gate it in CI with:

```bash
python benchmarks/corpus_metrics.py --fail-below 0.95
```

**Read the precision number with care.** The corpus is 24 hand-written
files, not real-world code. A 1.00 precision on it means "the rules do not
fire on their own safe counterparts", which is necessary but far weaker
than "no false positives on your monorepo". The script also reports
`rules_never_fired`, so a detector that silently stops working cannot hide
inside an average.

### Feed-derived dependency regression (not independent accuracy)

When run with the PyPA source pinned in the bundled snapshot, the optional
`benchmarks/independent_recall.py` probe scored **103/105, exit 1**. Two
unmatched PyPA labels assert that `cryptography==37.0.4` is vulnerable to
2026 issues in its X.509 verifier; GitHub Reviewed ranges exclude that version
and the verifier was added in cryptography 42.0.0. The raw probe **still
fails**; its improved diagnostic reports this as a source-range disagreement,
not as a nonexistent bundled advisory. See the [release-gate report](ENTERPRISE_RELEASE_GATE_2026-09-27.md)
for third-party references. Because the snapshot merges PyPA, even a perfect
feed-probe score would be partly circular and would not establish accuracy of
the shipped dependency scanner on independent code.

## Server-side throughput

By default, `POST /scan` queues a job and returns `202` without waiting
for scanning. `wait: true` opts into an inline scan for small trees and does
block until that scan finishes. The worker claims jobs from the same table;
`deploy/k8s/50-hpa.yaml` scales the worker Deployment independently of the API.

Measured API overhead per request is dominated by the database round trip,
not by scanning. `ironclad_api_request_duration_seconds` and
`ironclad_worker_job_duration_seconds` are exposed at `/metrics` so you can
measure your own deployment rather than trusting ours.

## What is deliberately not benchmarked

* **Startup time of a PyInstaller binary** — machine- and antivirus-specific.
* **Network advisory fetch** — the default source is offline; timing a
  network call measures your egress, not the product.
* **PostgreSQL query latency** — depends entirely on your instance size,
  connection pooling and storage. The migration set includes indexes that
  lead with `org_id` because that is always the first predicate; verify
  with `EXPLAIN ANALYZE` on your own data.
