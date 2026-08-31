# Benchmarks

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

## Server-side throughput

The API never blocks on a scan: `POST /scan` inserts a row and returns
`202`. The worker claims jobs from the same table, so scaling is a matter
of adding workers (`deploy/k8s/50-hpa.yaml` scales the worker Deployment
independently of the API).

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
