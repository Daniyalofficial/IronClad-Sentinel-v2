#!/usr/bin/env python3
"""Independently score the shipped Python SAST engines against RealVuln.

Usage:
  git clone https://github.com/kolega-ai/Real-Vuln-Benchmark.git /tmp/realvuln
  git -C /tmp/realvuln checkout --detach 3aa5a1069685cce00b472defcde1a94499418673
  # Use that release's clone_repos.py to fetch all 26 pinned human Python targets.
  # Do not use the later HEAD: its manifest has a stale ground-truth hash.
  python benchmarks/realvuln_probe.py --benchmark-dir /tmp/realvuln \
      --write-results docs/INDEPENDENT_SAST_RESULTS_2026-09-27.json

No target project is imported or executed. The external benchmark's *scorer*
is used unchanged, with its public file+CWE+line matcher (10-line tolerance).
Every unlabeled SAST alert is counted as a false positive under that scoring
protocol. Both independent GT provenance and target commits are verified. A
subset is useful for triage but cannot pass the full human-Python corpus gate.
Other scanners (secrets, dependencies, IaC, licenses) require *separate*
independent ground truth before any combined release accuracy can be claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ironclad.core.config import IronCladConfig  # noqa: E402
from ironclad.core.engine import run_scan  # noqa: E402

ENGINES = ("ast-python", "rule-engine")
SCANNER_ROOT = Path(__file__).resolve().parents[1] / "ironclad"


def declared_cwes() -> set:
    """A generous, label-blind bound on the CWEs named by shipped SAST rules.

    This includes rule-code comments as well as actual rule fields, so it can
    only *overstate* declared scope; it never selects labels based on success.
    """
    sources = [SCANNER_ROOT / "scanners" / "ast_python.py",
               SCANNER_ROOT / "scanners" / "python_flows.py",
               *sorted((SCANNER_ROOT / "rules" / "packs").glob("*.yml"))]
    cwes = set()
    for path in sources:
        cwes.update(re.findall(r"\bCWE-[0-9]{1,5}\b", path.read_text(encoding="utf-8")))
    return cwes


class ProbeError(ValueError):
    pass


def _checked_truth(root: Path) -> tuple[dict, str]:
    manifest = json.loads((root / "benchmark-manifest.json").read_text(encoding="utf-8"))
    h = hashlib.sha256()
    files = sorted((root / "ground-truth").glob("*/ground-truth.json"),
                   key=lambda path: path.relative_to(root).as_posix())
    if not files:
        raise ProbeError("benchmark has no ground truth files")
    for path in files:
        h.update(path.relative_to(root).as_posix().encode("utf-8"))
        h.update(b"\n")
        h.update(path.read_bytes())
    computed = "sha256:" + h.hexdigest()
    if computed != manifest.get("ground_truth_content_hash"):
        raise ProbeError("benchmark ground truth differs from its public manifest")
    return manifest, computed


def verify_target_checkout(target: Path, expected_sha: str,
                           required_files: list[str]) -> None:
    """Reject a pinned HEAD with missing sources (including sparse checkouts).

    `git clone --no-checkout` still gives `rev-parse HEAD` the right commit,
    but scanning its empty worktree produces an invalid, deceptively precise
    measurement. Neither that nor a dirty target is a valid pinned corpus.
    """
    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", "-C", str(target), *args], check=True,
                                  capture_output=True, text=True, timeout=20).stdout.strip()
        except (subprocess.SubprocessError, OSError) as exc:
            raise ProbeError(f"cannot verify pinned target {target.name}") from exc

    if git("rev-parse", "HEAD") != expected_sha:
        raise ProbeError(f"target {target.name} is not at its ground-truth commit")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ProbeError(f"pinned target {target.name} is not clean; check out all sources")
    for name in required_files:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not (target / path).is_file():
            raise ProbeError(f"pinned target {target.name} missing labeled source: {name}")
    try:
        sparse = subprocess.run(["git", "-C", str(target), "config", "--bool",
                                 "core.sparseCheckout"], capture_output=True, text=True,
                                timeout=20)
    except (subprocess.SubprocessError, OSError) as exc:
        raise ProbeError(f"cannot verify pinned target {target.name}") from exc
    if sparse.returncode == 0 and sparse.stdout.strip() == "true":
        raise ProbeError(f"pinned target {target.name} uses a sparse checkout")


def measure(root: Path, slugs=None) -> dict:
    root = root.resolve()
    manifest, truth_hash = _checked_truth(root)
    sys.path.insert(0, str(root))  # use the benchmark's own scorer, not our labels
    from parsers.base import NormalisedFinding  # noqa: PLC0415
    from scorer.matcher import load_ground_truth, match_findings  # noqa: PLC0415
    from scorer.metrics import compute_scorecard  # noqa: PLC0415

    families = json.loads((root / "config" / "cwe-families.json").read_text(encoding="utf-8"))
    candidates = {}
    for path in sorted((root / "ground-truth").glob("*/ground-truth.json")):
        gt = load_ground_truth(str(path))
        if gt.get("language") == "python" and gt.get("authorship") == "human_authored":
            candidates[path.parent.name] = gt
    if not candidates:
        raise ProbeError("no human-authored Python benchmarks found")
    selected = sorted(slugs or candidates)
    if not selected or any(slug not in candidates for slug in selected) or len(set(selected)) != len(selected):
        raise ProbeError("requested repo missing or duplicated in human-authored Python corpus")

    summary = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    supported = {"tp": 0, "fn": 0, "fp": 0}
    shipped_cwes = declared_cwes()
    rows = []
    for slug in selected:
        gt = candidates[slug]
        target = root / "repos" / slug
        if not target.is_dir():
            raise ProbeError(f"missing pinned target {slug}; run {root / 'clone_repos.py'} --repo {slug}")
        actual = gt.get("commit_sha")
        labeled_sources = sorted({finding["file"] for finding in gt["findings"]
                                  if finding.get("is_vulnerable") and finding.get("file")})
        verify_target_checkout(target, actual, labeled_sources)
        # The evaluated source itself is untrusted: never honor its
        # .ironclad.yml (or a workstation user config) when choosing engines.
        config = IronCladConfig(target=str(target), enabled_engines=list(ENGINES),
                                report_formats=["json"])
        scan = run_scan(config)
        findings = [NormalisedFinding(
            file=f.location.file_path, cwe=f.cwe or "", line=f.location.start_line,
            function=None, severity=f.severity.value, rule_id=f.rule_id,
            message=f.title, scanner="ironclad",
        ) for f in scan.findings]
        match = match_findings(findings, gt)
        for entry in match:
            if entry.classification == "FP":
                supported["fp"] += 1  # every unmatched shipped-SAST alert is counted
            elif entry.classification in ("TP", "FN") and entry.ground_truth_entry:
                if set(entry.ground_truth_entry.get("acceptable_cwes", [])) & shipped_cwes:
                    supported[entry.classification.lower()] += 1
        card = compute_scorecard(gt["repo_id"], "ironclad",
                                 datetime.now(timezone.utc).isoformat(), match, families)
        row = {"slug": slug, "target_sha": actual, "files_scanned": scan.stats.files_scanned,
               "findings": len(findings), "tp": card.tp, "fp": card.fp,
               "fn": card.fn, "tn": card.tn, "precision": round(card.precision, 4),
               "recall": round(card.recall, 4),
               "missed_ids": [r.ground_truth_id for r in match if r.classification == "FN"],
               "unmatched_rules": sorted({r.scanner_finding.rule_id for r in match
                                          if r.classification == "FP" and r.scanner_finding}),
               }
        rows.append(row)
        for key in summary:
            summary[key] += row[key]
        print(f"{slug}: TP={card.tp} FP={card.fp} FN={card.fn} TN={card.tn} "
              f"files={scan.stats.files_scanned}", flush=True)
    tp, fp, fn = summary["tp"], summary["fp"], summary["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    scoped_tp, scoped_fn, scoped_fp = supported["tp"], supported["fn"], supported["fp"]
    supported_scope = {
        "declared_cwes_generously_extracted": sorted(shipped_cwes),
        "counts": supported,
        "precision": round(scoped_tp / (scoped_tp + scoped_fp), 4) if scoped_tp + scoped_fp else 0.0,
        "recall": round(scoped_tp / (scoped_tp + scoped_fn), 4) if scoped_tp + scoped_fn else 0.0,
    }
    fully_covered = len(selected) == len(candidates)  # no cherry-picked subset can certify
    return {"benchmark_commit": subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                text=True, check=True, timeout=10).stdout.strip(),
            "benchmark_version": manifest.get("benchmark_version"),
            "truth_hash": truth_hash, "engines": list(ENGINES),
            "corpus": "human-authored Python repositories (SAST only)",
            "repos_measured": len(selected), "repos_required": len(candidates),
            "full_corpus": fully_covered, "counts": summary,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "generous_declared_cwe_scope": supported_scope,
            "caveats": [
                "RealVuln's labels may be incomplete; unmatched alerts are FPs under its published protocol, not a human-adjudicated real-world precision.",
                "Only ast-python and rule-engine were evaluated here. Other shipped scanners require separately labelled external corpora.",
                "Python-only measurement does not establish deep multi-language reachability or universal vulnerability coverage.",
                "Generous declared-CWE scope is a sensitivity analysis, not a replacement for the full benchmark; it is inferred from scanner source independently of outcome and still counts all unmatched alerts.",
            ],
            "repos": rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-dir", type=Path, required=True)
    parser.add_argument("--repo", action="append", dest="repos",
                        help="choose a pinned target for triage (repeatable); subset never certifies gate")
    parser.add_argument("--write-results", type=Path)
    parser.add_argument("--min-precision", type=float, default=0.95)
    parser.add_argument("--min-recall", type=float, default=0.90)
    args = parser.parse_args(argv)
    try:
        result = measure(args.benchmark_dir, args.repos)
    except (ProbeError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"INVALID MEASUREMENT: {exc}", file=sys.stderr)
        return 2
    scoped = result["generous_declared_cwe_scope"]
    passed = (result["full_corpus"] and result["precision"] >= args.min_precision
              and result["recall"] >= args.min_recall
              and scoped["precision"] >= args.min_precision
              and scoped["recall"] >= args.min_recall)
    result["gate"] = {"min_precision": args.min_precision, "min_recall": args.min_recall,
                      "passed_for_python_sast": passed}
    if args.write_results:
        args.write_results.parent.mkdir(parents=True, exist_ok=True)
        args.write_results.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
        print(f"results: {args.write_results}")
    print(f"Precision {result['precision']:.4f}, recall {result['recall']:.4f}, "
          f"TP={result['counts']['tp']}, FP={result['counts']['fp']}, "
          f"FN={result['counts']['fn']}, "
          f"repos={result['repos_measured']}/{result['repos_required']}")
    print("PASS: Python SAST gate" if passed else "FAIL: Python SAST gate (other scanners not scored)")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
