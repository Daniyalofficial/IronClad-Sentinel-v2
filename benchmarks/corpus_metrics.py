"""Detection accuracy measurement against the labelled corpus.

Every fixture under ``tests/security_corpus`` is labelled by its filename:

    vuln_*  -> must produce at least one finding of its declared class
    safe_*  -> must produce no finding of that class

This script runs the real scanner over the corpus and reports the numbers
that decide whether a rule is trustworthy:

    true positives    vulnerable fixture, rule fired
    false negatives   vulnerable fixture, rule did NOT fire
    false positives   safe fixture, rule fired
    precision         TP / (TP + FP)
    recall            TP / (TP + FN)

Run it with::

    python benchmarks/corpus_metrics.py
    python benchmarks/corpus_metrics.py --fail-below 0.9   # CI gate

The results are written to ``docs/CORPUS_RESULTS.json`` by
``--write-results`` so a regression in detection quality is visible in a
diff rather than only in someone's terminal.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "security_corpus")

#: fixture stem -> rule ids that prove the vulnerability class was caught.
#: A fixture counts as detected when ANY of its rules fire; per-rule detail
#: is reported separately so a rule that quietly stops firing is visible.
EXPECTED_RULES: Dict[str, List[str]] = {
    "vulnerable_sql": ["PY-AST-SQL-INJECTION"],
    "vuln_path_traversal": ["PY-AST-PATH-TRAVERSAL"],
    "vuln_ssrf": ["PY-AST-SSRF"],
    "vuln_xss": ["PY-AST-XSS"],
    "vuln_open_redirect": ["PY-AST-OPEN-REDIRECT"],
    "vuln_xxe": ["PY-AST-UNSAFE-XML-PARSER"],
    "vuln_insecure_random": ["PY-AST-INSECURE-RANDOM"],
    "vuln_weak_tls": ["PY-AST-WEAK-TLS-PROTOCOL"],
    "vuln_template_injection": ["PY-AST-TEMPLATE-INJECTION"],
    "vuln_yaml_loader": ["PY-AST-UNSAFE-YAML-LOADER"],
    "hardcoded_secret": ["SECRET-AWS-ACCESS-KEY-ID", "SECRETS-HARDCODED-CREDENTIAL"],
}

#: fixture stem -> rule ids that must NOT fire on it
SAFE_FIXTURES: Dict[str, List[str]] = {
    "safe_sql": ["PY-AST-SQL-INJECTION"],
    "safe_config": ["SECRET-AWS-ACCESS-KEY-ID", "SECRETS-HIGH-ENTROPY-ASSIGNMENT",
                    "SECRETS-HARDCODED-CREDENTIAL"],
    "safe_path_traversal": ["PY-AST-PATH-TRAVERSAL"],
    "safe_ssrf": ["PY-AST-SSRF"],
    "safe_xss": ["PY-AST-XSS"],
    "safe_open_redirect": ["PY-AST-OPEN-REDIRECT"],
    "safe_xxe": ["PY-AST-UNSAFE-XML-PARSER"],
    "safe_insecure_random": ["PY-AST-INSECURE-RANDOM"],
    "safe_weak_tls": ["PY-AST-WEAK-TLS-PROTOCOL"],
    "safe_template_injection": ["PY-AST-TEMPLATE-INJECTION"],
    "safe_yaml_loader": ["PY-AST-UNSAFE-YAML-LOADER"],
}


@dataclass
class CorpusResult:
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    rule_coverage: Dict[str, bool] = field(default_factory=dict)
    crashes: int = 0
    files_scanned: int = 0
    total_findings: int = 0
    missed: List[str] = field(default_factory=list)
    spurious: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 1.0

    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "crashes": self.crashes,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "rules_never_fired": sorted(rule for rule, fired in self.rule_coverage.items() if not fired),
            "missed": sorted(self.missed),
            "spurious": sorted(self.spurious),
        }


def measure(corpus_dir: str = CORPUS_DIR) -> CorpusResult:
    """Scan the corpus once and score every labelled fixture."""
    corpus_dir = os.path.abspath(corpus_dir)
    result = CorpusResult()

    # One scan of the whole tree, then per-fixture scoring. Scanning once is
    # what CI does; scanning per file would hide cross-file dedup effects.
    config = IronCladConfig(target=corpus_dir)
    scan = run_scan(config)
    result.files_scanned = scan.stats.files_scanned
    result.total_findings = len(scan.findings)

    by_file: Dict[str, set] = {}
    for finding in scan.findings:
        stem = os.path.splitext(os.path.basename(finding.location.file_path))[0]
        by_file.setdefault(stem, set()).add(finding.rule_id)

    present = {os.path.splitext(os.path.basename(path))[0] for path in _iter_files(corpus_dir)}
    for stem, expected in EXPECTED_RULES.items():
        for rule in expected:
            result.rule_coverage.setdefault(rule, False)
        if stem not in present:
            # A missing fixture is a corpus problem, not a detection miss --
            # counted separately so it cannot be hidden inside "recall".
            result.crashes += 1
            result.missed.append(f"{stem}: fixture missing")
            continue
        fired = by_file.get(stem, set())
        matched = [rule for rule in expected if rule in fired]
        for rule in matched:
            result.rule_coverage[rule] = True
        if matched:
            result.true_positives += 1
            # Report rules that exist for this class but did not fire, so a
            # partially-working detector is visible rather than averaged away.
            silent = [rule for rule in expected if rule not in fired]
            if silent:
                result.missed.extend(f"{stem}: silent rule {rule}" for rule in silent)
        else:
            result.false_negatives += 1
            result.missed.append(f"{stem}: none of {expected} fired")

    for stem, forbidden in SAFE_FIXTURES.items():
        fired = by_file.get(stem, set())
        spurious = [rule for rule in forbidden if rule in fired]
        if spurious:
            result.false_positives += len(spurious)
            result.spurious.extend(f"{stem}: {rule}" for rule in spurious)

    return result


def _iter_files(root: str):
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            yield os.path.join(dirpath, name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", default=CORPUS_DIR)
    parser.add_argument("--fail-below", type=float, default=None,
                        help="exit 1 if precision or recall falls below this value")
    parser.add_argument("--write-results", default=None, help="write JSON results to this path")
    args = parser.parse_args()

    result = measure(args.corpus)
    payload = result.to_dict()

    print("# ironclad corpus detection metrics")
    for key in ("files_scanned", "total_findings", "true_positives", "false_negatives",
                "false_positives", "crashes"):
        print(f"{key}={payload[key]}")
    print(f"precision={payload['precision']:.4f}")
    print(f"recall={payload['recall']:.4f}")
    if payload["missed"]:
        print("missed (false negatives):")
        for item in payload["missed"]:
            print(f"  - {item}")
    if payload["spurious"]:
        print("spurious (false positives):")
        for item in payload["spurious"]:
            print(f"  - {item}")

    if args.write_results:
        os.makedirs(os.path.dirname(os.path.abspath(args.write_results)) or ".", exist_ok=True)
        with open(args.write_results, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"results written to {args.write_results}")

    if args.fail_below is not None:
        if payload["precision"] < args.fail_below or payload["recall"] < args.fail_below:
            print(f"FAIL: precision/recall below {args.fail_below}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
