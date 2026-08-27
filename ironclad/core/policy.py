"""Organization security policy engine.

A policy is a single declarative YAML document that answers the question a
security team actually has to answer before a scanner can gate CI:

    "Which findings are allowed to exist in *our* code, and which ones stop
     a build?"

Everything in this module is deterministic: the same ``ScanResult`` plus
the same policy document always produces byte-identical decisions. There
is no randomness, no wall-clock dependence (except explicit baseline
expiration, which takes an injected ``now``), and no network access.

Schema (all keys optional unless noted)::

    version: 1                      # required, must be 1
    name: acme-standard
    fail_on: high                   # critical|high|medium|low|any|none
    max_risk_score: 100
    severity_gates:                 # max tolerated findings per severity
      critical: 0
      high: 0
    engines:
      enabled: [ast-python, secrets]
    rules:
      ignore: [RULE-ID]
      min_confidence: high          # low|medium|high
      severity_overrides:
        PY-AST-BIND-ALL-INTERFACES: low
    licenses:
      allowed: [MIT, Apache-2.0]
      warning: [LGPL-3.0, MPL-2.0]
      blocked: [GPL-3.0, AGPL-3.0]
      unknown: warn                 # warn|block|allow
    secrets:
      entropy_threshold: 4.3
    dependencies:
      block:
        - {ecosystem: javascript, name: lodash, reason: "policy"}
    paths:
      exclude: ["vendor/**"]
      exclude_dirs: [third_party]
    baseline:
      path: .ironclad/baseline.json
      max_age_days: 90
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

from ironclad.core.config import IronCladConfig
from ironclad.core.models import Finding, ScanResult, Severity

POLICY_SCHEMA_VERSION = 1

SEVERITY_NAMES = ("critical", "high", "medium", "low", "info")
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "any", "none")
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
UNKNOWN_LICENSE_ACTIONS = ("warn", "block", "allow")
KNOWN_ENGINES = (
    "ast-python",
    "rule-engine",
    "secrets",
    "dependency",
    "iac",
    "license-compliance",
)


class PolicyError(ValueError):
    """Raised when a policy document is structurally invalid.

    Carries every detected problem at once (not just the first) so an
    operator fixing a policy file gets the whole list in one run.
    """

    def __init__(self, problems: Iterable[str]):
        self.problems: List[str] = list(problems)
        super().__init__("invalid policy: " + "; ".join(self.problems))


@dataclass(frozen=True)
class DependencyBlock:
    ecosystem: str
    name: str
    reason: str = ""

    @property
    def key(self) -> Tuple[str, str]:
        return (self.ecosystem.lower(), self.name.lower())


@dataclass
class LicensePolicy:
    allowed: Set[str] = field(default_factory=set)
    warning: Set[str] = field(default_factory=set)
    blocked: Set[str] = field(default_factory=set)
    unknown: str = "warn"

    def classify(self, license_id: Optional[str]) -> str:
        """Return ``allowed`` | ``warning`` | ``blocked`` | ``unknown``.

        Unknown is *never* silently mapped to permissive: an unmapped
        license returns ``unknown`` and the configured ``unknown`` action
        decides whether that is a warning or a violation.
        """
        if not license_id or str(license_id).upper() in ("UNKNOWN", "NONE", "NOASSERTION"):
            return "unknown"
        if license_id in self.blocked:
            return "blocked"
        if license_id in self.warning:
            return "warning"
        if license_id in self.allowed:
            return "allowed"
        # Not explicitly listed anywhere: treat as unknown rather than
        # assuming the organization meant to allow it.
        return "unknown"


@dataclass
class Policy:
    version: int = POLICY_SCHEMA_VERSION
    name: str = "ironclad-policy"
    fail_on: str = "high"
    max_risk_score: Optional[int] = None
    severity_gates: Dict[str, int] = field(default_factory=dict)
    engines_enabled: Optional[List[str]] = None
    ignore_rules: List[str] = field(default_factory=list)
    min_confidence: str = "low"
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    license_policy: LicensePolicy = field(default_factory=LicensePolicy)
    entropy_threshold: float = 4.3
    blocked_dependencies: List[DependencyBlock] = field(default_factory=list)
    path_excludes: List[str] = field(default_factory=list)
    exclude_dirs: List[str] = field(default_factory=list)
    baseline_path: Optional[str] = None
    baseline_max_age_days: Optional[int] = None
    source_path: Optional[str] = None

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: str) -> "Policy":
        if not path or not os.path.isfile(path):
            raise PolicyError([f"policy file not found: {path!r}"])
        with open(path, "r", encoding="utf-8") as fh:
            try:
                data = yaml.safe_load(fh)
            except yaml.YAMLError as exc:  # pragma: no cover - message passthrough
                raise PolicyError([f"YAML parse error: {exc}"]) from exc
        if data is None:
            raise PolicyError(["policy file is empty"])
        if not isinstance(data, dict):
            raise PolicyError(["policy document must be a mapping at the top level"])
        return cls.from_dict(data, source_path=path)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_path: Optional[str] = None) -> "Policy":
        problems: List[str] = []
        version = data.get("version", POLICY_SCHEMA_VERSION)
        if version != POLICY_SCHEMA_VERSION:
            problems.append(
                f"unsupported policy version {version!r}; this build supports version {POLICY_SCHEMA_VERSION}"
            )

        fail_on = str(data.get("fail_on", "high")).lower()
        if fail_on not in FAIL_ON_CHOICES:
            problems.append(f"fail_on must be one of {list(FAIL_ON_CHOICES)}, got {fail_on!r}")

        max_risk_score = data.get("max_risk_score")
        if max_risk_score is not None:
            if not isinstance(max_risk_score, int) or isinstance(max_risk_score, bool) or max_risk_score < 0:
                problems.append(f"max_risk_score must be a non-negative integer, got {max_risk_score!r}")

        severity_gates: Dict[str, int] = {}
        raw_gates = data.get("severity_gates") or {}
        if not isinstance(raw_gates, dict):
            problems.append("severity_gates must be a mapping of severity -> integer")
        else:
            for sev, limit in raw_gates.items():
                key = str(sev).lower()
                if key not in SEVERITY_NAMES:
                    problems.append(f"severity_gates contains unknown severity {sev!r}")
                    continue
                if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                    problems.append(f"severity_gates[{sev}] must be a non-negative integer, got {limit!r}")
                    continue
                severity_gates[key] = limit

        engines_section = data.get("engines") or {}
        engines_enabled: Optional[List[str]] = None
        if engines_section:
            if not isinstance(engines_section, dict):
                problems.append("engines must be a mapping")
            else:
                enabled = engines_section.get("enabled")
                if enabled is not None:
                    if not isinstance(enabled, list):
                        problems.append("engines.enabled must be a list")
                    else:
                        unknown = [e for e in enabled if e not in KNOWN_ENGINES]
                        if unknown:
                            problems.append(f"engines.enabled contains unknown engines: {sorted(unknown)}")
                        engines_enabled = [str(e) for e in enabled]

        rules_section = data.get("rules") or {}
        ignore_rules: List[str] = []
        min_confidence = "low"
        severity_overrides: Dict[str, str] = {}
        if rules_section:
            if not isinstance(rules_section, dict):
                problems.append("rules must be a mapping")
            else:
                raw_ignore = rules_section.get("ignore") or []
                if not isinstance(raw_ignore, list):
                    problems.append("rules.ignore must be a list of rule IDs")
                else:
                    ignore_rules = [str(r) for r in raw_ignore]
                min_confidence = str(rules_section.get("min_confidence", "low")).lower()
                if min_confidence not in CONFIDENCE_ORDER:
                    problems.append(f"rules.min_confidence must be one of low|medium|high, got {min_confidence!r}")
                raw_overrides = rules_section.get("severity_overrides") or {}
                if not isinstance(raw_overrides, dict):
                    problems.append("rules.severity_overrides must be a mapping of rule ID -> severity")
                else:
                    for rule_id, sev in raw_overrides.items():
                        if str(sev).lower() not in SEVERITY_NAMES:
                            problems.append(f"rules.severity_overrides[{rule_id}] is not a valid severity: {sev!r}")
                        else:
                            severity_overrides[str(rule_id)] = str(sev).lower()

        license_section = data.get("licenses") or {}
        license_policy = LicensePolicy()
        if license_section:
            if not isinstance(license_section, dict):
                problems.append("licenses must be a mapping")
            else:
                for key, target in (("allowed", license_policy.allowed),
                                    ("warning", license_policy.warning),
                                    ("blocked", license_policy.blocked)):
                    raw = license_section.get(key) or []
                    if not isinstance(raw, list):
                        problems.append(f"licenses.{key} must be a list of SPDX identifiers")
                    else:
                        target.update(str(x) for x in raw)
                unknown_action = str(license_section.get("unknown", "warn")).lower()
                if unknown_action not in UNKNOWN_LICENSE_ACTIONS:
                    problems.append(
                        f"licenses.unknown must be one of {list(UNKNOWN_LICENSE_ACTIONS)}, got {unknown_action!r}"
                    )
                license_policy.unknown = unknown_action
                overlap = license_policy.blocked & license_policy.allowed
                if overlap:
                    problems.append(
                        f"licenses cannot be both allowed and blocked: {sorted(overlap)}"
                    )

        secrets_section = data.get("secrets") or {}
        entropy_threshold = 4.3
        if secrets_section:
            if not isinstance(secrets_section, dict):
                problems.append("secrets must be a mapping")
            else:
                value = secrets_section.get("entropy_threshold", 4.3)
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    problems.append(f"secrets.entropy_threshold must be a number, got {value!r}")
                else:
                    entropy_threshold = float(value)

        blocked_dependencies: List[DependencyBlock] = []
        deps_section = data.get("dependencies") or {}
        if deps_section:
            if not isinstance(deps_section, dict):
                problems.append("dependencies must be a mapping")
            else:
                raw_block = deps_section.get("block") or []
                if not isinstance(raw_block, list):
                    problems.append("dependencies.block must be a list")
                else:
                    for idx, item in enumerate(raw_block):
                        if not isinstance(item, dict) or "name" not in item:
                            problems.append(f"dependencies.block[{idx}] must be a mapping with a 'name' key")
                            continue
                        blocked_dependencies.append(DependencyBlock(
                            ecosystem=str(item.get("ecosystem", "*")).lower(),
                            name=str(item["name"]),
                            reason=str(item.get("reason", "")),
                        ))

        paths_section = data.get("paths") or {}
        path_excludes: List[str] = []
        exclude_dirs: List[str] = []
        if paths_section:
            if not isinstance(paths_section, dict):
                problems.append("paths must be a mapping")
            else:
                raw_excl = paths_section.get("exclude") or []
                if not isinstance(raw_excl, list):
                    problems.append("paths.exclude must be a list of globs")
                else:
                    path_excludes = [str(g) for g in raw_excl]
                raw_dirs = paths_section.get("exclude_dirs") or []
                if not isinstance(raw_dirs, list):
                    problems.append("paths.exclude_dirs must be a list of directory names")
                else:
                    exclude_dirs = [str(d) for d in raw_dirs]

        baseline_section = data.get("baseline") or {}
        baseline_path: Optional[str] = None
        baseline_max_age: Optional[int] = None
        if baseline_section:
            if not isinstance(baseline_section, dict):
                problems.append("baseline must be a mapping")
            else:
                baseline_path = baseline_section.get("path")
                age = baseline_section.get("max_age_days")
                if age is not None:
                    if not isinstance(age, int) or isinstance(age, bool) or age < 0:
                        problems.append(f"baseline.max_age_days must be a non-negative integer, got {age!r}")
                    else:
                        baseline_max_age = age

        unknown_keys = set(data) - {
            "version", "name", "fail_on", "max_risk_score", "severity_gates", "engines",
            "rules", "licenses", "secrets", "dependencies", "paths", "baseline",
        }
        if unknown_keys:
            problems.append(f"unknown top-level keys: {sorted(unknown_keys)}")

        if problems:
            raise PolicyError(problems)

        return cls(
            version=POLICY_SCHEMA_VERSION,
            name=str(data.get("name", "ironclad-policy")),
            fail_on=fail_on,
            max_risk_score=max_risk_score,
            severity_gates=severity_gates,
            engines_enabled=engines_enabled,
            ignore_rules=ignore_rules,
            min_confidence=min_confidence,
            severity_overrides=severity_overrides,
            license_policy=license_policy,
            entropy_threshold=entropy_threshold,
            blocked_dependencies=blocked_dependencies,
            path_excludes=path_excludes,
            exclude_dirs=exclude_dirs,
            baseline_path=baseline_path,
            baseline_max_age_days=baseline_max_age,
            source_path=source_path,
        )

    # ------------------------------------------------------------- to_dict
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "fail_on": self.fail_on,
            "max_risk_score": self.max_risk_score,
            "severity_gates": dict(sorted(self.severity_gates.items())),
            "engines": {"enabled": self.engines_enabled} if self.engines_enabled else {},
            "rules": {
                "ignore": sorted(self.ignore_rules),
                "min_confidence": self.min_confidence,
                "severity_overrides": dict(sorted(self.severity_overrides.items())),
            },
            "licenses": {
                "allowed": sorted(self.license_policy.allowed),
                "warning": sorted(self.license_policy.warning),
                "blocked": sorted(self.license_policy.blocked),
                "unknown": self.license_policy.unknown,
            },
            "secrets": {"entropy_threshold": self.entropy_threshold},
            "dependencies": {
                "block": [
                    {"ecosystem": b.ecosystem, "name": b.name, "reason": b.reason}
                    for b in self.blocked_dependencies
                ]
            },
            "paths": {"exclude": self.path_excludes, "exclude_dirs": self.exclude_dirs},
            "baseline": {"path": self.baseline_path, "max_age_days": self.baseline_max_age_days},
        }

    # --------------------------------------------------------------- apply
    def apply_to_config(self, config: IronCladConfig) -> IronCladConfig:
        """Return a *new* config with the policy folded in.

        Policy never silently widens an explicit CLI choice: CLI-provided
        overrides arrive in ``config`` and win for the fields they set. The
        policy contributes additive constraints (ignored rules, excluded
        paths, confidence floor, engine restrictions).
        """
        merged = IronCladConfig(
            target=config.target,
            exclude_dirs=set(config.exclude_dirs),
            exclude_globs=set(config.exclude_globs),
            include_globs=list(config.include_globs),
            enabled_engines=list(config.enabled_engines),
            min_severity=config.min_severity,
            fail_on_severity=config.fail_on_severity,
            max_risk_score=config.max_risk_score,
            baseline_file=config.baseline_file,
            custom_rules_dirs=list(config.custom_rules_dirs),
            ignore_rule_ids=list(config.ignore_rule_ids),
            ignore_paths=list(config.ignore_paths),
            max_file_size_kb=config.max_file_size_kb,
            entropy_threshold=config.entropy_threshold,
            report_formats=list(config.report_formats),
            output_dir=config.output_dir,
        )
        for rule_id in self.ignore_rules:
            if rule_id not in merged.ignore_rule_ids:
                merged.ignore_rule_ids.append(rule_id)
        for glob in self.path_excludes:
            if glob not in merged.ignore_paths:
                merged.ignore_paths.append(glob)
        for dirname in self.exclude_dirs:
            merged.exclude_dirs.add(dirname)
        if self.engines_enabled is not None:
            merged.enabled_engines = [e for e in merged.enabled_engines if e in self.engines_enabled]
        merged.entropy_threshold = min(config.entropy_threshold, self.entropy_threshold)
        if self.baseline_path and not config.baseline_file:
            merged.baseline_file = self.baseline_path
        return merged


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
SEVERITY_RANK = {name: idx for idx, name in enumerate(
    ["critical", "high", "medium", "low", "info"]
)}


@dataclass(frozen=True)
class Violation:
    kind: str
    message: str
    rule_id: str = ""
    file_path: str = ""
    line: int = 0
    severity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line": self.line,
            "severity": self.severity,
        }


@dataclass
class PolicyDecision:
    passed: bool
    exit_code: int
    policy_name: str
    violations: List[Violation] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "policy": self.policy_name,
            "violation_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "summary": self.summary,
        }


def _override_finding_severity(finding: Finding, policy: Policy) -> Finding:
    override = policy.severity_overrides.get(finding.rule_id)
    if not override:
        return finding
    if finding.severity.value == override:
        return finding
    import copy

    clone = copy.copy(finding)
    clone.severity = Severity(override)
    clone.extra = dict(finding.extra)
    clone.extra["policy_severity_override"] = finding.severity.value
    clone.fingerprint = clone.compute_fingerprint()
    return clone


def filter_findings_for_policy(findings: List[Finding], policy: Policy) -> List[Finding]:
    """Apply confidence floor + rule ignores + severity overrides.

    This is the *only* place policy mutates the finding set, and it is a
    pure function -- identical inputs always produce identical outputs.
    """
    floor = CONFIDENCE_ORDER[policy.min_confidence]
    ignore = set(policy.ignore_rules)
    out: List[Finding] = []
    for finding in findings:
        if finding.rule_id in ignore:
            continue
        if CONFIDENCE_ORDER.get(finding.confidence, 0) < floor:
            continue
        out.append(_override_finding_severity(finding, policy))
    return out


def _license_findings(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.category == "license-compliance"]


def _dependency_findings(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.category == "vulnerable-dependency"]


def _path_matches_any(rel_path: str, globs: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, g) for g in globs)


def evaluate_policy(result: ScanResult, policy: Policy,
                    findings: Optional[List[Finding]] = None) -> PolicyDecision:
    """Deterministically decide pass/fail for a scan result under a policy.

    By default the decision is taken over ``result.gating_findings()`` --
    new findings when a baseline is in effect, every finding otherwise.
    Pass ``findings`` explicitly to evaluate a specific set (the API does
    this when re-evaluating a stored scan).
    """
    gated = result.gating_findings() if findings is None else findings
    findings = filter_findings_for_policy(gated, policy)
    violations: List[Violation] = []

    counts = {name: 0 for name in SEVERITY_NAMES}
    for finding in findings:
        counts[finding.severity.value] += 1

    # 1. Explicit per-severity gates ------------------------------------
    for severity, limit in sorted(policy.severity_gates.items()):
        actual = counts.get(severity, 0)
        if actual > limit:
            violations.append(Violation(
                kind="severity_gate",
                severity=severity,
                message=f"{actual} {severity} finding(s) exceed the allowed maximum of {limit}",
            ))

    # 2. fail_on threshold ------------------------------------------------
    if policy.fail_on == "any":
        offending = [f for f in findings if f.severity is not Severity.INFO]
    elif policy.fail_on == "none":
        offending = []
    else:
        threshold = SEVERITY_RANK[policy.fail_on]
        offending = [f for f in findings if SEVERITY_RANK[f.severity.value] <= threshold]
    for finding in sorted(offending, key=lambda f: (f.rule_id, f.location.file_path, f.location.start_line)):
        violations.append(Violation(
            kind="severity",
            rule_id=finding.rule_id,
            file_path=finding.location.file_path,
            line=finding.location.start_line,
            severity=finding.severity.value,
            message=f"{finding.rule_id}: {finding.title} at {finding.location.file_path}:{finding.location.start_line}",
        ))

    # 3. Composite risk score --------------------------------------------
    if policy.max_risk_score is not None:
        score = sum(f.severity.weight for f in findings)
        if score > policy.max_risk_score:
            violations.append(Violation(
                kind="risk_score",
                message=f"risk score {score} exceeds policy maximum {policy.max_risk_score}",
            ))

    # 4. License policy ---------------------------------------------------
    for finding in sorted(_license_findings(findings), key=lambda f: f.extra.get("package", "")):
        license_id = str(finding.extra.get("license") or "UNKNOWN")
        classification = policy.license_policy.classify(license_id)
        if classification == "blocked":
            violations.append(Violation(
                kind="license_blocked",
                rule_id=finding.rule_id,
                file_path=finding.location.file_path,
                line=finding.location.start_line,
                severity=finding.severity.value,
                message=f"blocked license {license_id} used by {finding.extra.get('package', '?')}",
            ))
        elif classification == "unknown" and policy.license_policy.unknown == "block":
            violations.append(Violation(
                kind="license_unknown",
                rule_id=finding.rule_id,
                file_path=finding.location.file_path,
                line=finding.location.start_line,
                severity=finding.severity.value,
                message=f"unknown license for {finding.extra.get('package', '?')} and policy blocks unknown licenses",
            ))

    # 5. Blocked packages --------------------------------------------------
    blocked_index: Dict[Tuple[str, str], str] = {}
    for block in policy.blocked_dependencies:
        blocked_index[(block.ecosystem, block.name.lower())] = block.reason
        blocked_index[("*", block.name.lower())] = block.reason
    seen_blocked: Set[str] = set()
    for finding in sorted(_dependency_findings(findings), key=lambda f: f.extra.get("package", "")):
        package = str(finding.extra.get("package", "")).lower()
        ecosystem = str(finding.extra.get("ecosystem", "*")).lower()
        reason = blocked_index.get((ecosystem, package), blocked_index.get(("*", package)))
        if reason is None:
            continue
        marker = f"{ecosystem}:{package}"
        if marker in seen_blocked:
            continue
        seen_blocked.add(marker)
        violations.append(Violation(
            kind="blocked_dependency",
            rule_id=finding.rule_id,
            file_path=finding.location.file_path,
            line=finding.location.start_line,
            severity=finding.severity.value,
            message=f"package {package} ({ecosystem}) is blocked by policy" + (f": {reason}" if reason else ""),
        ))

    violations.sort(key=lambda v: (v.kind, v.rule_id, v.file_path, v.line, v.message))
    passed = not violations
    summary = {
        "evaluated_findings": len(findings),
        "severity_counts": counts,
        "risk_score": sum(f.severity.weight for f in findings),
        "min_confidence": policy.min_confidence,
        "ignored_rules": sorted(policy.ignore_rules),
    }
    return PolicyDecision(
        passed=passed,
        exit_code=0 if passed else 1,
        policy_name=policy.name,
        violations=violations,
        summary=summary,
    )


EXAMPLE_POLICY = """\
# IronClad Sentinel organization security policy.
# Validate with:  ironclad policy validate policy.yaml
# Apply with:     ironclad scan . --policy policy.yaml
version: 1
name: example-standard

# Highest severity that is allowed to exist without failing the build.
# One of: critical | high | medium | low | any | none
fail_on: high

# Hard caps. A build with more than this many findings of a given severity
# fails even if fail_on would have tolerated them.
severity_gates:
  critical: 0
  high: 0

# Optional composite ceiling (critical=40, high=20, medium=8, low=3, info=0).
max_risk_score: 120

engines:
  enabled:
    - ast-python
    - rule-engine
    - secrets
    - dependency
    - iac
    - license-compliance

rules:
  # Stable rule IDs that your organization has formally risk-accepted.
  ignore: []
  # Drop findings below this confidence: low | medium | high
  min_confidence: low
  # Re-grade a rule for your environment (never use this to hide a real bug).
  severity_overrides: {}

licenses:
  allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unlicense, "CC0-1.0"]
  warning: [LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0, "CDDL-1.0"]
  blocked: [GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0]
  # Unknown licenses are never assumed permissive: warn or block.
  unknown: warn

secrets:
  entropy_threshold: 4.3

dependencies:
  block: []

paths:
  exclude:
    - "**/vendor/**"
    - "**/node_modules/**"
    - "**/*_pb2.py"
  exclude_dirs: []

baseline:
  path: .ironclad/baseline.json
  max_age_days: 90
"""


def write_example_policy(path: str) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(EXAMPLE_POLICY)
    return path
