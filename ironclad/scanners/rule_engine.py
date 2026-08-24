"""
Generic multi-language pattern-matching engine.

Applies every compiled `Rule` (see `ironclad.rules.schema`) whose
`languages` list matches (or contains "*") the discovered file's
language, line by line (or as a whole-file scan when `multiline=True`).

This is the "Semgrep-style" breadth engine: it doesn't understand full
language grammar, but with well-crafted regex rules across a dozen+
languages it catches the overwhelming majority of common anti-patterns
(hardcoded secrets in non-Python languages, insecure crypto calls in
Java/Go/Ruby/PHP, XSS sinks in JS/TS, insecure YAML/Terraform lines,
etc.) without needing a full parser per language.
"""
from __future__ import annotations

from typing import List

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile, read_text_safely
from ironclad.rules.schema import Rule

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _rule_applies(rule: Rule, language: str) -> bool:
    return "*" in rule.languages or language in rule.languages


def scan_file_with_rules(discovered: DiscoveredFile, rules: List[Rule]) -> List[Finding]:
    applicable = [r for r in rules if _rule_applies(r, discovered.language)]
    if not applicable:
        return []

    content = read_text_safely(discovered.path)
    if not content:
        return []

    findings: List[Finding] = []
    lines = content.splitlines()

    for rule in applicable:
        if rule.multiline:
            for match in rule.compiled_pattern.finditer(content):
                start_line = content.count("\n", 0, match.start()) + 1
                end_line = content.count("\n", 0, match.end()) + 1
                snippet = "\n".join(lines[max(0, start_line - 1):end_line])[:500]
                findings.append(_build_finding(rule, discovered.rel_path, start_line, end_line, snippet))
        else:
            for idx, line in enumerate(lines, start=1):
                match = rule.compiled_pattern.search(line)
                if not match:
                    continue
                if rule.compiled_exclude and rule.compiled_exclude.search(line):
                    continue
                findings.append(_build_finding(rule, discovered.rel_path, idx, idx, line.strip()[:500]))

    return findings


def _build_finding(rule: Rule, rel_path: str, start_line: int, end_line: int, snippet: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        description=rule.message,
        severity=SEVERITY_MAP.get(rule.severity, Severity.MEDIUM),
        engine=Engine.RULE_ENGINE,
        category=rule.category,
        cwe=rule.cwe,
        owasp=rule.owasp,
        remediation=rule.remediation,
        confidence=rule.confidence,
        references=rule.references,
        location=CodeLocation(
            file_path=rel_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
        ),
    )
