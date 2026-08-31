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

#: Fields whose *values* in a rule-pack file are patterns and prose about
#: vulnerabilities, not vulnerable code. Scanning a rule pack without
#: skipping these makes the scanner report its own definitions -- a
#: self-inflicted false positive that is visible the moment anyone runs
#: IronClad against its own repository.
RULE_PACK_DEFINITION_KEYS = {
    "pattern", "exclude_if_matches", "message", "remediation",
    "title", "description", "id",
}


def _rule_pack_definition_lines(content: str) -> set:
    """Line numbers (1-based) that are rule-pack definitions, not code.

    Only applies when the file actually parses as an IronClad rule pack: a
    mapping with a ``rules`` list whose entries carry a ``pattern`` key.
    Any other YAML file is scanned normally.
    """
    import yaml

    try:
        data = yaml.safe_load(content)
    except Exception:  # noqa: BLE001 - not YAML we recognise; scan it normally
        return set()
    if not isinstance(data, dict):
        return set()
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        return set()
    if not any(isinstance(rule, dict) and "pattern" in rule for rule in rules):
        return set()

    skip = set()
    # A YAML key must be followed by whitespace or end-of-line. Without that
    # constraint a prose continuation line such as
    # "hostNetwork:true removes network namespace isolation" is mistaken for
    # a key, the skip state resets, and the line gets scanned as if it were
    # a manifest -- which is exactly the false positive this avoids.
    key_re = __import__("re").compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:(?:\s|$)")
    current_key = None
    for index, line in enumerate(content.splitlines(), start=1):
        match = key_re.match(line)
        if match:
            current_key = match.group(1)
            if current_key in RULE_PACK_DEFINITION_KEYS:
                skip.add(index)
            continue
        # Continuation lines of a multi-line scalar (folded `>` or `|`).
        if current_key in RULE_PACK_DEFINITION_KEYS and line.strip():
            skip.add(index)
        elif not line.strip():
            continue
        else:
            current_key = None
    return skip


# Languages where a triple-quoted block is a docstring rather than data.
_CODE_LANGUAGES = {"python"}


def _docstring_lines(lines: List[str]) -> set:
    """Line numbers that sit inside a Python docstring.

    Regex rules cannot tell prose from code, so a documentation example such
    as ``SECRET_KEY = 'development key'`` inside a docstring was reported as
    a live configuration. Found on real code: flask/src/flask/config.py and
    httpx/httpx/_urls.py both triggered rules from docstring examples.

    Only lines whose opening triple quote starts the line are treated as
    docstrings, so ``X = <triple-quote>...`` literals are still scanned.
    """
    triple_double = '"' * 3
    triple_single = "'" * 3
    inside: set = set()
    open_quote = None
    for index, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if open_quote is None:
            for quote in (triple_double, triple_single):
                if stripped.startswith(quote):
                    rest = stripped[3:]
                    if len(rest) >= 3 and rest.endswith(quote):
                        inside.add(index)  # single-line docstring
                    else:
                        open_quote = quote
                        inside.add(index)
                    break
        else:
            inside.add(index)
            if open_quote in raw:
                open_quote = None
    return inside


# Line-comment marker per language. Whole-line comments are prose: a rule
#: that matches one is reporting documentation, not code. Found on real code
#: (rubygems/lib/rubygems/specification.rb matched RUBY-YAML-LOAD inside
#: "# +input+ can be anything that YAML.load() accepts").
#:
#: Only lines whose first non-space character is the marker are skipped --
#: trailing comments are not attempted, because deciding whether a `#` starts
#: a comment or sits inside a string needs a real lexer.
LINE_COMMENT = {
    "python": "#", "ruby": "#", "shell": "#", "yaml": "#",
    "terraform": "#", "dotenv": "#", "sql": "--",
    "javascript": "//", "typescript": "//", "java": "//", "go": "//",
    "c": "//", "cpp": "//", "csharp": "//", "php": "//",
}


def _is_comment_line(line: str, language: str) -> bool:
    marker = LINE_COMMENT.get(language)
    if not marker:
        return False
    return line.lstrip().startswith(marker)


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
    definition_lines = _rule_pack_definition_lines(content)
    docstring_lines = _docstring_lines(lines) if discovered.language in _CODE_LANGUAGES else set()

    for rule in applicable:
        if rule.multiline:
            for match in rule.compiled_pattern.finditer(content):
                start_line = content.count("\n", 0, match.start()) + 1
                end_line = content.count("\n", 0, match.end()) + 1
                if start_line in definition_lines:
                    continue
                snippet = "\n".join(lines[max(0, start_line - 1):end_line])[:500]
                findings.append(_build_finding(rule, discovered.rel_path, start_line, end_line, snippet))
        else:
            for idx, line in enumerate(lines, start=1):
                if idx in definition_lines or idx in docstring_lines:
                    continue
                if _is_comment_line(line, discovered.language):
                    continue
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
