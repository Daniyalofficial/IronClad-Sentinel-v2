"""
Rule DSL schema and loader for the generic multi-language pattern engine.

A rule file is plain YAML, fully self-contained (no imports over the
network). Example:

    rules:
      - id: JS-HARDCODED-JWT-SECRET
        title: Hardcoded JWT signing secret
        languages: [javascript, typescript]
        severity: high
        category: secrets
        cwe: CWE-798
        pattern: 'jwt\\.sign\\(\\s*[^,]+,\\s*["\\'][A-Za-z0-9+/_=-]{6,}["\\']'
        message: >
          A JWT is signed with a secret hardcoded directly in source code.
        remediation: >
          Load the signing secret from an environment variable or secrets
          manager, never commit it to source control.
        exclude_if_matches: 'process\\.env'

`exclude_if_matches` is an optional second pattern: if it matches the SAME
line, the finding is suppressed (used to cut false positives, e.g. a line
that already reads the secret from an env var pattern nearby).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

import yaml


@dataclass
class Rule:
    id: str
    title: str
    languages: List[str]
    severity: str
    category: str
    pattern: str
    message: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: str = ""
    exclude_if_matches: Optional[str] = None
    confidence: str = "medium"
    multiline: bool = False
    references: List[str] = field(default_factory=list)
    compiled_pattern: Optional[re.Pattern] = None
    compiled_exclude: Optional[re.Pattern] = None

    def compile(self):
        flags = re.MULTILINE
        if self.multiline:
            flags |= re.DOTALL
        self.compiled_pattern = re.compile(self.pattern, flags)
        if self.exclude_if_matches:
            self.compiled_exclude = re.compile(self.exclude_if_matches, flags)


def load_rule_file(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    rules = []
    for raw in data.get("rules", []):
        rule = Rule(
            id=raw["id"],
            title=raw["title"],
            languages=raw.get("languages", ["*"]),
            severity=raw.get("severity", "medium"),
            category=raw.get("category", "general"),
            pattern=raw["pattern"],
            message=raw.get("message", raw["title"]),
            cwe=raw.get("cwe"),
            owasp=raw.get("owasp"),
            remediation=raw.get("remediation", ""),
            exclude_if_matches=raw.get("exclude_if_matches"),
            confidence=raw.get("confidence", "medium"),
            multiline=raw.get("multiline", False),
            references=raw.get("references", []),
        )
        try:
            rule.compile()
        except re.error:
            continue
        rules.append(rule)
    return rules


def load_rule_packs(directories: List[str]) -> List[Rule]:
    all_rules: List[Rule] = []
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            if filename.endswith((".yml", ".yaml")):
                all_rules.extend(load_rule_file(os.path.join(directory, filename)))
    return all_rules
