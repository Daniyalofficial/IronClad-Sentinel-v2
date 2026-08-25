"""
Standalone secrets & credential detector.

Runs independently of the YAML rule packs (which already cover known
provider token formats) and specifically hunts for generic high-entropy
strings assigned to suspiciously-named variables. It also detects
high-confidence PEM private-key material, which should never be committed
regardless of entropy.

The scanner is intentionally offline and conservative: deterministic secret
formats are high-confidence, while generic entropy-based assignments remain
medium-confidence and require a suspicious variable name.
"""
from __future__ import annotations

import math
import re
from typing import List

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile, read_text_safely

SENSITIVE_VAR_HINTS = re.compile(
    r"(?i)(secret|token|passwd|password|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|auth[_-]?token|session[_-]?key|encryption[_-]?key|"
    r"client[_-]?secret|signing[_-]?key)"
)

ASSIGNMENT_PATTERN = re.compile(
    r"""(?P<var>[A-Za-z_][A-Za-z0-9_.\-]{2,40})\s*[:=]\s*['\"](?P<value>[A-Za-z0-9+/_\-=]{16,100})['\"]"""
)

# High-confidence private-key material. We only report the PEM header rather
# than trying to parse the entire key; this keeps the scanner dependency-free.
PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
)

PLACEHOLDER_HINTS = re.compile(
    r"(?i)(example|changeme|xxxx|dummy|placeholder|your[_-]?key|test[_-]?value|"
    r"0000000|1111111|abcdefg|lorem|sample|fixme|todo)"
)

BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")

EXCLUDED_LANGUAGES = {"other"}
BINARY_LOOKING_EXT = {".png", ".jpg", ".gif", ".woff", ".ttf", ".ico", ".pdf"}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_hash_or_uuid(value: str) -> bool:
    """Skip common non-secret high-entropy patterns: hashes and UUIDs."""
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
        return True
    return False


def _finding(
    discovered: DiscoveredFile,
    line_number: int,
    line: str,
    *,
    rule_id: str,
    title: str,
    description: str,
    confidence: str,
    cwe: str = "CWE-798",
    extra: dict | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=Severity.HIGH,
        engine=Engine.SECRETS,
        category="secrets",
        cwe=cwe,
        owasp="A07:2021-Identification and Authentication Failures",
        confidence=confidence,
        remediation=(
            "Remove the credential from source control, rotate it if it was exposed, "
            "and load it from an environment variable, encrypted secret store, or vault."
        ),
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        location=CodeLocation(
            file_path=discovered.rel_path,
            start_line=line_number,
            end_line=line_number,
            snippet=line.strip()[:300],
        ),
        extra=extra or {},
    )


def scan_file_for_secrets(discovered: DiscoveredFile, entropy_threshold: float = 4.3) -> List[Finding]:
    content = read_text_safely(discovered.path)
    if not content:
        return []

    # Avoid decoding obviously binary assets. Source-like text files remain
    # eligible even when their language is unknown.
    suffix = discovered.path.lower()
    if any(suffix.endswith(ext) for ext in BINARY_LOOKING_EXT):
        return []

    findings: List[Finding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        if len(line) > 2000:
            continue

        if PEM_PRIVATE_KEY_PATTERN.search(line):
            findings.append(_finding(
                discovered,
                idx,
                line,
                rule_id="SECRETS-PEM-PRIVATE-KEY",
                title="Private key material embedded in source",
                description="A PEM private-key header was found in a source-controlled file. Private keys are credentials and should not be committed.",
                confidence="high",
                cwe="CWE-321",
            ))
            continue

        for match in ASSIGNMENT_PATTERN.finditer(line):
            var_name = match.group("var")
            value = match.group("value")

            if not SENSITIVE_VAR_HINTS.search(var_name):
                continue
            if PLACEHOLDER_HINTS.search(value) or PLACEHOLDER_HINTS.search(var_name):
                continue
            if _looks_like_hash_or_uuid(value):
                continue
            if not BASE64_LIKE.match(value):
                continue

            entropy = shannon_entropy(value)
            if entropy < entropy_threshold:
                continue

            findings.append(_finding(
                discovered,
                idx,
                line,
                rule_id="SECRETS-HIGH-ENTROPY-ASSIGNMENT",
                title=f"High-entropy secret assigned to `{var_name}`",
                description=(
                    f"The variable `{var_name}` is assigned a string with Shannon entropy "
                    f"{entropy:.2f} bits/char (threshold {entropy_threshold}), consistent with "
                    "a randomly generated secret/token/key hardcoded in source."
                ),
                confidence="medium",
                extra={"entropy": round(entropy, 3), "variable": var_name},
            ))

    return findings
