"""
Standalone secrets & credential detector.

Runs independently of the YAML rule packs (which already cover known
provider token formats) and specifically hunts for *generic* high-entropy
strings assigned to suspiciously-named variables -- the kind of secret
that doesn't match any known vendor prefix (internal API keys, custom
auth tokens, freshly-rotated credentials, etc.).

Uses Shannon entropy over the candidate string's character distribution:
random secrets have high entropy (close to log2(alphabet size) bits per
character), while English words, boilerplate, and typical code identifiers
have much lower entropy. This mirrors the detection technique used by
GitHub's secret scanning and TruffleHog, implemented here fully offline.
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
    r"""(?P<var>[A-Za-z_][A-Za-z0-9_.\-]{2,40})\s*[:=]\s*['"](?P<value>[A-Za-z0-9+/_\-=]{16,100})['"]"""
)

# Common false-positive substrings we never want to flag even if entropy is high.
PLACEHOLDER_HINTS = re.compile(
    r"(?i)(example|changeme|xxxx|dummy|placeholder|your[_-]?key|test[_-]?value|"
    r"0000000|1111111|abcdefg|lorem|sample|fixme|todo)"
)

BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")

EXCLUDED_LANGUAGES = {"other"}
BINARY_LOOKING_EXT = {".png", ".jpg", ".gif", ".woff", ".ttf"}


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
    """Skip common non-secret high-entropy patterns: hex hashes, UUIDs, git SHAs."""
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return True  # md5-length hex
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return True  # sha1-length hex / git commit sha
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
        return True  # UUID
    return False


def scan_file_for_secrets(discovered: DiscoveredFile, entropy_threshold: float = 4.3) -> List[Finding]:
    if discovered.language in EXCLUDED_LANGUAGES:
        pass  # still worth scanning generic text files
    content = read_text_safely(discovered.path)
    if not content:
        return []

    findings: List[Finding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        if len(line) > 2000:
            continue  # skip minified/huge lines, handled elsewhere
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

            findings.append(Finding(
                rule_id="SECRETS-HIGH-ENTROPY-ASSIGNMENT",
                title=f"High-entropy secret assigned to `{var_name}`",
                description=(
                    f"The variable `{var_name}` is assigned a string with Shannon entropy "
                    f"{entropy:.2f} bits/char (threshold {entropy_threshold}), consistent with "
                    f"a randomly generated secret/token/key hardcoded in source rather than "
                    f"loaded from secure configuration."
                ),
                severity=Severity.HIGH,
                engine=Engine.SECRETS,
                category="secrets",
                cwe="CWE-798",
                owasp="A07:2021-Identification and Authentication Failures",
                confidence="medium",
                remediation=(
                    "Move this value out of source code into an environment variable, "
                    "encrypted secret store, or vault, and rotate the exposed credential."
                ),
                references=["https://cwe.mitre.org/data/definitions/798.html"],
                location=CodeLocation(
                    file_path=discovered.rel_path,
                    start_line=idx,
                    end_line=idx,
                    snippet=line.strip()[:300],
                ),
                extra={"entropy": round(entropy, 3), "variable": var_name},
            ))

    return findings
