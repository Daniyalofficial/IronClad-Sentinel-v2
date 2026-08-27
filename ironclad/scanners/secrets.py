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
from typing import List, Optional

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

# A credential assignment with a *literal* value. Independent of entropy:
# a weak password such as "super-secret-password-123" has low entropy but is
# exactly the finding an operator needs to see, so an entropy-only detector
# would silently miss it.
CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?P<var>[A-Za-z_][A-Za-z0-9_.\-]{1,60})\s*[:=]\s*(?P<quote>['"])(?P<value>[^'"\n]{6,200})(?P=quote)"""
)

#: Literal values that look like a credential variable name but are not a
#: secret (field names, defaults, sentinels). Matching the variable name is
#: not the same as containing one.
NON_SECRET_LITERALS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "none", "null", "true", "false", "nil",
    "unset", "undefined", "redacted", "masked", "n/a", "-", "changeme",
}

#: A dotted lowercase identifier such as "token.manage" or "project.read".
#: Permission and enum constants are routinely assigned to credential-named
#: variables (TOKEN_MANAGE = "token.manage"); they are not secrets, and
#: reporting them is noise that trains people to ignore the rule.
DOTTED_IDENTIFIER = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)+$")


def _is_self_describing_constant(var_name: str, value: str) -> bool:
    """True when the literal simply restates the variable name.

    ``TOKEN_MANAGE = "token.manage"`` and ``SCAN_READ = "scan.read"`` are
    permission catalogues, not credentials. Comparing the normalised
    variable name against the value removes the whole class without
    weakening detection of real literals.
    """
    if not DOTTED_IDENTIFIER.match(value):
        return False
    normalized = var_name.strip().lower().split(".")[-1].replace("_", ".").replace("-", ".")
    return normalized == value


#: Patterns that mean "this value comes from configuration", not from source.
ENV_LOOKUP_HINTS = re.compile(
    r"(?i)(os\.environ|getenv|process\.env|System\.getenv|ENV\[|vault|keyring|"
    r"secret_?manager|config\.get|settings\.|fetch_?secret|read_?secret)"
)

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


#: Hex digests at the lengths the common algorithms produce. A pinned
#: checksum or commit digest assigned to a credential-named variable
#: (`api_token = "<sha256>"`) is not a secret, and reporting it trains
#: people to ignore the rule.
_HEX_DIGEST_LENGTHS = (32, 40, 64)  # md5, sha1/git sha, sha256


def _looks_like_hash_or_uuid(value: str) -> bool:
    """Skip common non-secret high-entropy patterns: hex digests and UUIDs."""
    for length in _HEX_DIGEST_LENGTHS:
        if re.fullmatch(r"[0-9a-fA-F]{%d}" % length, value):
            return True
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
        return True  # UUID
    return False


def _scan_credential_assignments(discovered: DiscoveredFile, lines: List[str],
                                 findings: List[Finding],
                                 skip_lines: Optional[set] = None) -> set:
    """Flag credentials assigned a literal value, regardless of entropy.

    ``skip_lines`` holds lines already reported by the entropy pass, which is
    the more informative of the two (it includes the measured entropy); one
    finding per problem, not two.
    """
    reported: set = set()
    for idx, line in enumerate(lines, start=1):
        if skip_lines and idx in skip_lines:
            continue
        if ENV_LOOKUP_HINTS.search(line):
            continue
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for match in CREDENTIAL_ASSIGNMENT.finditer(line):
            var_name = match.group("var")
            value = match.group("value")
            if not SENSITIVE_VAR_HINTS.search(var_name):
                continue
            if value.strip().lower() in NON_SECRET_LITERALS:
                continue
            if value.strip().lower() == var_name.strip().lower().split(".")[-1]:
                continue
            if _is_self_describing_constant(var_name, value.strip()):
                continue
            if PLACEHOLDER_HINTS.search(value):
                continue
            if _looks_like_hash_or_uuid(value):
                continue
            findings.append(Finding(
                rule_id="SECRETS-HARDCODED-CREDENTIAL",
                title=f"Hardcoded credential in `{var_name}`",
                description=(
                    f"`{var_name}` is assigned a literal string. A credential committed to "
                    f"source control is readable by everyone with repository access, survives "
                    f"in git history after deletion, and is usually shared rather than rotated."
                ),
                severity=Severity.HIGH,
                engine=Engine.SECRETS,
                category="secrets",
                cwe="CWE-798",
                owasp="A07:2021-Identification and Authentication Failures",
                confidence="medium",
                remediation=(
                    "Load the value from an environment variable or a secret manager, remove it "
                    "from version control, and rotate it -- deleting the line does not remove it "
                    "from git history."
                ),
                references=["https://cwe.mitre.org/data/definitions/798.html"],
                location=CodeLocation(file_path=discovered.rel_path, start_line=idx, end_line=idx,
                                      snippet=_redact(line.strip(), value)[:300]),
                extra={"variable": var_name, "value_length": len(value)},
            ))
            reported.add(idx)
            break
    return reported


def _redact(line: str, secret: str) -> str:
    """Never echo the secret itself into a finding's snippet."""
    if not secret:
        return line
    masked = secret[:2] + "*" * max(0, min(len(secret) - 2, 12))
    return line.replace(secret, masked)


def scan_file_for_secrets(discovered: DiscoveredFile, entropy_threshold: float = 4.3) -> List[Finding]:
    if discovered.language in EXCLUDED_LANGUAGES:
        pass  # still worth scanning generic text files
    content = read_text_safely(discovered.path)
    if not content:
        return []

    findings: List[Finding] = []
    lines = content.splitlines()
    entropy_lines: set = set()

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
            entropy_lines.add(idx)
            break

    # Second pass: literal credentials that the entropy test would miss. A
    # weak password has low entropy but is still a committed credential, so
    # an entropy-only detector silently drops it.
    _scan_credential_assignments(discovered, lines, findings, skip_lines=entropy_lines)

    return findings
