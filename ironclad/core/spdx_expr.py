"""SPDX license expression parsing and policy classification.

Dependency metadata is messy: ``MIT``, ``Apache-2.0 OR MIT``,
``(GPL-2.0 WITH Classpath-exception-2.0)``, ``MIT/Apache-2.0``,
``NOASSERTION``, or nothing at all. Treating all of those as "a string"
makes any real license gate unusable, and treating an unparseable value as
permissive is how copyleft ends up in a shipped product.

Rules implemented here:

* ``A OR B``  -- the consumer may choose, so the *best* branch decides.
* ``A AND B`` -- both obligations apply, so the *worst* branch decides.
* ``A WITH exception`` -- the exception is recorded but the base license
  decides the classification (an exception narrows obligations; it never
  turns a copyleft license permissive in our model).
* Anything unparseable or missing is ``unknown`` and is **never** mapped
  to permissive.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

# Ranking used to pick the best/worst branch of an expression.
# Lower number == more permissive.
CLASSIFICATION_ORDER = ["allowed", "warning", "unknown", "blocked"]

_TOKEN_RE = re.compile(r"[A-Za-z0-9.\-+]+|\(|\)|OR|AND|WITH", re.IGNORECASE)


@dataclass(frozen=True)
class LicenseExpression:
    """A parsed SPDX license expression."""

    raw: str
    ids: Tuple[str, ...] = ()
    operator: str = "NONE"  # NONE | OR | AND
    exceptions: Tuple[str, ...] = ()
    parse_error: Optional[str] = None

    @property
    def is_unknown(self) -> bool:
        return not self.ids or self.parse_error is not None

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "ids": list(self.ids),
            "operator": self.operator,
            "exceptions": list(self.exceptions),
            "parse_error": self.parse_error,
        }


UNKNOWN_EXPRESSION = LicenseExpression(raw="UNKNOWN")


def _clean(raw: Optional[str]) -> str:
    if not raw:
        return ""
    text = str(raw).strip()
    # Common non-SPDX spellings seen in the wild.
    text = text.replace("/", " OR ").replace(",", " OR ")
    text = re.sub(r"\s+", " ", text)
    return text


def parse_expression(raw: Optional[str]) -> LicenseExpression:
    """Parse a license string into a ``LicenseExpression``.

    Never raises: a malformed value returns an expression with
    ``parse_error`` set and no ids, so callers classify it as unknown.
    """
    text = _clean(raw)
    if not text or text.upper() in {"UNKNOWN", "NONE", "NOASSERTION", "NULL", "N/A", "-"}:
        return LicenseExpression(raw=str(raw or ""), parse_error=None if not text else "empty expression")

    stripped = text.strip("() ")
    tokens = _TOKEN_RE.findall(stripped)
    if not tokens:
        return LicenseExpression(raw=text, parse_error="no license identifiers found")

    ids: List[str] = []
    exceptions: List[str] = []
    operators: Set[str] = set()
    expect_with_operand = False
    for token in tokens:
        upper = token.upper()
        if upper in {"OR", "AND", "WITH"}:
            if expect_with_operand:
                return LicenseExpression(raw=text, parse_error=f"unexpected operator after WITH: {token}")
            operators.add(upper)
            expect_with_operand = upper == "WITH"
            continue
        if token in {"(", ")"}:
            continue
        if expect_with_operand:
            exceptions.append(token)
            expect_with_operand = False
            continue
        ids.append(token)

    if not ids:
        return LicenseExpression(raw=text, parse_error="no license identifiers found")
    if len(set(operators & {"OR", "AND"})) > 1:
        return LicenseExpression(raw=text, ids=tuple(ids), exceptions=tuple(exceptions),
                                 parse_error="mixed AND/OR without parentheses is ambiguous")
    operator = "AND" if "AND" in operators else ("OR" if "OR" in operators else "NONE")
    return LicenseExpression(raw=text, ids=tuple(ids), operator=operator, exceptions=tuple(exceptions))


@dataclass
class LicensePolicySets:
    """Explicit allow/warn/block lists, externalized from code."""

    allowed: Set[str] = field(default_factory=set)
    warning: Set[str] = field(default_factory=set)
    blocked: Set[str] = field(default_factory=set)
    unknown_action: str = "warn"  # warn | block | allow

    def classify_single(self, license_id: str) -> str:
        if license_id in self.blocked:
            return "blocked"
        if license_id in self.warning:
            return "warning"
        if license_id in self.allowed:
            return "allowed"
        return "unknown"

    def classify(self, raw: Optional[str]) -> str:
        """Classify a whole license expression.

        ``unknown`` never degrades to ``allowed`` unless the operator has
        explicitly configured ``unknown_action: allow`` -- and even then
        the finding is still reported, only its gate behaviour changes.
        """
        expression = parse_expression(raw)
        if expression.is_unknown:
            return {"warn": "unknown", "block": "blocked", "allow": "allowed"}.get(
                self.unknown_action, "unknown")
        classifications = [self.classify_single(license_id) for license_id in expression.ids]
        if expression.operator == "OR":
            # Consumer may pick one branch: take the most permissive.
            best = sorted(classifications, key=lambda c: CLASSIFICATION_ORDER.index(c))[0]
            return best
        # AND / NONE: every obligation applies, so take the strictest.
        worst = sorted(classifications, key=lambda c: -CLASSIFICATION_ORDER.index(c))[0]
        return worst


DEFAULT_PERMISSIVE = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib",
    "Unlicense", "CC0-1.0", "0BSD", "Python-2.0", "PSF-2.0", "BlueOak-1.0.0",
}
# LGPL-2.1/3.0 default to *blocked* rather than *warning*: their linking
# obligations (dynamic linking / relinkability) are the ones legal teams
# actually reject in commercial products. An organization that has a
# standing approval for LGPL moves it to `licenses.warning` in policy.yaml.
DEFAULT_WEAK_COPYLEFT = {
    "LGPL-2.0", "MPL-1.1", "MPL-2.0", "EPL-1.0",
    "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "Artistic-2.0",
}
DEFAULT_STRONG_COPYLEFT = {
    "GPL-2.0", "GPL-3.0", "AGPL-1.0", "AGPL-3.0", "SSPL-1.0", "OSL-3.0",
    "EUPL-1.2", "LGPL-2.1", "LGPL-3.0",
}


def default_policy(unknown_action: str = "warn") -> LicensePolicySets:
    return LicensePolicySets(
        allowed=set(DEFAULT_PERMISSIVE),
        warning=set(DEFAULT_WEAK_COPYLEFT),
        blocked=set(DEFAULT_STRONG_COPYLEFT),
        unknown_action=unknown_action,
    )
