"""OSV (Open Source Vulnerabilities) record conversion.

IronClad Sentinel stores advisories in a deliberately small internal shape::

    {"id", "cve", "affected", "severity", "summary", "fixed_in"}

The rest of the world uses the `OSV schema <https://ossf.github.io/osv-schema/>`_,
whose ``affected[].ranges[].events`` encoding is richer: a vulnerability can
have several disjoint ranges, an explicit ``versions`` list, an
``introduced``/``fixed``/``last_affected`` triple per range, and a range type
(``SEMVER``, ``ECOSYSTEM`` or ``GIT``) that determines whether the values are
comparable versions at all.

This module is the single place that understands the OSV encoding. Both the
``directory`` advisory overlay (so an organization can point
``advisory_path`` at a real OSV dump) and the opt-in ``remote`` OSV endpoint
convert through here, rather than each carrying a partial, divergent
implementation.

Conversion rules, and why:

* ``GIT`` ranges carry commit hashes, which are not comparable to the
  versions parsed out of a manifest. They are dropped rather than guessed.
* ``introduced: "0"`` means "from the beginning", so it contributes no lower
  bound instead of a meaningless ``>=0``.
* A range with an ``introduced`` but no ``fixed``/``last_affected`` is
  open-ended and still affects every later version, so it emits ``>=X``.
* A range with neither bound affects every version; that is emitted as
  ``>=0`` rather than an empty string, because the matcher treats an empty
  spec as "matches nothing".
* Disjoint ranges and explicit version lists are alternatives, so they are
  joined with ``||``; the comparators inside one range are conjunctions, so
  they are joined with ``,``.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

# OSV ecosystem identifier -> IronClad ecosystem key. OSV allows
# ecosystem-specific suffixes ("Debian:11", "Alpine:v3.18"); those are not
# mapped because IronClad's manifest parsers never produce them, and mapping
# them would silently claim coverage we do not have.
OSV_TO_ECOSYSTEM: Dict[str, str] = {
    "pypi": "python",
    "npm": "javascript",
    "go": "go",
    "rubygems": "ruby",
    "packagist": "php",
    "maven": "java",
    "crates.io": "rust",
    "nuget": "nuget",
}

ECOSYSTEM_TO_OSV: Dict[str, str] = {
    "python": "PyPI",
    "javascript": "npm",
    "go": "Go",
    "ruby": "RubyGems",
    "php": "Packagist",
    "java": "Maven",
    "rust": "crates.io",
    "nuget": "NuGet",
}

_SEVERITY_LEVELS = {"critical", "high", "medium", "moderate", "low", "unknown"}


def osv_ecosystem(ecosystem: str) -> str:
    """Map an IronClad ecosystem key to its OSV identifier."""
    return ECOSYSTEM_TO_OSV.get(ecosystem, ecosystem.capitalize())


def ironclad_ecosystem(osv_eco: str) -> Optional[str]:
    """Map an OSV ecosystem identifier to an IronClad key, or ``None``.

    ``None`` means "IronClad has no parser for this ecosystem", and the
    caller must drop the advisory rather than store it under a key nothing
    will ever look up.
    """
    if not osv_eco:
        return None
    base = str(osv_eco).split(":", 1)[0].strip().lower()
    return OSV_TO_ECOSYSTEM.get(base)


def affected_range_from_osv(ranges: Iterable[Dict[str, Any]],
                            versions: Iterable[str] = ()) -> str:
    """Build an IronClad ``affected`` expression from OSV range data.

    Returns ``">=0"`` when the record declares that every version is
    affected, so the matcher treats it as a match rather than as an empty
    (never-matching) spec.
    """
    alternatives: List[str] = []

    for rng in ranges or []:
        if not isinstance(rng, dict):
            continue
        if str(rng.get("type", "")).upper() == "GIT":
            # Commit hashes cannot be compared to manifest versions.
            continue
        events = rng.get("events") or []
        if not isinstance(events, list):
            continue
        lower: Optional[str] = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                raw = str(event["introduced"]).strip()
                lower = None if raw in {"0", ""} else raw
                continue
            upper_op: Optional[str] = None
            upper: Optional[str] = None
            if event.get("fixed"):
                upper_op, upper = "<", str(event["fixed"]).strip()
            elif event.get("last_affected"):
                upper_op, upper = "<=", str(event["last_affected"]).strip()
            elif "limit" in event:
                upper_op, upper = "<", str(event["limit"]).strip()
            tokens: List[str] = []
            if lower:
                tokens.append(f">={lower}")
            if upper_op:
                tokens.append(f"{upper_op}{upper}")
            alternatives.append(", ".join(tokens) if tokens else ">=0")
            lower = None
        if lower:
            # Open-ended: introduced with no fix, still vulnerable above it.
            alternatives.append(f">={lower}")

    explicit = [f"={str(v).strip()}" for v in (versions or []) if str(v).strip()]
    alternatives.extend(explicit)

    joined = " || ".join(a for a in alternatives if a)
    return joined or ">=0"


def severity_from_osv(record: Dict[str, Any]) -> str:
    """Best-effort severity for an OSV record.

    GitHub's reviewed advisories carry ``database_specific.severity``. When a
    record only has a CVSS vector there is no base score to read, so this
    falls back to ``medium`` rather than inventing a number from the vector
    string.
    """
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        raw = str(specific.get("severity", "")).strip().lower()
        if raw in _SEVERITY_LEVELS:
            return "high" if raw == "moderate" else raw
    for entry in record.get("severity") or []:
        if isinstance(entry, dict):
            raw = str(entry.get("score", "")).strip().lower()
            if raw in _SEVERITY_LEVELS:
                return raw
    return "medium"


def cve_from_osv(record: Dict[str, Any]) -> Optional[str]:
    """The first ``CVE-`` alias, if the record has one."""
    for alias in record.get("aliases") or []:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias.upper()
    return None


def summary_from_osv(record: Dict[str, Any], limit: int = 300) -> str:
    text = record.get("summary") or record.get("details") or ""
    text = " ".join(str(text).split())
    return text[:limit]


def record_to_entries(record: Dict[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Convert one OSV record into ``(ecosystem, package, advisory)`` tuples.

    A record can affect several packages and ecosystems at once, so this
    returns a list. Entries whose ecosystem IronClad cannot scan are
    dropped, and a record with no usable range information is still emitted
    (as ``>=0``) so an operator's overlay is never silently narrower than
    the feed it came from.
    """
    if not isinstance(record, dict):
        return []
    base = {
        "id": str(record.get("id") or "UNKNOWN"),
        "cve": cve_from_osv(record),
        "severity": severity_from_osv(record),
        "summary": summary_from_osv(record),
    }
    entries: List[Tuple[str, str, Dict[str, Any]]] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        if not isinstance(package, dict):
            continue
        eco = ironclad_ecosystem(str(package.get("ecosystem", "")))
        name = str(package.get("name", "")).strip()
        if not eco or not name:
            continue
        versions = affected.get("versions") or []
        if not isinstance(versions, list):
            versions = []
        advisory = dict(base)
        advisory["affected"] = affected_range_from_osv(affected.get("ranges"), versions)
        advisory["fixed_in"] = _first_fixed(affected.get("ranges"))
        if advisory["affected"] == ">=0" and _has_git_range(affected.get("ranges")):
            # We refused to guess a version range out of commit hashes, so
            # every declared version will be reported. Say so in the finding
            # text instead of letting it look version-scoped.
            advisory["summary"] = (
                f"{advisory['summary']} [This advisory tracks commits rather than "
                f"released versions and publishes no affected version range, so "
                f"every declared version is reported.]"
            ).strip()
        entries.append((eco, name, advisory))
    return entries


def _has_git_range(ranges: Any) -> bool:
    return any(isinstance(r, dict) and str(r.get("type", "")).upper() == "GIT"
               for r in ranges or [])


def _first_fixed(ranges: Any) -> str:
    for rng in ranges or []:
        if not isinstance(rng, dict):
            continue
        for event in rng.get("events") or []:
            if isinstance(event, dict) and event.get("fixed"):
                return str(event["fixed"])
    return ""


def iter_records(payload: Any) -> List[Dict[str, Any]]:
    """Flatten the three OSV payload shapes into a list of records.

    Accepts a single record, an OSV batch response (``{"vulns": [...]}``),
    and a bare JSON array of records.
    """
    if isinstance(payload, dict):
        if "vulns" in payload and isinstance(payload["vulns"], list):
            return [r for r in payload["vulns"] if isinstance(r, dict)]
        if "id" in payload and "affected" in payload:
            return [payload]
        return []
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    return []


def is_osv_payload(payload: Any) -> bool:
    """True when ``payload`` looks like OSV data rather than IronClad's schema.

    IronClad's bundled schema is ``{ecosystem: {package: [advisories]}}`` and
    never has a top-level ``id``/``affected``/``vulns`` key, so this is
    unambiguous.
    """
    if isinstance(payload, dict):
        if "vulns" in payload:
            return True
        return "id" in payload and "affected" in payload
    if isinstance(payload, list):
        return any(isinstance(r, dict) and "id" in r and "affected" in r for r in payload)
    return False


def build_database(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Fold OSV records into the IronClad database shape.

    Multiple records for the same package accumulate. Deduplicated on
    advisory ``id`` so importing the same dump twice is idempotent.
    """
    db: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for record in records:
        for eco, name, advisory in record_to_entries(record):
            bucket = db.setdefault(eco, {}).setdefault(name.lower(), [])
            if any(existing.get("id") == advisory["id"] for existing in bucket):
                continue
            bucket.append(advisory)
    return db
