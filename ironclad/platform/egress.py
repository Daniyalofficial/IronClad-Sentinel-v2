"""Per-organization outbound egress policy.

The process-global ``IRONCLAD_EGRESS_ALLOWLIST`` forces every organization in
a multi-tenant deployment onto one egress set, which contradicts the tenancy
model enforced everywhere else in the product. This module adds an
organization-scoped allowlist stored in the existing (previously unused)
``Organization.settings`` JSON column, so no parallel configuration system
is introduced.

Precedence — intersection, i.e. the most restrictive wins
---------------------------------------------------------
The organization policy can only ever **narrow** what the global allowlist
permits, never widen it:

* global unset, org unset            -> no allowlist (SSRF rules only)
* global set, org unset              -> global applies
* global unset, org set              -> org applies
* both set                           -> only hosts allowed by BOTH

Intersection is the safe model: an organization cannot grant itself egress
the deployment operator did not permit, and an operator tightening the global
list immediately tightens every organization. Widening semantics would let a
tenant escalate its own network reach, which is not something a tenant
should be able to do.

Enforcement point
-----------------
Checked inside ``resolve_target()`` **before** DNS, alongside the global
allowlist, so a rejected host is never resolved and no socket is opened.
Because ``resolve_target()`` runs for the initial destination *and* every
redirect hop, both are covered.

Organization context is carried in a contextvar rather than threaded through
every call signature, matching how ``observability`` carries request context.
Flows with no organization context (pre-authentication, CLI) fall back to the
global allowlist exactly as before.
"""
from __future__ import annotations

import json
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from ironclad.platform.integrations import (
    EGRESS_ALLOWLIST_ENV,
    EgressBlocked,
    egress_allowlist,
    host_allowed_by_allowlist,
)

#: Key inside ``Organization.settings`` holding the allowlist.
SETTINGS_KEY = "egress_allowlist"

#: A valid hostname label: 1-63 chars, alphanumerics and hyphens, no leading
#: or trailing hyphen. Deliberately strict -- anything looser invites
#: bypasses.
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

#: A valid IPv4/IPv6 literal is delegated to ipaddress by the caller.
MAX_ENTRIES = 200
MAX_HOSTNAME_LENGTH = 253


class EgressPolicyError(ValueError):
    """Raised for a malformed egress policy. Carries every problem at once."""

    def __init__(self, problems: List[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


def normalise_entry(entry: str) -> str:
    """Trim and lowercase one allowlist entry."""
    return (entry or "").strip().lower()


def validate_entry(entry: str) -> Optional[str]:
    """Return a problem string for a single entry, or None if it is valid.

    Accepts:
      * an exact hostname, validated label by label
      * a leading ``*.`` wildcard followed by a valid hostname
      * a valid IPv4 or IPv6 literal

    Rejects empty entries, malformed labels, a bare ``*``, a wildcard that is
    not a leading ``*.``, embedded wildcards, over-long names, and unsafe
    characters.
    """
    import ipaddress

    entry = normalise_entry(entry)
    if not entry:
        return "entry is empty"
    if len(entry) > MAX_HOSTNAME_LENGTH:
        return f"{entry!r} exceeds {MAX_HOSTNAME_LENGTH} characters"

    # IP literal (optionally bracketed, as it appears in a URL).
    bare = entry.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return None
    except ValueError:
        pass

    if "*" in entry:
        # Only an explicit leading "*." is permitted, and only once.
        if not entry.startswith("*."):
            return f"{entry!r}: a wildcard must be a leading '*.' (no embedded or trailing wildcards)"
        if entry.count("*") > 1:
            return f"{entry!r}: only one wildcard is permitted"
        remainder = entry[2:]
        if not remainder:
            return f"{entry!r}: a wildcard must be followed by a hostname"
        entry = remainder

    labels = entry.split(".")
    if len(labels) < 2:
        return f"{entry!r}: a hostname must have at least two labels"
    for label in labels:
        if not _LABEL_RE.match(label):
            return f"{entry!r}: {label!r} is not a valid hostname label"
    if label_is_ip_like(labels[-1]) and all(l.isdigit() for l in labels):
        return f"{entry!r}: looks like a malformed IP address"
    return None


def label_is_ip_like(label: str) -> bool:
    return bool(label) and label.isdigit()


def validate_allowlist(entries: Any) -> List[str]:
    """Validate a whole allowlist, returning every problem found."""
    problems: List[str] = []
    if entries is None:
        return problems
    if not isinstance(entries, list):
        return ["allowlist must be a list of hostnames"]
    if len(entries) > MAX_ENTRIES:
        problems.append(f"allowlist has {len(entries)} entries; maximum is {MAX_ENTRIES}")

    seen: Set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, str):
            problems.append(f"entry {index} is not a string: {entry!r}")
            continue
        problem = validate_entry(entry)
        if problem:
            problems.append(f"entry {index}: {problem}")
            continue
        normalised = normalise_entry(entry)
        if normalised in seen:
            problems.append(f"entry {index}: duplicate {normalised!r}")
            continue
        seen.add(normalised)
    return problems


@dataclass(frozen=True)
class EgressPolicy:
    """An organization's egress policy."""

    org_id: int
    entries: frozenset = frozenset()
    enabled: bool = False

    def as_allowlist(self) -> Optional[frozenset]:
        """The effective allowlist, or None when no policy is configured."""
        if not self.enabled:
            return None
        return self.entries


def parse_settings(settings_json: Optional[str]) -> Dict[str, Any]:
    try:
        parsed = json.loads(settings_json or "{}")
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def policy_from_settings(org_id: int, settings_json: Optional[str]) -> EgressPolicy:
    """Build an EgressPolicy from an organization's settings JSON."""
    settings = parse_settings(settings_json)
    entries = settings.get(SETTINGS_KEY)
    if entries is None:
        return EgressPolicy(org_id=org_id)
    if not isinstance(entries, list):
        return EgressPolicy(org_id=org_id)
    return EgressPolicy(
        org_id=org_id,
        entries=frozenset(normalise_entry(e) for e in entries if isinstance(e, str) and e.strip()),
        enabled=True,
    )


def settings_with_policy(settings_json: Optional[str], entries: List[str]) -> str:
    """Return settings JSON with the allowlist replaced (or removed if empty)."""
    settings = parse_settings(settings_json)
    if entries:
        settings[SETTINGS_KEY] = [normalise_entry(e) for e in entries]
    else:
        settings.pop(SETTINGS_KEY, None)
    return json.dumps(settings, sort_keys=True)


# --------------------------------------------------------------------------- #
# Organization context
# --------------------------------------------------------------------------- #
_current_org: ContextVar[Optional[int]] = ContextVar("egress_org_id", default=None)


def set_org_context(org_id: Optional[int]):
    """Bind the organization for the current context. Returns a reset token."""
    return _current_org.set(org_id)


def reset_org_context(token) -> None:
    _current_org.reset(token)


def current_org_id() -> Optional[int]:
    return _current_org.get()


def effective_allowlist(org_allowlist: Optional[frozenset]) -> Optional[frozenset]:
    """Combine the global and organization allowlists by intersection.

    Returns None only when neither is configured, meaning no allowlist and
    the existing SSRF controls are the only control.
    """
    global_allowlist = egress_allowlist()
    if global_allowlist is None and org_allowlist is None:
        return None
    if global_allowlist is None:
        return org_allowlist
    if org_allowlist is None:
        return global_allowlist
    # Intersection: the organization can only narrow, never widen.
    return global_allowlist & org_allowlist


def host_allowed_for_org(hostname: str, org_allowlist: Optional[frozenset]) -> bool:
    """Check a hostname against the combined (intersected) allowlist."""
    return host_allowed_by_allowlist(hostname, effective_allowlist(org_allowlist))


def resolve_org_allowlist(loader, org_id: Optional[int]) -> Optional[frozenset]:
    """Load an organization's allowlist via ``loader(org_id) -> settings_json``.

    The loader is injected so this module stays free of a database import and
    remains unit-testable. Returns None when there is no organization context.
    """
    if org_id is None:
        return None
    settings_json = loader(org_id)
    return policy_from_settings(org_id, settings_json).as_allowlist()


def check_egress(hostname: str, org_loader=None, org_id: Optional[int] = None) -> None:
    """Raise :class:`EgressBlocked` if the host is not permitted.

    Called from ``resolve_target()`` before DNS. With no organization context
    the behaviour is exactly the pre-existing global-only check.
    """
    org_allowlist = resolve_org_allowlist(org_loader, org_id) if org_loader else None
    if not host_allowed_for_org(hostname, org_allowlist):
        scope = "the organization egress policy" if org_allowlist is not None else EGRESS_ALLOWLIST_ENV
        raise EgressBlocked(f"{hostname} is not permitted by {scope}; refusing to resolve it")
