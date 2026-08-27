"""Role-based access control.

Five roles, ordered by privilege:

    owner > admin > security > developer > viewer

Permissions are explicit strings (``project.manage``, ``scan.create``, ...)
rather than ad-hoc boolean flags, so a new capability is added by naming it
once here instead of being inferred in six places. Every API route declares
the permission it needs; nothing checks "is this user an admin?" directly.

Deny by default: an unknown role gets no permissions at all, and an unknown
permission is never granted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Set

# --------------------------------------------------------------------------- #
# Permission catalogue
# --------------------------------------------------------------------------- #
ORGANIZATION_READ = "organization.read"
ORGANIZATION_MANAGE = "organization.manage"
PROJECT_READ = "project.read"
PROJECT_MANAGE = "project.manage"
SCAN_CREATE = "scan.create"
SCAN_READ = "scan.read"
SCAN_CANCEL = "scan.cancel"
FINDING_READ = "finding.read"
FINDING_MANAGE = "finding.manage"
SBOM_READ = "sbom.read"
LICENSE_READ = "license.read"
POLICY_READ = "policy.read"
POLICY_MANAGE = "policy.manage"
INTEGRATION_READ = "integration.read"
INTEGRATION_MANAGE = "integration.manage"
AUDIT_READ = "audit.read"
USER_READ = "user.read"
USER_MANAGE = "user.manage"
TOKEN_MANAGE = "token.manage"

ALL_PERMISSIONS: FrozenSet[str] = frozenset({
    ORGANIZATION_READ, ORGANIZATION_MANAGE,
    PROJECT_READ, PROJECT_MANAGE,
    SCAN_CREATE, SCAN_READ, SCAN_CANCEL,
    FINDING_READ, FINDING_MANAGE,
    SBOM_READ, LICENSE_READ,
    POLICY_READ, POLICY_MANAGE,
    INTEGRATION_READ, INTEGRATION_MANAGE,
    AUDIT_READ,
    USER_READ, USER_MANAGE,
    TOKEN_MANAGE,
})

_VIEWER: Set[str] = {
    ORGANIZATION_READ, PROJECT_READ, SCAN_READ, FINDING_READ,
    SBOM_READ, LICENSE_READ, POLICY_READ,
}

_DEVELOPER: Set[str] = _VIEWER | {
    SCAN_CREATE, INTEGRATION_READ, TOKEN_MANAGE,
}

_SECURITY: Set[str] = _DEVELOPER | {
    FINDING_MANAGE, POLICY_READ, INTEGRATION_READ, AUDIT_READ, USER_READ, SCAN_CANCEL,
}

_ADMIN: Set[str] = _SECURITY | {
    ORGANIZATION_MANAGE, PROJECT_MANAGE, POLICY_MANAGE,
    INTEGRATION_MANAGE, USER_MANAGE,
}

_OWNER: Set[str] = set(ALL_PERMISSIONS)

ROLE_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "viewer": frozenset(_VIEWER),
    "developer": frozenset(_DEVELOPER),
    "security": frozenset(_SECURITY),
    "admin": frozenset(_ADMIN),
    "owner": _OWNER,
}

ROLE_RANK = {"viewer": 0, "developer": 1, "security": 2, "admin": 3, "owner": 4}


class PermissionDenied(Exception):
    """Raised when an actor lacks a permission.

    Carries the permission name so the API layer can return a 403 with an
    actionable message instead of a bare "forbidden".
    """

    def __init__(self, permission: str, role: str = ""):
        self.permission = permission
        self.role = role
        detail = f" (role: {role})" if role else ""
        super().__init__(f"missing permission '{permission}'{detail}")


@dataclass(frozen=True)
class Principal:
    """The authenticated actor an authorization decision is made about."""

    user_id: int
    org_id: int
    email: str
    role: str
    is_active: bool = True
    #: Populated for API-token callers so a token can be narrower than its owner.
    token_scopes: FrozenSet[str] = frozenset()

    @property
    def permissions(self) -> FrozenSet[str]:
        granted = ROLE_PERMISSIONS.get(self.role, frozenset())
        if self.token_scopes:
            # A token may narrow the owner's permissions but never widen them.
            return granted & self.token_scopes
        return granted

    def can(self, permission: str) -> bool:
        if not self.is_active:
            return False
        if permission not in ALL_PERMISSIONS:
            return False
        return permission in self.permissions

    def require(self, permission: str) -> "Principal":
        if not self.can(permission):
            raise PermissionDenied(permission, self.role)
        return self


def role_at_least(role: str, minimum: str) -> bool:
    """True when ``role`` is at least as privileged as ``minimum``."""
    return ROLE_RANK.get(role, -1) >= ROLE_RANK.get(minimum, 99)


def describe_roles() -> Dict[str, list]:
    """Role -> sorted permission list, for the dashboard and docs."""
    return {role: sorted(permissions) for role, permissions in ROLE_PERMISSIONS.items()}
