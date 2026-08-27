"""Audit log.

Append-only by construction: this module exposes ``record`` and ``list_for_org``
and nothing else. There is no update or delete path, the API mounts the
audit route read-only, and the migration creates no trigger or rule that
would allow one.

What must be audited (and is, at the call sites):

    auth.login / auth.logout / auth.login_failed
    user.created / user.role_changed / user.deactivated
    project.created / project.archived
    policy.created / policy.updated / policy.deleted
    scan.created / scan.cancelled
    finding.suppressed / finding.resolved
    integration.created / integration.updated / integration.deleted
    token.created / token.revoked

Every record carries actor, timestamp, organization, action, target and a
metadata blob, plus the request id so an audit line can be joined to the
request log.

Redaction: metadata values are passed through :func:`redact_secrets`, so a
caller cannot accidentally persist a password, token or integration secret
into the audit trail.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ironclad.platform.models import AuditEvent, utcnow
from ironclad.platform.rbac import Principal

SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)")
REDACTED = "[redacted]"


def redact_secrets(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Strip anything that looks like a credential from an audit payload.

    Applied to nested mappings as well, because integration configs are
    stored as nested dictionaries.
    """
    if not metadata:
        return {}
    cleaned: Dict[str, Any] = {}
    for key, value in metadata.items():
        if SENSITIVE_KEY.search(str(key)):
            cleaned[key] = REDACTED
        elif isinstance(value, dict):
            cleaned[key] = redact_secrets(value)
        elif isinstance(value, list):
            cleaned[key] = [redact_secrets(v) if isinstance(v, dict) else v for v in value]
        else:
            cleaned[key] = value
    return cleaned


def record(session: Session, *, org_id: int, action: str, actor: str = "anonymous",
           actor_id: Optional[int] = None, target_type: str = "", target_id: str = "",
           metadata: Optional[Dict[str, Any]] = None, request_id: str = "") -> AuditEvent:
    """Append an audit record. This is the only writer."""
    event = AuditEvent(
        org_id=int(org_id),
        actor=str(actor or "anonymous"),
        actor_id=actor_id,
        action=str(action),
        target_type=str(target_type or ""),
        target_id=str(target_id or ""),
        metadata_json=json.dumps(redact_secrets(metadata), sort_keys=True, default=str),
        request_id=str(request_id or ""),
        created_at=utcnow(),
    )
    session.add(event)
    return event


def record_for_principal(session: Session, principal: Optional[Principal], *, action: str,
                         target_type: str = "", target_id: str = "",
                         metadata: Optional[Dict[str, Any]] = None,
                         request_id: str = "") -> Optional[AuditEvent]:
    """Convenience wrapper that fills actor/org from the authenticated principal."""
    if principal is None:
        return None
    return record(session, org_id=principal.org_id, action=action, actor=principal.email,
                  actor_id=principal.user_id, target_type=target_type, target_id=target_id,
                  metadata=metadata, request_id=request_id)


def list_for_org(session: Session, org_id: int, *, action: Optional[str] = None,
                 actor: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[AuditEvent]:
    """Page through an organization's audit trail, newest first."""
    statement = select(AuditEvent).where(AuditEvent.org_id == int(org_id))
    if action:
        statement = statement.where(AuditEvent.action == action)
    if actor:
        statement = statement.where(AuditEvent.actor == actor)
    statement = statement.order_by(desc(AuditEvent.created_at), desc(AuditEvent.id))
    statement = statement.limit(max(1, min(int(limit), 500))).offset(max(0, int(offset)))
    return list(session.execute(statement).scalars().all())


def count_for_org(session: Session, org_id: int) -> int:
    return int(session.execute(
        select(func.count(AuditEvent.id)).where(AuditEvent.org_id == int(org_id))
    ).scalar_one())


def to_dict(event: AuditEvent) -> Dict[str, Any]:
    try:
        metadata = json.loads(event.metadata_json or "{}")
    except ValueError:
        metadata = {}
    return {
        "id": event.id,
        "org_id": event.org_id,
        "actor": event.actor,
        "actor_id": event.actor_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "metadata": metadata,
        "request_id": event.request_id,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }
