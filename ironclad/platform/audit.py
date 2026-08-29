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


# --------------------------------------------------------------------------- #
# Export (compliance evidence)
# --------------------------------------------------------------------------- #
#: Chunk size for streaming exports. An audit trail can be large enough that
#: materialising it all at once would spike memory, so exports are produced in
#: ordered chunks and yielded.
EXPORT_CHUNK_SIZE = 1000

EXPORT_FIELDS = ("id", "created_at", "actor", "actor_id", "action",
                 "target_type", "target_id", "request_id", "org_id")


def iter_export(session: Session, org_id: int, *, action: Optional[str] = None,
                actor: Optional[str] = None, since=None, until=None,
                chunk_size: int = EXPORT_CHUNK_SIZE):
    """Yield audit records oldest-first in chunks, for streaming export.

    Oldest-first is deliberate: an auditor reading an export expects
    chronological order, which is the reverse of the UI's newest-first list.

    Keyset pagination on ``id`` rather than OFFSET, so exporting a large trail
    does not get quadratically slower as the offset grows.
    """
    chunk = max(1, min(int(chunk_size), 5000))
    last_id = 0
    while True:
        statement = (
            select(AuditEvent)
            .where(AuditEvent.org_id == int(org_id), AuditEvent.id > last_id)
            .order_by(AuditEvent.id)
            .limit(chunk)
        )
        if action:
            statement = statement.where(AuditEvent.action == action)
        if actor:
            statement = statement.where(AuditEvent.actor == actor)
        if since is not None:
            statement = statement.where(AuditEvent.created_at >= since)
        if until is not None:
            statement = statement.where(AuditEvent.created_at <= until)

        rows = list(session.execute(statement).scalars().all())
        if not rows:
            return
        for row in rows:
            yield to_dict(row)
        last_id = rows[-1].id
        if len(rows) < chunk:
            return


def export_json_lines(session: Session, org_id: int, **filters) -> str:
    """Newline-delimited JSON: one record per line, safe to stream and append."""
    return "".join(json.dumps(record, sort_keys=True, default=str) + "\n"
                   for record in iter_export(session, org_id, **filters))


def export_csv(session: Session, org_id: int, **filters) -> str:
    """CSV for auditors who need a spreadsheet.

    ``metadata`` is serialised as JSON in a single column. Values that begin
    with ``=``, ``+``, ``-`` or ``@`` are prefixed with a single quote to
    prevent CSV/spreadsheet formula injection -- an auditor opening an export
    must not execute a formula that came from audit data.
    """
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(list(EXPORT_FIELDS) + ["metadata"])
    for record in iter_export(session, org_id, **filters):
        row = [record.get(field, "") for field in EXPORT_FIELDS]
        row.append(json.dumps(record.get("metadata", {}), sort_keys=True, default=str))
        writer.writerow([_csv_safe(value) for value in row])
    return buffer.getvalue()


def _csv_safe(value: Any) -> Any:
    """Defuse spreadsheet formula injection."""
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #
def retention_summary(session: Session, org_id: int, *, retention_days: int) -> Dict[str, Any]:
    """Report what a retention policy would remove, without removing it.

    Previewing before purging is the point: deleting audit history is
    irreversible and an operator must be able to see the consequence first.
    """
    from datetime import timedelta

    if retention_days < 0:
        raise ValueError("retention_days must be non-negative")
    cutoff = utcnow() - timedelta(days=retention_days)
    total = count_for_org(session, org_id)
    expiring = int(session.execute(
        select(func.count(AuditEvent.id))
        .where(AuditEvent.org_id == int(org_id), AuditEvent.created_at < cutoff)
    ).scalar_one())
    return {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "total_records": total,
        "expiring_records": expiring,
        "retained_records": total - expiring,
    }


def purge_expired(session: Session, org_id: int, *, retention_days: int,
                  actor: str = "system", request_id: str = "") -> Dict[str, Any]:
    """Delete audit records older than the retention window.

    The purge is itself audited *before* the delete runs, so the fact that
    audit history was removed is permanently recorded. Deleting the record of
    a deletion would defeat the purpose of an audit log.
    """
    from datetime import timedelta

    if retention_days < 0:
        raise ValueError("retention_days must be non-negative")
    summary = retention_summary(session, org_id, retention_days=retention_days)

    record(session, org_id=org_id, action="audit.purged", actor=actor,
           target_type="audit_events", target_id="", request_id=request_id,
           metadata={"retention_days": retention_days,
                     "cutoff": summary["cutoff"],
                     "records_removed": summary["expiring_records"]})

    cutoff = utcnow() - timedelta(days=retention_days)
    session.execute(
        AuditEvent.__table__.delete()
        .where(AuditEvent.org_id == int(org_id), AuditEvent.created_at < cutoff)
    )
    return summary
