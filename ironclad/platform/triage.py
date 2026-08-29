"""Finding triage service.

Both the JSON API and the server-rendered dashboard need to suppress,
resolve and reopen findings. Keeping the logic here means the two entry
points cannot diverge on authorization or on what counts as a valid
transition -- duplicated authorization checks are exactly how a bypass gets
introduced later by someone editing one copy.
"""
from __future__ import annotations

import json
from typing import Optional

from ironclad.platform import events
from ironclad.platform.models import Finding, FindingEvent, utcnow

VALID_STATUSES = ("open", "resolved", "suppressed")

_EVENT_TYPES = {
    "resolved": "finding.resolved",
    "suppressed": "finding.suppressed",
    "open": "finding.reopened",
}


class TriageError(ValueError):
    """Raised when a triage transition is not permitted.

    ``code`` maps to an HTTP status so both entry points translate it
    identically.
    """

    def __init__(self, message: str, code: int = 422):
        super().__init__(message)
        self.code = code


def validate_transition(status: str, reason: str) -> None:
    """Validate a requested transition. Raises :class:`TriageError`."""
    if status not in VALID_STATUSES:
        raise TriageError(
            f"status must be one of {list(VALID_STATUSES)}, got {status!r}")
    if status == "suppressed" and not (reason or "").strip():
        raise TriageError("a reason is required to suppress a finding")


def apply_triage(session, *, finding: Finding, status: str, reason: str,
                 actor_email: str, org_id: int, audit, request_id: str = "") -> Finding:
    """Apply a validated transition, record the event and audit it.

    The caller is responsible for having already authorized the actor and
    established that ``finding`` belongs to ``org_id``.
    """
    validate_transition(status, reason)

    previous = finding.status
    finding.status = status
    if status in ("resolved", "suppressed"):
        finding.resolved_at = utcnow()
        finding.suppressed_by = actor_email
        finding.suppressed_reason = reason
    else:
        finding.resolved_at = None
        finding.suppressed_by = ""
        finding.suppressed_reason = ""

    event_type = _EVENT_TYPES[status]
    session.add(FindingEvent(
        org_id=org_id, finding_id=finding.id, event_type=event_type,
        actor=actor_email,
        detail=json.dumps({"from": previous, "to": status, "reason": reason}),
    ))

    if event_type == "finding.suppressed":
        events.default_bus.publish(session, events.FINDING_SUPPRESSED, org_id,
                                   {"finding_id": finding.id, "reason": reason},
                                   subject_id=str(finding.id))
    elif event_type == "finding.resolved":
        events.default_bus.publish(session, events.FINDING_RESOLVED, org_id,
                                   {"finding_id": finding.id}, subject_id=str(finding.id))

    audit(action=f"finding.{status}", target_type="finding",
          target_id=str(finding.id),
          metadata={"from": previous, "reason": reason})
    session.commit()
    return finding
