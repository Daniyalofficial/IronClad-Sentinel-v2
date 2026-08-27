"""Internal event bus.

Events are the seam between "a scan happened" and everything that reacts to
it (persist findings, notify integrations, update metrics, write audit).
Two properties matter:

* **Stable contracts.** Every event type has a fixed schema declared in
  :data:`EVENT_SCHEMAS`. Publishing a payload that does not match raises,
  so a consumer never has to guess whether ``scan_id`` is present.
* **Distributable later.** Handlers are plain callables registered against
  an event type, and every event is also persisted to the ``events`` table.
  Swapping the in-process dispatcher for Redis/NATS later means changing
  where handlers are invoked, not what is published.

Handlers must not raise into the publisher: a failing notification handler
cannot be allowed to fail a scan. Exceptions are caught, counted, and
surfaced through ``EventBus.errors`` and the ``integration.failed`` event.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from ironclad.platform.models import Event, utcnow

SCAN_CREATED = "scan.created"
SCAN_STARTED = "scan.started"
SCAN_COMPLETED = "scan.completed"
SCAN_FAILED = "scan.failed"
SCAN_CANCELLED = "scan.cancelled"
FINDING_CREATED = "finding.created"
FINDING_RESOLVED = "finding.resolved"
FINDING_SUPPRESSED = "finding.suppressed"
POLICY_PASSED = "policy.passed"
POLICY_FAILED = "policy.failed"
INTEGRATION_FAILED = "integration.failed"
INTEGRATION_SUCCEEDED = "integration.succeeded"
AUTH_LOGIN = "auth.login"
AUTH_LOGOUT = "auth.logout"

#: event type -> required payload keys. Extra keys are allowed; missing
#: required keys are a programming error and raise at publish time.
EVENT_SCHEMAS: Dict[str, tuple] = {
    SCAN_CREATED: ("scan_id", "project_id"),
    SCAN_STARTED: ("scan_id",),
    SCAN_COMPLETED: ("scan_id", "finding_count", "risk_score"),
    SCAN_FAILED: ("scan_id", "error"),
    SCAN_CANCELLED: ("scan_id",),
    FINDING_CREATED: ("finding_id", "rule_id", "severity"),
    FINDING_RESOLVED: ("finding_id",),
    FINDING_SUPPRESSED: ("finding_id", "reason"),
    POLICY_PASSED: ("scan_id", "policy"),
    POLICY_FAILED: ("scan_id", "policy", "violation_count"),
    INTEGRATION_FAILED: ("integration_id", "error"),
    INTEGRATION_SUCCEEDED: ("integration_id",),
    AUTH_LOGIN: ("user_id",),
    AUTH_LOGOUT: ("user_id",),
}

ALL_EVENT_TYPES = tuple(sorted(EVENT_SCHEMAS))


class EventContractError(ValueError):
    """Raised when a published payload violates the declared contract."""


@dataclass
class DomainEvent:
    event_type: str
    org_id: int
    payload: Dict[str, Any]
    subject_id: str = ""
    correlation_id: str = ""
    created_at: Any = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "org_id": self.org_id,
            "subject_id": self.subject_id,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
        }


class EventBus:
    """In-process pub/sub with persistence to the ``events`` table."""

    def __init__(self, persist: bool = True):
        self._handlers: Dict[str, List[Callable[[DomainEvent], None]]] = {}
        self.persist = persist
        self.errors: List[Dict[str, str]] = []
        self.published: List[DomainEvent] = []

    def subscribe(self, event_type: str, handler: Callable[[DomainEvent], None]) -> None:
        if event_type not in EVENT_SCHEMAS:
            raise EventContractError(f"unknown event type {event_type!r}")
        self._handlers.setdefault(event_type, []).append(handler)

    def publish(self, session: Optional[Session], event_type: str, org_id: int,
                payload: Dict[str, Any], subject_id: str = "", correlation_id: str = "") -> DomainEvent:
        missing = [key for key in EVENT_SCHEMAS.get(event_type, ()) if key not in payload]
        if missing:
            raise EventContractError(f"{event_type} payload is missing required keys: {sorted(missing)}")
        if event_type not in EVENT_SCHEMAS:
            raise EventContractError(f"unknown event type {event_type!r}")

        event = DomainEvent(event_type=event_type, org_id=int(org_id), payload=dict(payload),
                            subject_id=str(subject_id), correlation_id=correlation_id)
        self.published.append(event)

        if self.persist and session is not None:
            session.add(Event(
                org_id=int(org_id),
                event_type=event_type,
                subject_id=str(subject_id),
                payload=json.dumps(payload, sort_keys=True, default=str),
                correlation_id=correlation_id,
            ))

        for handler in self._handlers.get(event_type, []):
            try:
                handler(event)
            except Exception as exc:  # noqa: BLE001 - a handler must not fail the publisher
                self.errors.append({"event_type": event_type, "error": f"{type(exc).__name__}: {exc}"})
        return event

    def handler_count(self, event_type: str) -> int:
        return len(self._handlers.get(event_type, []))


#: Process-wide default bus. Tests construct their own; production code uses
#: this so integrations and metrics can subscribe at startup.
default_bus = EventBus()
