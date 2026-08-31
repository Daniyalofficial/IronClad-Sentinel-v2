"""Job handlers: the work the API queues and the worker executes.

Keeping this in its own module means the API package and the worker can
both import it without a circular dependency, and a Celery/RQ worker only
has to call :func:`register_job_handlers` to get identical behaviour.
"""
from __future__ import annotations

import json
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ironclad.platform.database import session_scope
from ironclad.platform.jobs import JobQueue
from ironclad.platform.models import Scan
from ironclad.platform.observability import WORKER_DURATION, get_logger, registry, set_request_context
from ironclad.platform.scanning import perform_scan, resolve_policy

logger = get_logger("worker")

SCAN_RUN = "scan.run"


def _load_scan(session: Session, org_id: int, scan_id: int) -> Optional[Scan]:
    """Tenant-scoped lookup: a job payload can never read another org's scan."""
    return session.execute(
        select(Scan).where(Scan.org_id == org_id, Scan.id == scan_id)
    ).scalar_one_or_none()


def handle_scan_run(engine, session: Session, payload: dict) -> None:
    """Execute one scan job.

    The job is idempotent: re-running it against a scan that already
    succeeded is a no-op, and the ``(scan_id, fingerprint)`` unique
    constraint means a replay cannot duplicate findings.
    """
    scan_id = int(payload.get("scan_id") or 0)
    org_id = int(payload.get("org_id") or 0)
    set_request_context(org_id=org_id, scan_id=scan_id,
                        correlation_id=str(payload.get("correlation_id", "")))
    scan = _load_scan(session, org_id, scan_id)
    if scan is None:
        logger.warning("scan job for missing scan", extra={"fields": {"scan_id": scan_id}})
        return
    if scan.status in ("succeeded", "cancelled"):
        logger.info("scan job already terminal",
                    extra={"fields": {"scan_id": scan_id, "status": scan.status}})
        return

    policy = resolve_policy(session, org_id, payload.get("policy_id"), payload.get("policy_document"))
    with registry.timer(WORKER_DURATION, "Worker job duration"):
        perform_scan(session, org_id=org_id, project_id=scan.project_id, scan_row=scan,
                     target=payload["target"], policy=policy,
                     actor=payload.get("actor", "worker"),
                     correlation_id=str(payload.get("correlation_id", "")))
    session.commit()
    logger.info("scan job finished", extra={"fields": {"scan_id": scan_id,
                                                       "status": scan.status}})


def register_job_handlers(queue: JobQueue, engine) -> None:
    """Register every handler on a queue, bound to an engine."""

    def _scan_runner(session: Session, payload: dict) -> None:
        handle_scan_run(engine, session, payload)

    queue.register(SCAN_RUN, _scan_runner)
