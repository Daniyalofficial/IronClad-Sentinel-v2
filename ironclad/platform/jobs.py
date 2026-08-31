"""Job queue and worker.

Architecture::

    API  ->  jobs table (queued)  ->  worker  ->  scanner  ->  database
                                                        ->  events / reports

The queue is the ``jobs`` table. That is a deliberate choice rather than a
shortcut: it gives durable jobs, at-least-once delivery, retries with
backoff, crash recovery and "what is stuck?" visibility without requiring
a broker in a single-node install. The :class:`JobQueue` interface is
narrow enough that a Redis/RQ or Celery backend can be dropped in behind
``enqueue``/``claim`` without touching the API or the scanner.

Guarantees:

* **Non-blocking API.** ``POST /scan`` inserts a row and returns 202 with
  the scan id; the worker does the scanning.
* **At-least-once.** A claimed job that is never finished (worker killed)
  is reclaimed after ``stale_after_seconds`` and retried up to
  ``max_attempts``.
* **Idempotent scans.** ``scan_target`` honours the scan's idempotency key
  and the finding table's ``(scan_id, fingerprint)`` unique constraint, so
  a replayed job cannot double-insert findings.
"""
from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from ironclad.platform.models import Job, utcnow

QUEUED = "queued"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_STALE_AFTER_SECONDS = 15 * 60


class JobError(RuntimeError):
    """Raised when a job cannot be enqueued or claimed."""


@dataclass
class JobSpec:
    kind: str
    org_id: int
    payload: Dict[str, Any]
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    scheduled_at: Optional[Any] = None


class JobQueue:
    """Database-backed job queue."""

    def __init__(self, stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
                 retry_backoff: float = 5.0):
        self.stale_after_seconds = stale_after_seconds
        self.retry_backoff = retry_backoff
        self._handlers: Dict[str, Callable[[Session, Dict[str, Any]], None]] = {}

    def register(self, kind: str, handler: Callable[[Session, Dict[str, Any]], None]) -> None:
        self._handlers[kind] = handler

    def enqueue(self, session: Session, spec: JobSpec) -> Job:
        if spec.kind not in self._handlers:
            raise JobError(f"no handler registered for job kind {spec.kind!r}")
        job = Job(
            org_id=int(spec.org_id),
            kind=spec.kind,
            payload=json.dumps(spec.payload or {}, sort_keys=True, default=str),
            status=QUEUED,
            max_attempts=int(spec.max_attempts),
            scheduled_at=spec.scheduled_at or utcnow(),
            created_at=utcnow(),
        )
        session.add(job)
        session.flush()
        return job

    def claim(self, session: Session, kinds: Optional[List[str]] = None) -> Optional[Job]:
        """Atomically claim the next runnable job.

        Uses a single ``UPDATE ... WHERE id = (SELECT ...)`` so two workers
        cannot claim the same row. Jobs whose worker died while running are
        reclaimable once they are older than ``stale_after_seconds``.
        """
        now = utcnow()
        statement = select(Job.id).where(
            or_(
                Job.status == QUEUED,
                and_(Job.status == RUNNING,
                     Job.started_at.is_not(None),
                     Job.started_at < _seconds_ago(self.stale_after_seconds)),
            )
        )
        if kinds:
            statement = statement.where(Job.kind.in_(kinds))
        statement = statement.where(Job.scheduled_at <= now).order_by(Job.scheduled_at, Job.id).limit(1)
        row = session.execute(statement).first()
        if row is None:
            return None
        session.execute(
            update(Job)
            .where(Job.id == row[0], Job.status.in_((QUEUED, RUNNING)))
            .values(status=RUNNING, attempts=Job.attempts + 1, started_at=now, error="")
        )
        # Commit the claim itself. If the handler later raises and the caller
        # rolls back, the attempt counter and the RUNNING marker must survive
        # -- otherwise a job that always fails would retry forever because
        # `attempts` kept being rolled back to 0.
        session.commit()
        return session.get(Job, row[0])

    def finish(self, session: Session, job: Job, *, error: str = "",
               retry_backoff: Optional[float] = None) -> str:
        """Mark a job succeeded, or failed/retryable."""
        if not error:
            job.status = SUCCEEDED
            job.finished_at = utcnow()
            job.error = ""
            return SUCCEEDED
        job.error = error[:2000]
        if job.attempts >= job.max_attempts:
            job.status = FAILED
            job.finished_at = utcnow()
            return FAILED
        # Exponential backoff so a persistently failing job does not spin.
        backoff = self.retry_backoff if retry_backoff is None else retry_backoff
        delay = backoff * (2 ** max(0, job.attempts - 1))
        job.status = QUEUED
        job.scheduled_at = _seconds_from_now(delay)
        return QUEUED

    def cancel(self, session: Session, job: Job) -> None:
        job.status = CANCELLED
        job.finished_at = utcnow()

    def depth(self, session: Session, org_id: Optional[int] = None) -> Dict[str, int]:
        statement = select(Job.status)
        if org_id is not None:
            statement = statement.where(Job.org_id == int(org_id))
        counts: Dict[str, int] = {QUEUED: 0, RUNNING: 0, SUCCEEDED: 0, FAILED: 0, CANCELLED: 0}
        for (status,) in session.execute(statement).all():
            counts[status] = counts.get(status, 0) + 1
        return counts

    def run_pending(self, session: Session, limit: int = 10) -> int:
        """Process up to ``limit`` jobs. Returns how many were handled."""
        handled = 0
        for _ in range(max(0, int(limit))):
            job = self.claim(session)
            if job is None:
                break
            handler = self._handlers.get(job.kind)
            try:
                payload = json.loads(job.payload or "{}")
                if handler is None:
                    raise JobError(f"no handler registered for job kind {job.kind!r}")
                handler(session, payload)
                self.finish(session, job)
            except Exception as exc:  # noqa: BLE001 - a job failure must not kill the worker
                session.rollback()
                job = session.get(Job, job.id)
                if job is not None:
                    self.finish(session, job, error=f"{type(exc).__name__}: {exc}")
                    session.commit()
            handled += 1
        return handled


def _seconds_ago(seconds: float):
    from datetime import timedelta

    return utcnow() - timedelta(seconds=seconds)


def _seconds_from_now(seconds: float):
    from datetime import timedelta

    return utcnow() + timedelta(seconds=seconds)


class Worker:
    """Long-running poller around a :class:`JobQueue`."""

    def __init__(self, queue: JobQueue, poll_interval: float = 0.5, batch_size: int = 5):
        self.queue = queue
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        self.running = False
        self.processed = 0
        self.errors: List[str] = []

    def stop(self) -> None:
        self.running = False

    def run(self, session_factory: Callable[[], Session], max_jobs: Optional[int] = None) -> int:
        """Poll until stopped, or drain and exit when ``max_jobs`` is given.

        With ``max_jobs`` the worker returns as soon as it has handled that
        many jobs *or* the queue is empty -- otherwise a one-shot
        ``ironclad server worker --max-jobs 1`` would block forever on an
        idle queue, which is exactly what CI does not want.
        """
        self.running = True
        while self.running:
            session = session_factory()
            try:
                handled = self.queue.run_pending(session, limit=self.batch_size)
                session.commit()
            except Exception as exc:  # noqa: BLE001 - keep the worker alive
                session.rollback()
                self.errors.append(f"{type(exc).__name__}: {exc}")
                self.errors.append(traceback.format_exc(limit=3))
                handled = 0
            finally:
                session.close()
            self.processed += handled
            if max_jobs is not None and (self.processed >= max_jobs or handled == 0):
                self.running = False
                break
            if handled == 0:
                time.sleep(self.poll_interval)
        return self.processed
