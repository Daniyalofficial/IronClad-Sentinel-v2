"""Structured logging, correlation ids and metrics.

Everything here is standard-library only, so the scanner keeps its
zero-dependency property and the server adds nothing to scrape.

* **Structured logs.** One JSON object per line with ``timestamp``,
  ``level``, ``event``, ``request_id``, ``correlation_id``, ``org_id``,
  ``scan_id``. Machine-parseable by Loki/ELK without a formatter plugin.
* **Correlation.** ``request_id`` is generated per HTTP request; a scan
  started by that request carries the same id as ``correlation_id`` so a
  single investigation can join API log -> scan log -> worker log.
* **Metrics.** Counters/gauges/histograms in the Prometheus text exposition
  format at ``/metrics``. No client library, no background threads.
* **No secrets in logs.** ``safe_fields`` redacts any key that looks like a
  credential before it reaches the log line.
"""
from __future__ import annotations

import json
import logging
import math
import re
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|credential)")

_request_id: ContextVar[str] = ContextVar("request_id", default="")
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_org_id: ContextVar[int] = ContextVar("org_id", default=0)
_scan_id: ContextVar[int] = ContextVar("scan_id", default=0)


def new_request_id() -> str:
    return uuid.uuid4().hex


def set_request_context(request_id: str = "", correlation_id: str = "",
                        org_id: int = 0, scan_id: int = 0) -> None:
    if request_id:
        _request_id.set(request_id)
    if correlation_id:
        _correlation_id.set(correlation_id)
    if org_id:
        _org_id.set(int(org_id))
    if scan_id:
        _scan_id.set(int(scan_id))


def current_context() -> Dict[str, Any]:
    return {
        "request_id": _request_id.get(),
        "correlation_id": _correlation_id.get(),
        "org_id": _org_id.get(),
        "scan_id": _scan_id.get(),
    }


def safe_fields(**fields: Any) -> Dict[str, Any]:
    """Redact credential-shaped keys before they reach a log line."""
    return {key: ("[redacted]" if SENSITIVE_KEY.search(key) else value) for key, value in fields.items()}


class StructuredFormatter(logging.Formatter):
    """Render each record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update({k: v for k, v in current_context().items() if v})
        extra = getattr(record, "fields", None)
        if extra:
            payload.update(safe_fields(**extra))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, sort_keys=True)


def configure_logging(level: str = "INFO", stream=None) -> logging.Logger:
    """Install the structured formatter on the root logger. Idempotent."""
    root = logging.getLogger("ironclad")
    root.setLevel(level.upper())
    root.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(StructuredFormatter())
    root.addHandler(handler)
    root.propagate = False
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ironclad.{name}")


def log_event(logger: logging.Logger, event: str, level: str = "info", **fields: Any) -> None:
    logger.log(getattr(logging, level.upper(), logging.INFO), event, extra={"fields": fields})


@contextmanager
def request_scope(request_id: Optional[str] = None, **context: Any) -> Iterator[str]:
    """Bind a request id (and any extra context) for the duration of a block."""
    rid = request_id or new_request_id()
    tokens = {
        "request_id": _request_id.set(rid),
        "correlation_id": _correlation_id.set(context.get("correlation_id", rid)),
        "org_id": _org_id.set(int(context.get("org_id", 0) or 0)),
        "scan_id": _scan_id.set(int(context.get("scan_id", 0) or 0)),
    }
    try:
        yield rid
    finally:
        for var, token in zip((_request_id, _correlation_id, _org_id, _scan_id), tokens.values()):
            var.reset(token)


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
DEFAULT_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0)


@dataclass
class _Counter:
    value: float = 0.0

    def inc(self, amount: float = 1.0) -> None:
        self.value += float(amount)


@dataclass
class _Gauge:
    value: float = 0.0

    def set(self, value: float) -> None:
        self.value = float(value)

    def inc(self, amount: float = 1.0) -> None:
        self.value += float(amount)

    def dec(self, amount: float = 1.0) -> None:
        self.value -= float(amount)


@dataclass
class _Histogram:
    buckets: tuple = DEFAULT_BUCKETS
    counts: List[int] = field(default_factory=lambda: [0] * (len(DEFAULT_BUCKETS) + 1))
    total: float = 0.0
    count: int = 0

    def observe(self, value: float) -> None:
        self.total += float(value)
        self.count += 1
        for index, bound in enumerate(self.buckets):
            if value <= bound:
                self.counts[index] += 1
                return
        self.counts[-1] += 1


class MetricsRegistry:
    """Thread-safe registry rendering the Prometheus text format."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, _Counter] = {}
        self._gauges: Dict[str, _Gauge] = {}
        self._histograms: Dict[str, _Histogram] = {}
        self._help: Dict[str, str] = {}

    def counter(self, name: str, help_text: str = "") -> _Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = _Counter()
                self._help[name] = help_text
            return self._counters[name]

    def gauge(self, name: str, help_text: str = "") -> _Gauge:
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = _Gauge()
                self._help[name] = help_text
            return self._gauges[name]

    def histogram(self, name: str, help_text: str = "", buckets: tuple = DEFAULT_BUCKETS) -> _Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = _Histogram(buckets=buckets,
                                                    counts=[0] * (len(buckets) + 1))
                self._help[name] = help_text
            return self._histograms[name]

    def inc(self, name: str, amount: float = 1.0, help_text: str = "") -> None:
        self.counter(name, help_text).inc(amount)

    def observe(self, name: str, value: float, help_text: str = "") -> None:
        self.histogram(name, help_text).observe(value)

    @contextmanager
    def timer(self, name: str, help_text: str = "") -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.observe(name, time.perf_counter() - started, help_text)

    def render(self) -> str:
        with self._lock:
            lines: List[str] = []
            for name in sorted(self._counters):
                lines.append(f"# HELP {name} {self._help.get(name, '')}".rstrip())
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name} {_format(self._counters[name].value)}")
            for name in sorted(self._gauges):
                lines.append(f"# HELP {name} {self._help.get(name, '')}".rstrip())
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name} {_format(self._gauges[name].value)}")
            for name in sorted(self._histograms):
                histogram = self._histograms[name]
                lines.append(f"# HELP {name} {self._help.get(name, '')}".rstrip())
                lines.append(f"# TYPE {name} histogram")
                cumulative = 0
                for index, bound in enumerate(histogram.buckets):
                    cumulative += histogram.counts[index]
                    lines.append(f'{name}_bucket{{le="{_format(bound)}"}} {cumulative}')
                cumulative += histogram.counts[-1]
                lines.append(f'{name}_bucket{{le="+Inf"}} {cumulative}')
                lines.append(f"{name}_sum {_format(histogram.total)}")
                lines.append(f"{name}_count {histogram.count}")
            return "\n".join(lines) + "\n"

    def snapshot(self) -> Dict[str, float]:
        with self._lock:
            values: Dict[str, float] = {}
            values.update({name: c.value for name, c in self._counters.items()})
            values.update({name: g.value for name, g in self._gauges.items()})
            for name, h in self._histograms.items():
                values[f"{name}_count"] = float(h.count)
                values[f"{name}_sum"] = h.total
            return values


def _format(value: float) -> str:
    if math.isinf(value):
        return "+Inf"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.6g}"


#: Process-wide registry; ``/metrics`` renders it.
registry = MetricsRegistry()

# Metric names used across the product (declared once so dashboards and
# alert rules can rely on them).
SCAN_DURATION = "ironclad_scan_duration_seconds"
SCAN_TOTAL = "ironclad_scans_total"
SCAN_FAILURES = "ironclad_scan_failures_total"
FILES_SCANNED = "ironclad_files_scanned_total"
FINDINGS_TOTAL = "ironclad_findings_total"
QUEUE_DEPTH = "ironclad_queue_depth"
WORKER_DURATION = "ironclad_worker_job_duration_seconds"
API_LATENCY = "ironclad_api_request_duration_seconds"
API_REQUESTS = "ironclad_api_requests_total"
