"""IronClad Sentinel platform layer.

This package holds everything that turns the scanning engine into a
multi-tenant product: persistent storage, authentication, authorization,
tenant isolation, jobs, events, audit and observability.

It is imported lazily by the CLI so that ``ironclad scan`` keeps working
with only the core dependencies installed; the API/dashboard entry points
require the ``server`` extra (FastAPI, SQLAlchemy, uvicorn).
"""
from __future__ import annotations

__all__ = ["database", "models", "security", "rbac", "tenancy", "audit", "events", "jobs"]
