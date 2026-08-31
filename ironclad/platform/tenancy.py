"""Organization isolation.

Every row the product stores belongs to an organization. This module is the
single supported way to start a query, and it exists so that "forgot the
org filter" is a code-review-visible omission rather than a silent
cross-tenant read.

Rules enforced here:

* :func:`org_query` refuses a model that has no ``org_id`` column, so a new
  tenant-owned table cannot be queried unscoped by accident.
* :func:`get_for_org` returns ``None`` (not another tenant's row) when the
  id belongs to a different organization -- the API turns that into a 404,
  never a 403, so object existence is not leaked across tenants.
* :func:`assert_same_org` is the guard for multi-object operations.
"""
from __future__ import annotations

from typing import Any, List, Optional, Sequence, Type, TypeVar

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from ironclad.platform.rbac import Principal

ModelT = TypeVar("ModelT")


class TenantError(RuntimeError):
    """Raised when an operation would cross an organization boundary."""


def _require_org_column(model: Type[Any]) -> None:
    if not hasattr(model, "org_id"):
        raise TenantError(
            f"{model.__name__} has no org_id column; it cannot be safely queried per tenant. "
            f"Add org_id in a migration or query it through an already-scoped parent."
        )


def org_query(session: Session, model: Type[ModelT], org_id: int) -> Select:
    """Start a tenant-scoped select. This is the only supported entry point."""
    _require_org_column(model)
    if not org_id:
        raise TenantError("org_id is required for every tenant-scoped query")
    return select(model).where(model.org_id == org_id)


def get_for_org(session: Session, model: Type[ModelT], org_id: int, object_id: int) -> Optional[ModelT]:
    """Fetch one row by primary key, scoped to an organization."""
    _require_org_column(model)
    return session.execute(
        select(model).where(model.org_id == org_id, model.id == object_id)
    ).scalar_one_or_none()


def list_for_org(session: Session, model: Type[ModelT], org_id: int,
                 order_by: Optional[Any] = None, limit: Optional[int] = None,
                 offset: int = 0, **filters: Any) -> List[ModelT]:
    """List rows for one organization with optional ordering and paging."""
    statement = org_query(session, model, org_id)
    for column, value in filters.items():
        if not hasattr(model, column):
            raise TenantError(f"{model.__name__} has no column '{column}'")
        statement = statement.where(getattr(model, column) == value)
    if order_by is not None:
        statement = statement.order_by(order_by)
    if limit is not None:
        statement = statement.limit(max(0, min(int(limit), 500)))
    if offset:
        statement = statement.offset(max(0, int(offset)))
    return list(session.execute(statement).scalars().all())


def assert_same_org(principal: Principal, *rows: Any) -> None:
    """Assert every object belongs to the principal's organization."""
    for row in rows:
        if row is None:
            continue
        row_org = getattr(row, "org_id", None)
        if row_org is None:
            raise TenantError(f"{type(row).__name__} is not tenant-scoped")
        if row_org != principal.org_id:
            raise TenantError(
                f"{type(row).__name__} #{getattr(row, 'id', '?')} belongs to organization "
                f"{row_org}, not {principal.org_id}"
            )


def require_row(session: Session, model: Type[ModelT], principal: Principal, object_id: int) -> ModelT:
    """Fetch a row for the principal's organization or raise :class:`TenantError`.

    Callers convert this into a 404 -- deliberately identical to the
    "does not exist" response so tenants cannot probe for object ids.
    """
    row = get_for_org(session, model, principal.org_id, object_id)
    if row is None:
        raise TenantError(f"{model.__name__} {object_id} not found")
    return row


def scoped_ids(rows: Sequence[Any], org_id: int) -> List[int]:
    """Defensive filter used before bulk operations on id lists."""
    return [row.id for row in rows if getattr(row, "org_id", None) == org_id]
