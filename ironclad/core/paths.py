"""Scan-target path confinement.

This lives in `core` rather than `platform` on purpose: confining a scan
target to a permitted root is a scanner concern, and it must be available
without pulling in the database stack. The CLI uses it directly.

`POST /scan` accepts a path from a remote caller. Without this, that
endpoint is an arbitrary file-read primitive.
"""
from __future__ import annotations

import os
from typing import Optional

SCAN_ROOT_ENV = "IRONCLAD_SCAN_ROOT"


class TargetError(ValueError):
    """Raised when a requested scan target is outside the permitted root."""


def scan_root() -> str:
    """The directory scans are confined to (env override, else cwd)."""
    return os.path.realpath(os.environ.get(SCAN_ROOT_ENV) or os.getcwd())


def resolve_target(target: str, root: Optional[str] = None) -> str:
    """Resolve and confine a scan target inside the scan root.

    Rejects absolute paths outside the root, ``..`` traversal that escapes
    it, and symlinks that resolve outside it. ``realpath`` is what makes the
    symlink case safe: a symlink inside the root pointing outside it would
    otherwise pass a purely lexical check.
    """
    allowed_root = os.path.realpath(root or scan_root())
    candidate = target if os.path.isabs(target) else os.path.join(allowed_root, target)
    resolved = os.path.realpath(candidate)
    if resolved != allowed_root and not resolved.startswith(allowed_root + os.sep):
        raise TargetError(
            f"scan target {target!r} resolves outside the permitted scan root {allowed_root!r}"
        )
    if not os.path.isdir(resolved):
        raise TargetError(f"scan target is not a directory: {target!r}")
    return resolved
