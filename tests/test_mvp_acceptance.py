"""Acceptance gate for the shippable product surface.

This module *is* collected by pytest (it is named ``test_*.py``). It used
to live at ``tests/mvp_acceptance.py``, which pytest never collects under
its default ``python_files`` pattern -- meaning the gate silently reported
nothing while CI stayed green. It is kept strict on purpose: every entry
below must exist in the repository for a customer install to work.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "ironclad/cli.py",
    "ironclad/scanners/sbom.py",
    "ironclad/scanners/dependency.py",
    "ironclad/data/vuln_db.json",
    "ironclad/data/license_db.json",
    "integrations/github-actions/ironclad-scan.yml",
    "integrations/gitlab-ci/.gitlab-ci.yml",
    "integrations/pre-commit/pre-commit-hook.sh",
    "scripts/build_release.sh",
    "scripts/customer_install.sh",
]


@pytest.mark.parametrize("rel_path", REQUIRED)
def test_mvp_distribution_surface_exists(rel_path):
    assert (ROOT / rel_path).exists(), f"missing distribution surface: {rel_path}"


def test_no_placeholder_markers_in_core_tree():
    bad = []
    for path in (ROOT / "ironclad").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in ("TODO", "FIXME", "XXX:", "NotImplementedError"):
            if marker in text:
                bad.append(f"{path.relative_to(ROOT)}: {marker}")
    assert not bad, f"placeholder markers remain in core: {bad}"
