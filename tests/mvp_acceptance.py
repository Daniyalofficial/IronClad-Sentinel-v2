"""Small, dependency-free acceptance checks for the practical MVP contract."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "ironclad/cli.py",
    "ironclad/scanners/sbom.py",
    "ironclad/scanners/dependencies.py",
    "ironclad/data/vuln_db.json",
    "ironclad/data/license_db.json",
    "integrations/github-actions/ironclad-scan.yml",
    "integrations/gitlab-ci/.gitlab-ci.yml",
    "integrations/pre-commit/pre-commit-hook.sh",
    "scripts/build_release.sh",
    "scripts/customer_install.sh",
]


def test_mvp_distribution_surface_exists():
    missing = [p for p in REQUIRED if not (ROOT / p).exists()]
    assert not missing, f"missing MVP distribution surfaces: {missing}"


def test_no_placeholder_markers_in_core_tree():
    bad = []
    for path in (ROOT / "ironclad").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "TODO" in text or "FIXME" in text:
            bad.append(str(path.relative_to(ROOT)))
    assert not bad, f"placeholder markers remain in core: {bad}"
