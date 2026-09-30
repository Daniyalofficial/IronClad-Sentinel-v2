"""A pinned commit is not evidence that its source files were checked out."""
from pathlib import Path
import subprocess

import pytest

from benchmarks import realvuln_probe


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def pinned_target(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs" / "README.md").write_text("Pinned source\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=Benchmark Test", "-c", "user.email=test@example.com",
         "commit", "-q", "-m", "fixture")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_pinned_target_with_deleted_sources_is_not_measured(pinned_target):
    repo, sha = pinned_target
    (repo / "src" / "app.py").unlink()
    assert _git(repo, "rev-parse", "HEAD") == sha  # commit check alone falsely passes
    with pytest.raises(realvuln_probe.ProbeError, match="not clean"):
        realvuln_probe.verify_target_checkout(repo, sha, ["src/app.py"])


def test_pinned_target_with_modified_sources_is_not_measured(pinned_target):
    repo, sha = pinned_target
    (repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
    assert _git(repo, "rev-parse", "HEAD") == sha
    with pytest.raises(realvuln_probe.ProbeError, match="not clean"):
        realvuln_probe.verify_target_checkout(repo, sha, ["src/app.py"])


def test_sparse_checkout_missing_labeled_source_is_not_measured(pinned_target):
    repo, sha = pinned_target
    _git(repo, "sparse-checkout", "set", "docs")
    assert _git(repo, "status", "--porcelain") == ""
    assert not (repo / "src" / "app.py").exists()
    with pytest.raises(realvuln_probe.ProbeError, match="missing.*src/app.py"):
        realvuln_probe.verify_target_checkout(repo, sha, ["src/app.py"])


def test_clean_pinned_target_is_measured(pinned_target):
    repo, sha = pinned_target
    realvuln_probe.verify_target_checkout(repo, sha, ["src/app.py"])
