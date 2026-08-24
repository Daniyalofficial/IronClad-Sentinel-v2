from pathlib import Path

from ironclad.core.config import IronCladConfig
from ironclad.core.walker import discover
from ironclad.core.engine import run_scan

ROOT = Path(__file__).parent / "security_corpus"

def test_ignore_paths_really_excludes_files(tmp_path):
    (tmp_path / "keep.py").write_text("x = 1\n")
    (tmp_path / "ignored.py").write_text("x = 2\n")
    cfg = IronCladConfig(target=str(tmp_path), ignore_paths=["ignored.py"])
    files = discover(cfg)
    assert [f.rel_path for f in files.files] == ["keep.py"]

def test_include_globs_really_limits_files(tmp_path):
    (tmp_path / "a.py").write_text("x = 1;\n")
    (tmp_path / "b.js").write_text("const x = 1;\n")
    cfg = IronCladConfig(target=str(tmp_path), include_globs=["*.py"])
    files = discover(cfg)
    assert [f.rel_path for f in files.files] == ["a.py"]

def test_line_statistics_are_populated():
    cfg = IronCladConfig(target=str(ROOT), enabled_engines=["ast-python", "secrets", "rule-engine"])
    result = run_scan(cfg)
    assert result.stats.lines_scanned > 0
    assert result.stats.files_scanned >= 4
