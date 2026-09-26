"""Regression tests for untrusted filesystem entries in scan targets.

The potentially blocking reads run in a child process: a regression must
fail on a short timeout rather than hanging the entire test runner/worker.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest


_SECRET_ASSIGNMENT = 'api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n'


def _child(script: str, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script), *(str(arg) for arg in args)],
        text=True, capture_output=True, timeout=6, check=True,
    )
    return result.stdout.strip()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes required")
def test_scanning_a_named_pipe_finishes_and_skips_it(tmp_path):
    (tmp_path / "safe.py").write_text("value = 1\n", encoding="utf-8")
    os.mkfifo(tmp_path / "blocked.py")

    output = _child("""
        import json, sys
        from ironclad.core.config import IronCladConfig
        from ironclad.core.engine import run_scan
        result = run_scan(IronCladConfig(target=sys.argv[1]))
        print(json.dumps([result.stats.files_scanned, result.stats.files_skipped]))
    """, tmp_path)
    assert json.loads(output) == [1, 1]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes required")
def test_direct_text_reader_never_waits_on_a_named_pipe(tmp_path):
    fifo = tmp_path / "blocked.py"
    os.mkfifo(fifo)
    assert _child("""
        import sys
        from ironclad.core.walker import read_text_safely
        assert read_text_safely(sys.argv[1]) == ""
        print("safe")
    """, fifo) == "safe"


def test_scan_cannot_read_a_file_symlinked_outside_its_root(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "safe.py").write_text("value = 1\n", encoding="utf-8")
    private = tmp_path / "private.py"
    private.write_text(_SECRET_ASSIGNMENT, encoding="utf-8")
    (allowed / "linked.py").symlink_to(private)

    output = _child("""
        import json, sys
        from ironclad.core.config import IronCladConfig
        from ironclad.core.engine import run_scan
        result = run_scan(IronCladConfig(target=sys.argv[1], enabled_engines=["secrets"]))
        print(json.dumps([result.stats.files_scanned, result.stats.files_skipped,
                          [f.rule_id for f in result.findings]]))
    """, allowed)
    assert json.loads(output) == [1, 1, []]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes required")
def test_replacing_a_discovered_file_with_fifo_does_not_block(tmp_path):
    source = tmp_path / "changing.py"
    source.write_text("value = 1\n", encoding="utf-8")
    output = _child("""
        import json, os, sys
        from ironclad.core import engine
        from ironclad.core.config import IronCladConfig
        original = engine.discover
        def swap(config):
            fileset = original(config)
            os.unlink(sys.argv[2])
            os.mkfifo(sys.argv[2])
            return fileset
        engine.discover = swap
        result = engine.run_scan(IronCladConfig(target=sys.argv[1]))
        print(json.dumps([f.rule_id for f in result.findings]))
    """, tmp_path, source)
    assert json.loads(output) == []


def test_replacing_a_discovered_file_with_external_symlink_is_not_read(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = allowed / "changing.py"
    source.write_text("value = 1\n", encoding="utf-8")
    private = tmp_path / "private.py"
    private.write_text(_SECRET_ASSIGNMENT, encoding="utf-8")
    output = _child("""
        import json, os, sys
        from ironclad.core import engine
        from ironclad.core.config import IronCladConfig
        original = engine.discover
        def swap(config):
            fileset = original(config)
            os.unlink(sys.argv[2])
            os.symlink(sys.argv[3], sys.argv[2])
            return fileset
        engine.discover = swap
        result = engine.run_scan(IronCladConfig(target=sys.argv[1], enabled_engines=["secrets"]))
        print(json.dumps([f.rule_id for f in result.findings]))
    """, allowed, source, private)
    assert json.loads(output) == []
