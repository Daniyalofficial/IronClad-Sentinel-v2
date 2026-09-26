"""The local verifier must not count self-skipped benchmarks as measurements."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("bash") is None, reason="verifier requires bash")
def test_verifier_distinguishes_explicit_skip_pass_and_failure():
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "verify_all.sh").read_text(encoding="utf-8")

    def definition(name: str) -> str:
        start = script.index(f"{name}() {{")
        end = script.index("\n}\n", start) + 2
        return script[start:end]

    probe = "\n".join((
        "PASS=0; FAIL=0; SKIP=0; RESULTS=()",
        definition("record"),
        definition("step"),
        "step 'network corpus' bash -c 'printf \"# header\\nSKIP: network unavailable\\n\"'",
        "step 'measured corpus' bash -c 'printf \"measured 12 findings\\n\"'",
        "step 'broken corpus' bash -c 'echo error; exit 7'",
        "printf 'COUNTS=%s:%s:%s\\n' \"$PASS\" \"$FAIL\" \"$SKIP\"",
        "printf 'FIRST=%s\\n' \"${RESULTS[0]}\"",
    ))
    result = subprocess.run(["bash", "-c", probe], cwd=root, check=True,
                            text=True, capture_output=True, timeout=10)
    assert "COUNTS=1:1:1" in result.stdout
    assert "FIRST=SKIP|network corpus|network unavailable" in result.stdout
