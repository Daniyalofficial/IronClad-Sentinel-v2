from pathlib import Path

from ironclad.scanners.python_security_supplement import scan_python_path_traversal


def test_path_traversal_fixture_is_detected():
    fixture = Path("tests/security_corpus/taint/path_traversal.py")
    findings = scan_python_path_traversal(str(fixture), str(fixture))
    assert any(f.rule_id == "PY-AST-PATH-TRAVERSAL" for f in findings)


def test_safe_path_fixture_is_not_reported_when_used_alone(tmp_path):
    source = """
from pathlib import Path

def safe(base, user_path):
    root = Path(base).resolve()
    candidate = (root / user_path).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError('path escapes root')
    return candidate.read_text()
"""
    target = tmp_path / "safe.py"
    target.write_text(source, encoding="utf-8")
    findings = scan_python_path_traversal(str(target), "safe.py")
    assert findings == []
