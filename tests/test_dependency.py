import os
import tempfile

from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.dependency import scan_dependencies, _version_less_than, _satisfies_affected_range


def _manifest(filename: str, content: str):
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, filename)
    with open(path, "w") as fh:
        fh.write(content)
    return DiscoveredFile(path=path, rel_path=filename, language="other", size_bytes=len(content), is_dependency_manifest=True)


def test_version_less_than():
    assert _version_less_than("1.2.3", "1.2.4")
    assert not _version_less_than("1.2.4", "1.2.3")
    assert not _version_less_than("1.2.3", "1.2.3")


def test_satisfies_affected_range():
    assert _satisfies_affected_range("2.28.0", "<2.31.0")
    assert not _satisfies_affected_range("2.31.0", "<2.31.0")


def test_flags_vulnerable_pyyaml_pinned_version():
    m = _manifest("requirements.txt", "pyyaml==5.3\n")
    findings = scan_dependencies([m])
    assert any("pyyaml" in f.extra.get("package", "") for f in findings)


def test_no_findings_for_patched_version():
    m = _manifest("requirements.txt", "pyyaml==6.0.1\n")
    findings = scan_dependencies([m])
    assert findings == []


def test_flags_vulnerable_npm_lodash():
    m = _manifest("package.json", '{"dependencies": {"lodash": "4.17.11"}}')
    findings = scan_dependencies([m])
    assert any(f.extra.get("package") == "lodash" for f in findings)
