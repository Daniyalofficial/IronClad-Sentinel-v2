import os
import tempfile

from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.dependency import (
    _satisfies_affected_range,
    parse_package_lock,
    parse_package_json,
    parse_requirements_txt,
    scan_dependencies,
)


def _manifest(filename: str, content: str):
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return DiscoveredFile(path=path, rel_path=filename, language="other",
                          size_bytes=len(content), is_dependency_manifest=True)


def test_compound_advisory_range():
    assert _satisfies_affected_range("2.5.0", ">=2.0.0, <3.0.0")
    assert not _satisfies_affected_range("3.0.0", ">=2.0.0, <3.0.0")


def test_requirements_range_keeps_declared_spec():
    deps = parse_requirements_txt(_manifest("requirements.txt", "requests>=2.20,<2.31\n"))
    assert deps[0].version == "2.20"
    assert deps[0].declared_spec == ">=2.20,<2.31"


def test_npm_range_is_checked_conservatively():
    deps = parse_package_json(_manifest("package.json", '{"dependencies":{"lodash":"^4.17.11"}}'))
    assert deps[0].version == "4.17.11"
    findings = scan_dependencies([_manifest("package.json", '{"dependencies":{"lodash":"^4.17.11"}}')])
    assert any(f.extra.get("package") == "lodash" for f in findings)


def test_package_lock_v3_is_scanned():
    lock = _manifest("package-lock.json", '{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/lodash":{"version":"4.17.11"}}}')
    deps = parse_package_lock(lock)
    assert any(d.name == "lodash" and d.version == "4.17.11" for d in deps)
    findings = scan_dependencies([lock])
    assert any(f.extra.get("package") == "lodash" for f in findings)


def test_patched_lockfile_is_clean():
    lock = _manifest("package-lock.json", '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}')
    assert scan_dependencies([lock]) == []
