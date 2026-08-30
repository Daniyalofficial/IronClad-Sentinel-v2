"""Self-scan and scan-target confinement.

Deliberately free of any `server` extra dependency: these two guarantees
must be checked even on a core-only install, which is what CI does.
"""
import os

import pytest

from ironclad.core.paths import TargetError, resolve_target, scan_root
from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.secrets import scan_file_for_secrets


def test_self_scan_is_clean():
    """IronClad scanning itself must stay at zero findings.

    Regression guard for the two precision bugs found by self-scanning:
    rule packs matching their own pattern/message text.
    """
    from ironclad.core.config import IronCladConfig
    from ironclad.core.engine import run_scan

    root = os.path.join(os.path.dirname(__file__), "..", "ironclad")
    result = run_scan(IronCladConfig(target=root))
    assert result.stats.files_scanned > 50
    assert result.findings == [], [(f.rule_id, f.location.file_path, f.location.start_line)
                                   for f in result.findings]


def test_scan_root_defaults_to_the_working_directory(monkeypatch):
    monkeypatch.delenv("IRONCLAD_SCAN_ROOT", raising=False)
    assert scan_root() == os.path.realpath(os.getcwd())


def test_scan_root_honours_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(tmp_path))
    assert scan_root() == str(tmp_path.resolve())


def test_scan_root_confines_targets(tmp_path):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    assert resolve_target(str(root), root=str(root)) == str(root)
    with pytest.raises(TargetError):
        resolve_target(str(outside), root=str(root))
    with pytest.raises(TargetError):
        resolve_target("../outside", root=str(root))


def test_scan_root_rejects_a_symlink_that_escapes(tmp_path):
    """A lexical check would pass here; realpath is what makes it safe."""
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), str(root / "escape"))
    with pytest.raises(TargetError):
        resolve_target("escape", root=str(root))


def test_scan_root_rejects_a_missing_directory(tmp_path):
    with pytest.raises(TargetError):
        resolve_target("does-not-exist", root=str(tmp_path))


def _scan_text(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return DiscoveredFile(path=str(path), rel_path=name, language="python",
                          size_bytes=path.stat().st_size)


def test_permission_constants_are_not_reported_as_credentials(tmp_path):
    """Regression: `TOKEN_MANAGE = "token.manage"` is a permission, not a secret."""
    discovered = _scan_text(tmp_path, "perms.py",
                            'TOKEN_MANAGE = "token.manage"\n'
                            'SCAN_READ = "scan.read"\n'
                            'PROJECT_MANAGE = "project.manage"\n')
    assert scan_file_for_secrets(discovered) == []


def test_real_credential_is_still_reported_alongside_constants(tmp_path):
    discovered = _scan_text(tmp_path, "mixed.py",
                            'SCAN_READ = "scan.read"\n'
                            'api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n')
    findings = scan_file_for_secrets(discovered)
    assert {f.rule_id for f in findings} == {"SECRETS-HIGH-ENTROPY-ASSIGNMENT"}


def test_report_and_sarif_advertise_the_real_tool_version(tmp_path):
    """Reports must name the version actually shipped, not a stale literal.

    A customer ingesting our SARIF into GitHub code scanning records
    ``runs[].tool.driver.version``. If that disagrees with the installed
    package, every finding is attributed to a version that does not exist
    and baseline/CI provenance is wrong.
    """
    from ironclad import __version__
    from ironclad.core.config import IronCladConfig
    from ironclad.core.engine import run_scan
    from ironclad.reporting.sarif import build_sarif

    target = tmp_path / "app"
    target.mkdir()
    (target / "x.py").write_text('import os\nos.system("id")\n')

    result = run_scan(IronCladConfig(target=str(target)))

    assert result.tool_version == __version__, (
        f"ScanResult advertises {result.tool_version!r} but the package is {__version__!r}"
    )
    assert result.to_dict()["tool_version"] == __version__

    doc = build_sarif(result)
    assert doc["runs"][0]["tool"]["driver"]["version"] == __version__
