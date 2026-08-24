from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.secrets import scan_file_for_secrets, shannon_entropy
import os
import tempfile


def _discovered_for(content: str, suffix=".py"):
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return DiscoveredFile(path=fh.name, rel_path=os.path.basename(fh.name), language="python", size_bytes=len(content))


def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_random_string_is_high():
    assert shannon_entropy("aZ9x8Qm2Lp7Rk4Vt") > 3.0


def test_flags_high_entropy_secret_assignment():
    d = _discovered_for('api_secret_key = "aZ9xQm2LpRk4VtNb8Ws1EoYc3Fg6Hj"\n')
    try:
        findings = scan_file_for_secrets(d)
        assert any(f.rule_id == "SECRETS-HIGH-ENTROPY-ASSIGNMENT" for f in findings)
    finally:
        os.unlink(d.path)


def test_ignores_placeholder_values():
    d = _discovered_for('api_secret_key = "changeme_placeholder_value"\n')
    try:
        findings = scan_file_for_secrets(d)
        assert findings == []
    finally:
        os.unlink(d.path)


def test_ignores_low_entropy_words():
    d = _discovered_for('secret_token = "helloworldhelloworld"\n')
    try:
        findings = scan_file_for_secrets(d)
        assert findings == []
    finally:
        os.unlink(d.path)
