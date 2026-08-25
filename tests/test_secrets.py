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
    d = _discovered_for('api_secret_key = "aZ9x8Qm2LpRk4VtNb8Ws1EoYc3Fg6Hj"\n')
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


def test_flags_pem_private_key_header():
    d = _discovered_for("-----BEGIN PRIVATE KEY-----\nMIIE...not-a-real-key...\n-----END PRIVATE KEY-----\n")
    try:
        findings = scan_file_for_secrets(d)
        assert any(f.rule_id == "SECRETS-PEM-PRIVATE-KEY" for f in findings)
        finding = next(f for f in findings if f.rule_id == "SECRETS-PEM-PRIVATE-KEY")
        assert finding.confidence == "high"
        assert finding.cwe == "CWE-321"
    finally:
        os.unlink(d.path)


def test_ignores_hash_and_uuid_values():
    d = _discovered_for(
        'secret_token = "0123456789abcdef0123456789abcdef"\n'
        'api_key = "550e8400-e29b-41d4-a716-446655440000"\n'
    )
    try:
        findings = scan_file_for_secrets(d)
        assert findings == []
    finally:
        os.unlink(d.path)
