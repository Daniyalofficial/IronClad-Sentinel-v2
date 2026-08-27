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


def test_low_entropy_literal_is_not_an_entropy_finding_but_is_a_credential():
    """A weak literal is below the entropy bar but is still a committed secret.

    This used to be a blind spot: an entropy-only detector reported nothing
    for `secret_token = "helloworldhelloworld"`, which is exactly the kind of
    credential an operator needs to hear about.
    """
    d = _discovered_for('secret_token = "helloworldhelloworld"\n')
    try:
        findings = scan_file_for_secrets(d)
        rule_ids = {f.rule_id for f in findings}
        assert "SECRETS-HIGH-ENTROPY-ASSIGNMENT" not in rule_ids
        assert "SECRETS-HARDCODED-CREDENTIAL" in rule_ids
    finally:
        os.unlink(d.path)


def test_credential_rule_ignores_environment_lookups():
    d = _discovered_for('import os\napi_secret_key = os.environ["API_SECRET_KEY"]\n')
    try:
        assert scan_file_for_secrets(d) == []
    finally:
        os.unlink(d.path)


def test_credential_rule_ignores_a_value_that_is_just_the_field_name():
    d = _discovered_for('PASSWORD_FIELD = "password"\n')
    try:
        assert scan_file_for_secrets(d) == []
    finally:
        os.unlink(d.path)


def test_credential_finding_never_echoes_the_secret():
    d = _discovered_for('db_password = "Tr0ubador-Horse-9911"\n')
    try:
        findings = scan_file_for_secrets(d)
        assert findings, "a hardcoded db password must be reported"
        blob = " ".join(f.location.snippet + f.description + str(f.extra) for f in findings)
        assert "Tr0ubador-Horse-9911" not in blob, "the secret itself must never be emitted"
        assert "Tr" in findings[0].location.snippet  # redacted prefix is kept
    finally:
        os.unlink(d.path)


def test_one_finding_per_credential_not_two():
    d = _discovered_for('api_secret_key = "aZ9xQm2LpRk4VtNb8Ws1EoYc3Fg6Hj"\n')
    try:
        findings = scan_file_for_secrets(d)
        assert len(findings) == 1, [f.rule_id for f in findings]
        assert findings[0].rule_id == "SECRETS-HIGH-ENTROPY-ASSIGNMENT"
    finally:
        os.unlink(d.path)
