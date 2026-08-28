import pytest

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


@pytest.mark.parametrize("length,label", [(32, "md5"), (40, "sha1"), (64, "sha256")])
def test_hex_digests_are_not_reported_as_credentials(length, label):
    """A pinned digest is not a secret, even in a credential-named variable.

    Regression: the sha256 length (64) was missing from the exclusion list,
    so `api_token = "<sha256>"` was reported as a hardcoded credential.
    """
    digest = ("a1b2c3d4" * 8)[:length]
    d = _discovered_for(f'api_token = "{digest}"\n')
    try:
        assert scan_file_for_secrets(d) == [], f"{label}-length hex should not be reported"
    finally:
        os.unlink(d.path)


def test_a_real_token_of_the_same_length_is_still_reported():
    """The exclusion is shape-based, not length-based."""
    token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5eUqR7cXnB4vM2tY8wE6sA0dG9"  # 56 chars, not hex
    d = _discovered_for(f'api_token = "{token}"\n')
    try:
        findings = scan_file_for_secrets(d)
        assert findings, "a non-hex token must still be reported"
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


def test_placeholder_conventions_are_not_reported_as_credentials(tmp_path):
    """REPLACE_ME / CHANGE_ME / your_secret are placeholders, not leaks.

    Found by scanning this repository: deploy/k8s/20-secret.yaml is a
    documented template whose value is `REPLACE_ME_WITH_32_PLUS_CHARS`, and
    it was reported as a hardcoded credential.
    """
    path = tmp_path / "template.yaml"
    path.write_text(
        'IRONCLAD_SIGNING_KEY: "REPLACE_ME_WITH_32_PLUS_CHARS"\n'
        'DB_PASSWORD: "CHANGE_ME"\n'
        'api_token: "your_secret_here"\n',
        encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="template.yaml", language="other",
                       size_bytes=path.stat().st_size)
    assert scan_file_for_secrets(d) == []


def test_a_real_secret_is_still_reported_next_to_placeholders(tmp_path):
    path = tmp_path / "mixed.py"
    path.write_text(
        'SIGNING_KEY = "REPLACE_ME_WITH_32_PLUS_CHARS"\n'
        'API_TOKEN = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n',
        encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="mixed.py", language="python",
                       size_bytes=path.stat().st_size)
    findings = scan_file_for_secrets(d)
    assert findings, "the real secret must still be reported"
    assert all("REPLACE_ME" not in f.location.snippet for f in findings)


def test_bare_url_assigned_to_a_credential_name_is_not_a_secret(tmp_path):
    """A URL is configuration, not a credential.

    Found on real code: rubygems/lib/rubygems/s3_uri_signer.rb sets
    `EC2_IAM_TOKEN = "http://169.254.169.254/..."`, which is the EC2
    metadata endpoint, not a secret.
    """
    path = tmp_path / "signer.rb"
    path.write_text('EC2_IAM_TOKEN = "http://169.254.169.254/latest/api/token"\n', encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="signer.rb", language="ruby",
                       size_bytes=path.stat().st_size)
    assert scan_file_for_secrets(d) == []


def test_url_with_embedded_credentials_is_still_reported(tmp_path):
    """The exclusion is for *bare* URLs; user:pass@host must still fire."""
    from ironclad.scanners.secrets import _is_bare_url

    assert _is_bare_url("https://example.com/path") is True
    assert _is_bare_url("https://user:pass@host/db") is False
    assert _is_bare_url("postgres://user:pass@host/db") is False
    assert _is_bare_url("Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e") is False


def test_comment_lines_do_not_trigger_rules(tmp_path):
    """Whole-line comments are prose, not code.

    Found on real code: rubygems/lib/rubygems/specification.rb matched
    RUBY-YAML-LOAD inside the comment
    "# +input+ can be anything that YAML.load() accepts".
    """
    import os

    import ironclad
    from ironclad.rules.schema import load_rule_packs
    from ironclad.scanners.rule_engine import scan_file_with_rules

    path = tmp_path / "spec.rb"
    path.write_text(
        "# +input+ can be anything that YAML.load() accepts: String or IO.\n"
        "def load(input)\n"
        "  parser.parse(input)\n"
        "end\n",
        encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="spec.rb", language="ruby",
                       size_bytes=path.stat().st_size)
    rules = load_rule_packs([os.path.join(os.path.dirname(ironclad.__file__), "rules", "packs")])
    fired = {f.rule_id for f in scan_file_with_rules(d, rules)}
    assert "RUBY-YAML-LOAD" not in fired


def test_live_yaml_load_outside_a_comment_is_still_reported(tmp_path):
    import os

    import ironclad
    from ironclad.rules.schema import load_rule_packs
    from ironclad.scanners.rule_engine import scan_file_with_rules

    path = tmp_path / "live.rb"
    path.write_text("def load(input)\n  YAML.load(input)\nend\n", encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="live.rb", language="ruby",
                       size_bytes=path.stat().st_size)
    rules = load_rule_packs([os.path.join(os.path.dirname(ironclad.__file__), "rules", "packs")])
    assert "RUBY-YAML-LOAD" in {f.rule_id for f in scan_file_with_rules(d, rules)}


def test_your_x_fill_in_placeholders_are_not_reported(tmp_path):
    """The `your<X>` convention is a fill-in marker, not a leak.

    Found on real code: PHPMailer ships examples/gmail.phps and friends with
    `$mail->Password = 'yourpassword'`. Six of PHPMailer's nine findings were
    this one class.
    """
    path = tmp_path / "gmail.php"
    path.write_text(
        "$mail->Password = 'yourpassword';\n"
        "$clientSecret = 'yourClientId';\n"
        "$user = 'youremail@gmail.com';\n",
        encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="gmail.php", language="php",
                       size_bytes=path.stat().st_size)
    assert scan_file_for_secrets(d) == []


def test_credential_shaped_literal_is_still_reported_next_to_fill_ins(tmp_path):
    path = tmp_path / "mixed.php"
    path.write_text(
        "$mail->Password = 'yourpassword';\n"
        "$api_secret = 'Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e';\n",
        encoding="utf-8")
    d = DiscoveredFile(path=str(path), rel_path="mixed.php", language="php",
                       size_bytes=path.stat().st_size)
    findings = scan_file_for_secrets(d)
    assert findings, "the real secret must still be reported"
    assert all("yourpassword" not in f.location.snippet for f in findings)
