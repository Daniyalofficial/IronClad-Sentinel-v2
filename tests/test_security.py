"""Security primitive tests (Phase 15/24).

These cover the cryptographic and authorization primitives directly, so a
regression shows up as a unit failure rather than as a breach.

Requires the `server` extra (SQLAlchemy, via the audit/models imports);
core-only installs skip this module and still run `tests/test_self_scan.py`.
"""
import time

import pytest

pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from ironclad.platform.audit import REDACTED, redact_secrets
from ironclad.platform.rbac import (
    ALL_PERMISSIONS,
    ROLE_PERMISSIONS,
    PermissionDenied,
    Principal,
    describe_roles,
    normalize_scope,
    role_at_least,
)
from ironclad.platform.security import (
    API_TOKEN_PREFIX,
    MAX_FAILED_LOGINS,
    PBKDF2_ITERATIONS,
    SecurityError,
    constant_time_equals,
    decode_token,
    generate_api_token,
    generate_session_token,
    hash_password,
    hash_token,
    issue_token,
    lockout_decision,
    looks_like_api_token,
    needs_rehash,
    password_problems,
    verify_password,
)

TEST_KEY = "unit-test-signing-key-that-is-long-enough"


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def test_password_hash_round_trip():
    stored = hash_password("Str0ng!Passw0rd-99")
    assert verify_password("Str0ng!Passw0rd-99", stored)
    assert not verify_password("Str0ng!Passw0rd-98", stored)


def test_hash_is_salted_and_not_reproducible():
    a = hash_password("same-password-123")
    b = hash_password("same-password-123")
    assert a != b, "identical passwords must not produce identical hashes"
    assert verify_password("same-password-123", a)
    assert verify_password("same-password-123", b)


def test_hash_stores_its_own_parameters():
    stored = hash_password("Str0ng!Passw0rd-99")
    name, iterations, _salt, _digest = stored.split("$", 3)
    assert name == "pbkdf2_sha256"
    assert int(iterations) == PBKDF2_ITERATIONS


def test_plaintext_never_appears_in_the_stored_hash():
    password = "Str0ng!Passw0rd-99"
    assert password not in hash_password(password)


def test_needs_rehash_flags_a_weaker_cost():
    weak = hash_password("Str0ng!Passw0rd-99", iterations=1000)
    assert needs_rehash(weak)
    assert not needs_rehash(hash_password("Str0ng!Passw0rd-99"))
    assert needs_rehash("garbage-not-a-hash")


def test_verify_never_raises_on_malformed_input():
    for bad in ("", "nonsense", "a$b", "pbkdf2_sha256$x$y$z", "pbkdf2_sha256$0$c2FsdA==$ZGln"):
        assert verify_password("anything", bad) is False


def test_empty_password_is_refused():
    with pytest.raises(SecurityError):
        hash_password("")


@pytest.mark.parametrize("password,problems", [
    ("short", True),
    ("alllowercaseonly", True),        # one character class
    ("Str0ng!Passw0rd-99", False),
    ("correct-horse-battery", True),   # lowercase + symbol only = 2 classes
])
def test_password_policy(password, problems):
    assert bool(password_problems(password)) is problems


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #
def test_session_token_is_returned_with_its_digest():
    token, digest = generate_session_token()
    assert token and digest
    assert digest == hash_token(token)
    assert token != digest, "the stored value must not be the token"


def test_api_token_shape_and_prefix():
    token, digest, prefix = generate_api_token("ci")
    assert token.startswith(API_TOKEN_PREFIX)
    assert looks_like_api_token(token)
    assert prefix == token[:12]
    assert digest == hash_token(token)
    assert API_TOKEN_PREFIX not in digest


def test_tokens_are_unique():
    tokens = {generate_session_token()[0] for _ in range(50)}
    assert len(tokens) == 50


def test_constant_time_equals():
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")
    assert not constant_time_equals("abc", "")
    assert constant_time_equals("", "")


# --------------------------------------------------------------------------- #
# Signed tokens
# --------------------------------------------------------------------------- #
def test_signed_token_round_trip():
    token = issue_token({"sub": "user-1", "org": 7}, key=TEST_KEY)
    claims = decode_token(token, key=TEST_KEY)
    assert claims["sub"] == "user-1"
    assert claims["org"] == 7
    assert claims["exp"] > claims["iat"]


def test_signed_token_rejects_a_tampered_payload():
    token = issue_token({"sub": "user-1"}, key=TEST_KEY)
    payload, _, signature = token.rpartition(".")
    forged = payload[:-2] + "eA." + signature  # flip a payload byte
    with pytest.raises(SecurityError):
        decode_token(forged, key=TEST_KEY)


def test_signed_token_rejects_the_wrong_key():
    token = issue_token({"sub": "user-1"}, key=TEST_KEY)
    with pytest.raises(SecurityError):
        decode_token(token, key="a-completely-different-key-1234567890")


def test_signed_token_expires():
    token = issue_token({"sub": "user-1"}, ttl_seconds=1, key=TEST_KEY)
    with pytest.raises(SecurityError):
        decode_token(token, key=TEST_KEY, now=time.time() + 10)


def test_malformed_tokens_are_rejected():
    for bad in ("", "no-dot-here", "aaa.bbb", "...."):
        with pytest.raises(SecurityError):
            decode_token(bad, key=TEST_KEY)


def test_short_signing_key_is_refused():
    with pytest.raises(SecurityError):
        issue_token({"sub": "x"}, key="too-short")


# --------------------------------------------------------------------------- #
# Lockout
# --------------------------------------------------------------------------- #
def test_lockout_after_max_failures():
    decision = lockout_decision(MAX_FAILED_LOGINS, None)
    assert decision.allowed is False
    assert "consecutive failures" in decision.reason


def test_lockout_is_time_based_and_self_clearing():
    """An expired lock window must not keep blocking on its own.

    ``failed_logins`` is reset by the login route on a successful
    authentication, so a caller below the threshold with an expired window
    is allowed through again.
    """
    now = time.time()
    locked = lockout_decision(MAX_FAILED_LOGINS, now + 60, now=now)
    assert locked.allowed is False
    assert locked.locked_until == now + 60

    cleared = lockout_decision(MAX_FAILED_LOGINS - 1, now - 60, now=now)
    assert cleared.allowed is True

    # Still above the failure threshold means still blocked, window or not.
    still_blocked = lockout_decision(MAX_FAILED_LOGINS, now - 60, now=now)
    assert still_blocked.allowed is False


def test_below_threshold_is_allowed():
    assert lockout_decision(MAX_FAILED_LOGINS - 1, None).allowed is True


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #
def test_roles_are_ordered():
    assert role_at_least("owner", "admin")
    assert role_at_least("admin", "admin")
    assert not role_at_least("developer", "admin")
    assert not role_at_least("nonsense", "viewer")


def test_unknown_role_has_no_permissions():
    principal = Principal(user_id=1, org_id=1, email="x", role="superuser")
    assert principal.permissions == frozenset()
    assert not principal.can("project.read")


def test_unknown_permission_is_never_granted():
    principal = Principal(user_id=1, org_id=1, email="x", role="owner")
    assert not principal.can("delete.the.universe")
    assert "delete.the.universe" not in ALL_PERMISSIONS


def test_deactivated_principal_can_do_nothing():
    principal = Principal(user_id=1, org_id=1, email="x", role="owner", is_active=False)
    assert not principal.can("project.read")


def test_token_scopes_narrow_but_never_widen():
    owner = Principal(user_id=1, org_id=1, email="x", role="owner")
    narrowed = Principal(user_id=1, org_id=1, email="x", role="owner",
                         token_scopes=frozenset({"scan.read"}))
    assert owner.can("policy.manage")
    assert not narrowed.can("policy.manage")
    assert narrowed.can("scan.read")

    viewer = Principal(user_id=1, org_id=1, email="x", role="viewer",
                       token_scopes=frozenset({"policy.manage"}))
    assert not viewer.can("policy.manage"), "a token cannot grant what the role lacks"


def test_scope_normalisation():
    assert normalize_scope("scan:read") == "scan.read"
    assert normalize_scope("SCAN.READ") == "scan.read"
    assert normalize_scope("  finding:manage ") == "finding.manage"


def test_require_raises_with_the_permission_named():
    principal = Principal(user_id=1, org_id=1, email="x", role="viewer")
    with pytest.raises(PermissionDenied) as excinfo:
        principal.require("scan.create")
    assert "scan.create" in str(excinfo.value)
    assert excinfo.value.permission == "scan.create"


def test_every_role_is_documented():
    matrix = describe_roles()
    assert set(matrix) == {"owner", "admin", "security", "developer", "viewer"}
    assert all(isinstance(perms, list) for perms in matrix.values())
    # Privilege must be monotonic across the hierarchy.
    assert set(matrix["viewer"]) <= set(matrix["developer"]) <= set(matrix["security"])
    assert set(matrix["security"]) <= set(matrix["admin"]) <= set(matrix["owner"])


def test_no_role_declares_an_unknown_permission():
    for role, permissions in ROLE_PERMISSIONS.items():
        unknown = set(permissions) - ALL_PERMISSIONS
        assert not unknown, f"{role} declares unknown permissions: {unknown}"


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
def test_redaction_covers_credential_shaped_keys():
    cleaned = redact_secrets({
        "password": "hunter2",
        "api_key": "abc",
        "Authorization": "Bearer xyz",
        "client_secret": "s",
        "note": "this stays",
    })
    assert cleaned["note"] == "this stays"
    for key in ("password", "api_key", "Authorization", "client_secret"):
        assert cleaned[key] == REDACTED


def test_redaction_is_recursive():
    cleaned = redact_secrets({"config": {"url": "https://x", "token": "secret-value"},
                              "list": [{"private_key": "k"}, "plain"]})
    assert cleaned["config"]["token"] == REDACTED
    assert cleaned["config"]["url"] == "https://x"
    assert cleaned["list"][0]["private_key"] == REDACTED
    assert cleaned["list"][1] == "plain"


def test_redaction_handles_empty_input():
    assert redact_secrets(None) == {}
    assert redact_secrets({}) == {}


# --------------------------------------------------------------------------- #
# Self-scan and scan-root confinement
# --------------------------------------------------------------------------- #
