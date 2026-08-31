"""Authentication primitives.

Deliberate choices, and why:

* **PBKDF2-HMAC-SHA256 from the standard library** for password hashing.
  It is not the strongest KDF available (argon2/bcrypt are), but it is in
  every Python 3.9+ install, it is FIPS-recognised, and it means an
  air-gapped customer install needs no compiled dependency to store
  passwords safely. 210k iterations follows OWASP's current guidance for
  PBKDF2-SHA256. Parameters are stored *in* the hash string, so raising
  the cost later does not invalidate existing credentials.
* **Raw passwords are never stored, logged or returned.** ``hash_password``
  is the only way to produce a stored value and ``verify_password`` the
  only way to check one.
* **Session and API tokens are stored as SHA-256 digests.** A database
  leak therefore does not hand over usable credentials. Only the caller
  ever sees the plaintext token, exactly once, at creation time.
* **Timing-safe comparison everywhere** a secret is matched.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

PBKDF2_ITERATIONS = 210_000
HASH_NAME = "pbkdf2_sha256"
SALT_BYTES = 16
TOKEN_BYTES = 32
API_TOKEN_PREFIX = "ics_"
SESSION_TTL_SECONDS = 12 * 60 * 60
API_TOKEN_MAX_AGE_SECONDS = 365 * 24 * 60 * 60

# Lockout: slow down online guessing without turning a typo into a support ticket.
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60


class SecurityError(ValueError):
    """Raised for malformed credentials or tokens."""


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Return a self-describing password hash string.

    Format: ``pbkdf2_sha256$<iterations>$<b64 salt>$<b64 digest>``.
    """
    if not password:
        raise SecurityError("password must not be empty")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join([
        HASH_NAME,
        str(iterations),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    ])


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash. Never raises on bad input."""
    if not stored or "$" not in stored:
        return False
    try:
        name, raw_iterations, raw_salt, raw_digest = stored.split("$", 3)
        if name != HASH_NAME:
            return False
        iterations = int(raw_iterations)
        salt = base64.b64decode(raw_salt)
        expected = base64.b64decode(raw_digest)
    except (ValueError, TypeError):
        return False
    if iterations <= 0:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str, iterations: int = PBKDF2_ITERATIONS) -> bool:
    """True when a stored hash was produced with a weaker cost parameter."""
    try:
        _, raw_iterations, _, _ = stored.split("$", 3)
        return int(raw_iterations) < iterations
    except (ValueError, TypeError):
        return True


PASSWORD_RULES = {
    "min_length": 12,
    "require_multiple_classes": True,
}


def password_problems(password: str) -> list[str]:
    """Return human-readable policy problems for a candidate password."""
    problems = []
    if len(password or "") < PASSWORD_RULES["min_length"]:
        problems.append(f"must be at least {PASSWORD_RULES['min_length']} characters")
    classes = sum([
        bool(re.search(r"[a-z]", password or "")),
        bool(re.search(r"[A-Z]", password or "")),
        bool(re.search(r"\d", password or "")),
        bool(re.search(r"[^A-Za-z0-9]", password or "")),
    ])
    if PASSWORD_RULES["require_multiple_classes"] and classes < 3:
        problems.append("must mix at least three of: lowercase, uppercase, digit, symbol")
    return problems


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #
def generate_session_token() -> Tuple[str, str]:
    """Return (plaintext token, sha256 digest to store)."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    return token, hash_token(token)


def generate_api_token(name: str = "") -> Tuple[str, str, str]:
    """Return (plaintext token, digest to store, display prefix).

    The plaintext is shown to the user exactly once; only the digest is
    persisted. The prefix (``ics_ab12…``) is stored so an operator can
    recognise a token in a list without being able to use it.
    """
    body = secrets.token_urlsafe(TOKEN_BYTES)
    token = f"{API_TOKEN_PREFIX}{body}"
    return token, hash_token(token), token[:12]


def hash_token(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))


def looks_like_api_token(value: str) -> bool:
    return bool(value) and value.startswith(API_TOKEN_PREFIX)


# --------------------------------------------------------------------------- #
# Signed bearer tokens (offline, no JWT library required)
# --------------------------------------------------------------------------- #
def signing_key(explicit: Optional[str] = None) -> bytes:
    """Resolve the HMAC signing key.

    ``IRONCLAD_SIGNING_KEY`` in production; a per-process random key
    otherwise, which makes stateless tokens unusable across restarts in
    development rather than silently trusting a shared default.
    """
    configured = explicit or os.environ.get("IRONCLAD_SIGNING_KEY")
    if configured:
        if len(configured) < 32:
            raise SecurityError("IRONCLAD_SIGNING_KEY must be at least 32 characters")
        return configured.encode("utf-8")
    return _process_key()


_PROCESS_KEY: Optional[bytes] = None


def _process_key() -> bytes:
    global _PROCESS_KEY
    if _PROCESS_KEY is None:
        _PROCESS_KEY = secrets.token_bytes(32)
    return _PROCESS_KEY


def issue_token(claims: Dict[str, Any], ttl_seconds: int = SESSION_TTL_SECONDS,
                key: Optional[str] = None) -> str:
    """Issue a compact signed token: ``base64(payload).base64(signature)``."""
    payload = dict(claims)
    payload["iat"] = int(time.time())
    payload["exp"] = payload["iat"] + int(ttl_seconds)
    raw = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signature = hmac.new(signing_key(key), raw, hashlib.sha256).digest()
    return raw.decode("ascii") + "." + base64.urlsafe_b64encode(signature).decode("ascii")


def decode_token(token: str, key: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Verify signature and expiry; raise :class:`SecurityError` otherwise."""
    if not token or "." not in token:
        raise SecurityError("malformed token")
    raw, _, raw_signature = token.rpartition(".")
    try:
        expected = hmac.new(signing_key(key), raw.encode("ascii"), hashlib.sha256).digest()
        provided = base64.urlsafe_b64decode(raw_signature.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SecurityError(f"malformed token: {exc}") from exc
    if not hmac.compare_digest(expected, provided):
        raise SecurityError("invalid token signature")
    try:
        claims = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
    except (ValueError, TypeError) as exc:
        raise SecurityError(f"malformed token payload: {exc}") from exc
    if int(claims.get("exp", 0)) < (now if now is not None else time.time()):
        raise SecurityError("token expired")
    return claims


@dataclass(frozen=True)
class LockoutDecision:
    allowed: bool
    locked_until: Optional[float] = None
    reason: str = ""


def lockout_decision(failed_logins: int, locked_until_epoch: Optional[float],
                     now: Optional[float] = None) -> LockoutDecision:
    """Decide whether a login attempt may proceed.

    Account lockout is time-based and self-clearing, so a mistyped password
    cannot permanently disable an account (which would itself be a denial
    of service an attacker could trigger deliberately).
    """
    current = time.time() if now is None else now
    if locked_until_epoch and locked_until_epoch > current:
        return LockoutDecision(False, locked_until_epoch, "account temporarily locked")
    if failed_logins >= MAX_FAILED_LOGINS:
        return LockoutDecision(False, current + LOCKOUT_SECONDS,
                               f"{MAX_FAILED_LOGINS} consecutive failures")
    return LockoutDecision(True, None, "")
