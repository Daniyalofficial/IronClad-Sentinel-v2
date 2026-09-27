"""Optional, pre-provisioned OIDC login for the browser dashboard.

Authorization code + PKCE (S256), server-side client authentication, a
browser-bound state cookie, a single-use database state and a signed ID token
are all required. IdP claims NEVER choose the organization or role: a fixed
configured organization and an existing, active user do. First login binds
the issuer/subject to that user; subsequent logins cannot silently rebind.

The scanner remains air-gapped: these HTTPS requests are only made by the
operator-enabled authentication route, not by scanning repository content.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from ironclad.api.deps import get_db
from ironclad.platform import audit, events
from ironclad.platform.models import (
    OidcIdentity,
    OidcState,
    Organization,
    Session as SessionRow,
    User,
    utcnow,
)
from ironclad.platform.ratelimit import client_ip
from ironclad.platform.security import SESSION_TTL_SECONDS, generate_session_token
from ironclad.web.app import COOKIE_NAME

router = APIRouter(prefix="/auth/oidc", tags=["auth"])
STATE_COOKIE = "__Host-ironclad-oidc-state"
STATE_SECONDS = 600
ALGORITHMS = ("RS256", "PS256", "ES256")  # public-key signatures only; no `none` or HMAC
MAX_ID_TOKEN_SIZE = 32_768
MAX_PROVIDER_RESPONSE = 1_048_576


class OidcUnavailable(Exception):
    """The configured provider or its metadata is unavailable/unsafe."""


class OidcRejected(Exception):
    """The provider response cannot authenticate this user."""


def _https_url(value: str, *, callback: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
                parsed.password or parsed.fragment or (callback and parsed.query)):
            raise ValueError("not a safe HTTPS URL")
        if callback and parsed.path != "/auth/oidc/callback":
            raise ValueError("callback must point to /auth/oidc/callback")
    except ValueError as exc:
        raise ValueError("OIDC URLs must use HTTPS and the fixed callback path") from exc
    return value


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    org_slug: str
    token_auth_method: str
    session_ttl: int
    ca_bundle: Optional[str]

    @classmethod
    def from_environment(cls) -> Optional["OidcConfig"]:
        names = ("ISSUER", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI", "ORG_SLUG")
        values = {name: os.environ.get(f"IRONCLAD_OIDC_{name}", "").strip() for name in names}
        if not any(values.values()):
            return None
        if not all(values.values()):
            raise ValueError("OIDC requires IRONCLAD_OIDC_ISSUER, CLIENT_ID, CLIENT_SECRET, "
                             "REDIRECT_URI and ORG_SLUG")
        issuer = _https_url(values["ISSUER"]).rstrip("/")
        if len(issuer) > 512 or len(values["CLIENT_ID"]) > 256:
            raise ValueError("OIDC issuer or client ID exceeds supported length")
        redirect = _https_url(values["REDIRECT_URI"], callback=True)
        if not values["ORG_SLUG"] or len(values["ORG_SLUG"]) > 128:
            raise ValueError("OIDC organization slug is invalid")
        method = os.environ.get("IRONCLAD_OIDC_TOKEN_AUTH_METHOD", "client_secret_basic").strip()
        if method not in ("client_secret_basic", "client_secret_post"):
            raise ValueError("OIDC token auth method must be client_secret_basic or client_secret_post")
        ttl = int(os.environ.get("IRONCLAD_OIDC_SESSION_TTL_SECONDS", "3600"))
        if not 60 <= ttl <= SESSION_TTL_SECONDS:
            raise ValueError("OIDC session TTL must be between 60 and 43200 seconds")
        bundle = os.environ.get("IRONCLAD_OIDC_CA_BUNDLE", "").strip() or None
        if bundle and not os.path.isfile(bundle):
            raise ValueError("OIDC CA bundle must be an existing file")
        return cls(issuer, values["CLIENT_ID"], values["CLIENT_SECRET"], redirect,
                   values["ORG_SLUG"], method, ttl, bundle)


class OidcProvider:
    def __init__(self, config: OidcConfig):
        self.config = config
        # MockTransport is only injected by tests; production uses TLS verification.
        self.transport: Optional[httpx.BaseTransport] = None

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False,
                            verify=self.config.ca_bundle or True, transport=self.transport)

    @staticmethod
    def _json(response: httpx.Response) -> Dict[str, Any]:
        if response.status_code != 200 or len(response.content) > MAX_PROVIDER_RESPONSE:
            raise OidcUnavailable("unexpected provider response")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OidcUnavailable("invalid provider response") from exc
        if not isinstance(payload, dict):
            raise OidcUnavailable("invalid provider response")
        return payload

    def discovery(self, client: httpx.Client) -> Dict[str, str]:
        url = self.config.issuer + "/.well-known/openid-configuration"
        try:
            data = self._json(client.get(url))
            if data.get("issuer") != self.config.issuer:
                raise OidcUnavailable("OIDC issuer mismatch")
            return {key: _https_url(data[key]) for key in
                    ("authorization_endpoint", "token_endpoint", "jwks_uri")}
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
            raise OidcUnavailable("OIDC discovery failed") from exc

    def authorization_url(self, state: str, nonce: str, verifier: str) -> str:
        with self._client() as client:
            endpoint = self.discovery(client)["authorization_endpoint"]
        challenge = _b64u(hashlib.sha256(verifier.encode("ascii")).digest())
        params = {
            "client_id": self.config.client_id, "response_type": "code",
            "scope": "openid email profile", "redirect_uri": self.config.redirect_uri,
            "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)

    def authenticate(self, code: str, nonce: str, verifier: str) -> Dict[str, Any]:
        try:
            with self._client() as client:
                metadata = self.discovery(client)
                form = {
                    "grant_type": "authorization_code", "code": code,
                    "redirect_uri": self.config.redirect_uri, "code_verifier": verifier,
                }
                if self.config.token_auth_method == "client_secret_basic":
                    auth = httpx.BasicAuth(self.config.client_id, self.config.client_secret)
                else:
                    auth = None
                    form.update(client_id=self.config.client_id,
                                client_secret=self.config.client_secret)
                token = self._json(client.post(metadata["token_endpoint"], data=form, auth=auth))
                id_token = token.get("id_token")
                if not isinstance(id_token, str) or not 1 <= len(id_token) <= MAX_ID_TOKEN_SIZE:
                    raise OidcRejected("missing or oversized ID token")
                jwks = self._json(client.get(metadata["jwks_uri"]))
        except httpx.HTTPError as exc:
            raise OidcUnavailable("OIDC token exchange failed") from exc
        return self._verify_id_token(id_token, jwks, nonce, token.get("access_token"))

    def _verify_id_token(self, id_token: str, jwks: Dict[str, Any], nonce: str,
                         access_token: Any) -> Dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
            alg, kid = header.get("alg"), header.get("kid")
            if alg not in ALGORITHMS or not isinstance(kid, str) or not kid:
                raise OidcRejected("unsupported ID token signature")
            keys = jwks.get("keys")
            if not isinstance(keys, list) or len(keys) > 100:
                raise OidcRejected("invalid signing keys")
            matching = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
            if len(matching) != 1:
                raise OidcRejected("ambiguous or missing signing key")
            key = matching[0]
            if (key.get("use", "sig") != "sig" or
                    ("key_ops" in key and "verify" not in key["key_ops"]) or
                    (key.get("alg") not in (None, alg))):
                raise OidcRejected("key is not allowed for verification")
            verified = jwt.decode(id_token, key=jwt.PyJWK.from_dict(key).key,
                                  algorithms=[alg], audience=self.config.client_id,
                                  issuer=self.config.issuer, leeway=60,
                                  options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]})
            if not isinstance(verified, dict):
                raise OidcRejected("invalid ID token claims")
            audience = verified.get("aud")
            if isinstance(audience, list) and len(audience) > 1 and verified.get("azp") != self.config.client_id:
                raise OidcRejected("wrong authorized party")
            if not isinstance(verified["nonce"], str) or not hmac.compare_digest(verified["nonce"], nonce):
                raise OidcRejected("nonce mismatch")
            subject = verified.get("sub")
            if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
                raise OidcRejected("invalid OIDC subject")
            if verified.get("email_verified") is not True:
                raise OidcRejected("unverified email")
            email = verified.get("email")
            if not isinstance(email, str) or len(email) > 320:
                raise OidcRejected("missing email")
            verified["email"] = validate_email(email, check_deliverability=False).normalized.lower()
            # When the provider includes at_hash in the token response, check
            # that it actually describes the access token it delivered.
            if "at_hash" in verified:
                if not isinstance(access_token, str):
                    raise OidcRejected("missing access token for at_hash")
                expected = _b64u(hashlib.sha256(access_token.encode()).digest()[:16])
                if not isinstance(verified["at_hash"], str) or not hmac.compare_digest(verified["at_hash"], expected):
                    raise OidcRejected("access token hash mismatch")
            return verified
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, EmailNotValidError) as exc:
            raise OidcRejected("ID token validation failed") from exc


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _configured(request: Request) -> OidcProvider:
    provider = getattr(request.app.state, "oidc", None)
    if provider is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC not configured")
    return provider


def _no_store(response: RedirectResponse) -> RedirectResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("/start")
def start(request: Request, session: DbSession = Depends(get_db)) -> RedirectResponse:
    provider = _configured(request)
    decision = request.app.state.limiter.check_login(client_ip(request))
    if not decision.allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many sign-in attempts")
    org = session.execute(select(Organization).where(
        Organization.slug == provider.config.org_slug)).scalar_one_or_none()
    if org is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "OIDC organization not provisioned")
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    try:
        location = provider.authorization_url(state, nonce, verifier)
    except OidcUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "identity provider unavailable") from exc
    session.execute(delete(OidcState).where(OidcState.expires_at < utcnow()))
    session.add(OidcState(state_hash=hashlib.sha256(state.encode()).hexdigest(), org_id=org.id,
                          nonce=nonce, code_verifier=verifier,
                          expires_at=utcnow() + timedelta(seconds=STATE_SECONDS)))
    session.commit()
    response = _no_store(RedirectResponse(location, status_code=status.HTTP_302_FOUND))
    response.set_cookie(STATE_COOKIE, state, max_age=STATE_SECONDS,
                        httponly=True, secure=True, samesite="lax", path="/")
    return response


@router.get("/callback")
def callback(request: Request, state: str = Query(..., min_length=32, max_length=256),
             code: Optional[str] = Query(None, min_length=1, max_length=8192),
             error: Optional[str] = Query(None, max_length=256),
             session: DbSession = Depends(get_db)) -> RedirectResponse:
    provider = _configured(request)
    cookie = request.cookies.get(STATE_COOKIE, "")
    if not cookie or not hmac.compare_digest(cookie, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid OIDC state")
    row = session.execute(
        delete(OidcState).where(OidcState.state_hash == hashlib.sha256(state.encode()).hexdigest(),
                                OidcState.expires_at > utcnow())
        .returning(OidcState.org_id, OidcState.nonce, OidcState.code_verifier)
    ).one_or_none()
    session.commit()  # consume before any IdP I/O; concurrent callback gets no row
    if row is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired OIDC state")
    org_id, nonce, verifier = row
    if error or not code:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "identity provider rejected sign-in")
    try:
        claims = provider.authenticate(code, nonce, verifier)
    except OidcUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "identity provider unavailable") from exc
    except OidcRejected as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "OIDC verification failed") from exc

    # A tenant and role are never read from IdP claims. No JIT users, no
    # implicit admins: the operator provisions users with the existing API.
    org = session.get(Organization, org_id)
    if org is None or org.slug != provider.config.org_slug:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC user not provisioned")
    identity = session.execute(select(OidcIdentity).where(
        OidcIdentity.issuer == provider.config.issuer,
        OidcIdentity.subject == claims["sub"])).scalar_one_or_none()
    if identity is not None:
        if identity.org_id != org_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC user not provisioned")
        user = session.get(User, identity.user_id)
    else:
        user = session.execute(select(User).where(
            User.org_id == org_id, User.email == claims["email"])).scalar_one_or_none()
        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC user not provisioned")
        already_bound = session.execute(select(OidcIdentity.id).where(
            OidcIdentity.user_id == user.id,
            OidcIdentity.issuer == provider.config.issuer)).scalar_one_or_none()
        if already_bound is not None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC identity already bound")
        session.add(OidcIdentity(org_id=org_id, user_id=user.id,
                                 issuer=provider.config.issuer, subject=claims["sub"]))
    if user is None or not user.is_active or user.org_id != org_id or user.email != claims["email"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC user not provisioned")

    token, token_hash = generate_session_token()
    session.add(SessionRow(user_id=user.id, org_id=org_id, token_hash=token_hash,
                           expires_at=utcnow() + timedelta(seconds=provider.config.session_ttl),
                           user_agent=(request.headers.get("user-agent") or "")[:200]))
    user.last_login_at = utcnow()
    audit.record(session, org_id=org_id, action="auth.login", actor=user.email, actor_id=user.id,
                 metadata={"via": "oidc", "issuer": provider.config.issuer})
    events.default_bus.publish(session, events.AUTH_LOGIN, org_id, {"user_id": user.id})
    try:
        session.commit()
    except IntegrityError as exc:
        # Two first-time logins with the same email or subject race; a UNIQUE
        # constraint rejects the second rather than rebinding either account.
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "OIDC identity binding conflict") from exc
    response = _no_store(RedirectResponse("/ui/", status_code=status.HTTP_303_SEE_OTHER))
    response.delete_cookie(STATE_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    response.set_cookie(COOKIE_NAME, token, max_age=provider.config.session_ttl,
                        httponly=True, secure=True, samesite="lax", path="/")
    return response
