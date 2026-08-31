"""Pluggable mail transport for transactional mail (password resets).

The product must be installable and testable with no SMTP credentials, and
must not silently pretend to have sent mail when it has not. So the transport
is an explicit interface with three implementations:

``InMemoryTransport``
    Records messages in a list. Used by the test suite and by local
    development. Nothing leaves the process, and the tests assert on the
    recorded messages rather than on a mock that claims delivery happened.

``SmtpTransport``
    Real delivery via ``smtplib``. Configured entirely from the environment
    (``IRONCLAD_SMTP_*``); no credentials live in code or config files.

``NullTransport``
    Accepts and discards. For deployments that wire password reset to an
    external identity flow and do not want IronClad sending mail at all --
    but unlike simply not configuring a transport, it is explicit.

Selection is via ``IRONCLAD_MAIL_TRANSPORT`` (``memory`` | ``smtp`` |
``null``). The default is ``memory``, so a fresh install never attempts a
network connection.

Every transport returns a :class:`DeliveryResult` rather than raising on a
refused message, because a reset request must return the same generic
response whether or not the address exists -- a transport error must not
change the HTTP response and leak that information.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Dict, List, Optional, Protocol

ENV_TRANSPORT = "IRONCLAD_MAIL_TRANSPORT"
ENV_FROM = "IRONCLAD_MAIL_FROM"
ENV_RESET_URL_BASE = "IRONCLAD_PASSWORD_RESET_URL_BASE"

DEFAULT_FROM = "IronClad Sentinel <no-reply@ironclad.local>"


@dataclass(frozen=True)
class DeliveryResult:
    ok: bool
    detail: str = ""
    #: Set by InMemoryTransport so tests can inspect what would have been sent.
    message: Optional[EmailMessage] = None


class MailTransport(Protocol):
    """Interface a transport must implement."""

    def send(self, to: str, subject: str, body_text: str, *,
             body_html: Optional[str] = None) -> DeliveryResult:
        ...


@dataclass
class InMemoryTransport:
    """Records messages instead of sending them."""

    sent: List[Dict] = field(default_factory=list)
    from_address: str = DEFAULT_FROM
    #: Set to make send() fail, for testing transport-error handling.
    fail_with: Optional[str] = None

    def send(self, to: str, subject: str, body_text: str, *,
             body_html: Optional[str] = None) -> DeliveryResult:
        if self.fail_with:
            return DeliveryResult(False, self.fail_with)
        message = EmailMessage()
        message["From"] = self.from_address
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body_text)
        if body_html:
            message.add_alternative(body_html, subtype="html")
        self.sent.append({"to": to, "subject": subject, "body": body_text,
                          "html": body_html, "message": message})
        return DeliveryResult(True, "recorded", message)

    def last(self) -> Optional[Dict]:
        return self.sent[-1] if self.sent else None

    def clear(self) -> None:
        self.sent.clear()


@dataclass
class NullTransport:
    """Accepts and discards. Explicit, unlike not configuring a transport."""

    def send(self, to: str, subject: str, body_text: str, *,
             body_html: Optional[str] = None) -> DeliveryResult:
        return DeliveryResult(True, "discarded (null transport)")


@dataclass
class SmtpTransport:
    """Real SMTP delivery, configured entirely from the environment."""

    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    use_ssl: bool = False
    from_address: str = DEFAULT_FROM
    timeout: float = 15.0

    def send(self, to: str, subject: str, body_text: str, *,
             body_html: Optional[str] = None) -> DeliveryResult:
        if not self.host:
            return DeliveryResult(False, "IRONCLAD_SMTP_HOST is not set")

        message = EmailMessage()
        message["From"] = self.from_address
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body_text)
        if body_html:
            message.add_alternative(body_html, subtype="html")

        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout,
                                          context=context)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with server:
                if self.use_tls and not self.use_ssl:
                    server.starttls(context=ssl.create_default_context())
                if self.username:
                    server.login(self.username, self.password)
                server.send_message(message)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            # Returned, not raised: the caller must still give the same generic
            # response it would give for a nonexistent address.
            return DeliveryResult(False, f"{type(exc).__name__}: {exc}")
        return DeliveryResult(True, "sent")


def build_transport_from_env() -> MailTransport:
    """Build the transport selected by ``IRONCLAD_MAIL_TRANSPORT``.

    An unrecognised value falls back to the in-memory transport rather than
    raising: a typo in one environment variable must not stop the API from
    starting, and silently discarding is safer than accidentally attempting a
    network connection.
    """
    kind = (os.environ.get(ENV_TRANSPORT) or "memory").strip().lower()
    from_address = os.environ.get(ENV_FROM) or DEFAULT_FROM

    if kind == "null":
        return NullTransport()
    if kind == "smtp":
        return SmtpTransport(
            host=os.environ.get("IRONCLAD_SMTP_HOST", ""),
            port=int(os.environ.get("IRONCLAD_SMTP_PORT", "587")),
            username=os.environ.get("IRONCLAD_SMTP_USERNAME", ""),
            password=os.environ.get("IRONCLAD_SMTP_PASSWORD", ""),
            use_tls=os.environ.get("IRONCLAD_SMTP_STARTTLS", "1").lower() in {"1", "true", "yes"},
            use_ssl=os.environ.get("IRONCLAD_SMTP_SSL", "0").lower() in {"1", "true", "yes"},
            from_address=from_address,
            timeout=float(os.environ.get("IRONCLAD_SMTP_TIMEOUT", "15")),
        )
    return InMemoryTransport(from_address=from_address)
