"""VULNERABLE fixture: deprecated protocol pinned on the SSL context."""
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
