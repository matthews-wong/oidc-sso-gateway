"""Signed, TTL-bounded session cookies backed by ``itsdangerous``.

The cookie value is a signed (not encrypted) token. Do not store secrets in
it; store only the identity claims needed to authorize requests. Tampering is
detected via the HMAC signature; expiry is enforced via ``max_age``.
"""

from __future__ import annotations

from typing import Any, Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class SessionManager:
    """Encode/decode a dict payload into a signed, timestamped cookie value."""

    def __init__(self, secret: str, ttl_seconds: int, salt: str) -> None:
        # A per-purpose salt keeps the session token and the transient auth-flow
        # token cryptographically distinct even though they share one secret.
        self._serializer = URLSafeTimedSerializer(secret, salt=salt)
        self._ttl = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def encode(self, payload: dict[str, Any]) -> str:
        """Serialize and sign ``payload`` into a URL-safe cookie value."""
        return self._serializer.dumps(payload)

    def decode(self, token: str) -> Optional[dict[str, Any]]:
        """Return the payload if the signature is valid and unexpired, else ``None``."""
        try:
            return self._serializer.loads(token, max_age=self._ttl)
        except (BadSignature, SignatureExpired):
            return None
