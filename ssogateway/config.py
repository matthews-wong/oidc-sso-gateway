"""Gateway configuration, sourced from environment variables.

Defaults target the bundled mock IdP so the gateway runs fully offline. Point
``OIDC_DISCOVERY_URL`` / ``OIDC_CLIENT_ID`` / ``OIDC_CLIENT_SECRET`` at a real
provider and set ``USE_MOCK_IDP=false`` to use production identity.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_TRUTHY = {"1", "true", "yes", "on"}

# Path under which the bundled mock IdP is mounted on the gateway app.
MOCK_IDP_PREFIX = "/mock-idp"


@dataclass(frozen=True)
class Settings:
    """Resolved gateway settings. Treat as immutable per-process configuration."""

    session_secret: str
    public_base_url: str
    oidc_discovery_url: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_scopes: str
    session_cookie_name: str
    flow_cookie_name: str
    session_ttl_seconds: int
    flow_ttl_seconds: int
    use_mock_idp: bool

    @property
    def redirect_uri(self) -> str:
        """The OIDC redirect/callback URI registered with the IdP."""
        return f"{self.public_base_url}/callback"

    @property
    def cookies_secure(self) -> bool:
        """Emit ``Secure`` cookies whenever the public origin is HTTPS."""
        return self.public_base_url.lower().startswith("https")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


def get_settings() -> Settings:
    """Build :class:`Settings` from the current environment.

    Called once at app construction; not cached so tests can vary the
    environment between :func:`ssogateway.main.create_app` invocations.
    """
    public_base_url = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
    default_discovery = f"{public_base_url}{MOCK_IDP_PREFIX}/.well-known/openid-configuration"

    return Settings(
        session_secret=os.getenv("SESSION_SECRET", "dev-insecure-secret-change-me"),
        public_base_url=public_base_url,
        oidc_discovery_url=os.getenv("OIDC_DISCOVERY_URL", default_discovery),
        oidc_client_id=os.getenv("OIDC_CLIENT_ID", "mock-client"),
        oidc_client_secret=os.getenv("OIDC_CLIENT_SECRET", "mock-secret"),
        oidc_scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "ssogw_session"),
        flow_cookie_name=os.getenv("FLOW_COOKIE_NAME", "ssogw_flow"),
        session_ttl_seconds=int(os.getenv("SESSION_TTL_SECONDS", "3600")),
        flow_ttl_seconds=int(os.getenv("FLOW_TTL_SECONDS", "600")),
        use_mock_idp=_env_bool("USE_MOCK_IDP", True),
    )
