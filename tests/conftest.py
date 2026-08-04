"""Shared test fixtures.

The gateway's back-channel ``httpx.AsyncClient`` is wired to an ASGI transport
over the gateway app itself, so token/JWKS/discovery calls hit the mounted mock
IdP entirely in-process -- no sockets, fully offline.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from ssogateway.config import Settings

BASE_URL = "http://testserver"


def _make_settings() -> Settings:
    return Settings(
        session_secret="test-secret-key",
        public_base_url=BASE_URL,
        oidc_discovery_url=f"{BASE_URL}/mock-idp/.well-known/openid-configuration",
        oidc_client_id="mock-client",
        oidc_client_secret="mock-secret",
        oidc_scopes="openid profile email",
        session_cookie_name="ssogw_session",
        flow_cookie_name="ssogw_flow",
        session_ttl_seconds=3600,
        flow_ttl_seconds=600,
        use_mock_idp=True,
    )


@pytest.fixture()
def app():
    from ssogateway.main import create_app

    application = create_app(_make_settings())
    # Inject an in-process back-channel client before lifespan runs so the
    # gateway talks to the mounted mock IdP without real networking.
    application.state.http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url=BASE_URL
    )
    return application


@pytest.fixture()
def client(app):
    with TestClient(app, base_url=BASE_URL) as test_client:
        yield test_client
