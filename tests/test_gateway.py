"""End-to-end and unit tests for the OIDC SSO gateway."""

from __future__ import annotations

import pytest
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError

from ssogateway import oidc


def test_unauthenticated_protected_route_redirects_to_login(client):
    resp = client.get("/app/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("/login")
    assert "next=" in location


def test_full_flow_grants_session_and_access(client):
    # Follow the whole chain: /app -> /login -> /authorize -> /callback -> /app.
    resp = client.get("/app/dashboard", follow_redirects=True)
    assert resp.status_code == 200
    body = resp.json()
    assert body["path"] == "/dashboard"
    assert body["user"]["email"] == "mock.user@example.com"
    assert body["user"]["sub"] == "mock-user-123"

    # A session cookie should now be set on the client.
    assert "ssogw_session" in client.cookies

    # The session is reused on a subsequent request without re-authenticating.
    again = client.get("/app/other", follow_redirects=False)
    assert again.status_code == 200
    assert again.json()["path"] == "/other"


def test_login_redirects_to_authorize_endpoint(client):
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "/mock-idp/authorize" in location
    assert "response_type=code" in location
    assert "state=" in location and "nonce=" in location
    assert "ssogw_flow" in resp.cookies


def test_callback_rejects_bad_state(client):
    # No prior /login means no flow cookie, so state validation must fail.
    resp = client.get("/callback?code=abc&state=nope", follow_redirects=False)
    assert resp.status_code == 400


def _valid_context(app):
    idp = app.state.mock_idp
    jwks = {"keys": [idp.public_jwk]}
    return idp, jwks


def test_expired_id_token_rejected(app):
    idp, jwks = _valid_context(app)
    token = idp.issue_id_token(nonce="n1", ttl_seconds=-10)
    with pytest.raises(ExpiredSignatureError):
        oidc.validate_id_token(
            token, jwks=jwks, issuer=idp.issuer, audience=idp.client_id, nonce="n1"
        )


def test_tampered_id_token_rejected(app):
    idp, jwks = _valid_context(app)
    token = idp.issue_id_token(nonce="n1")
    # Rewrite the leading signature byte so the RS256 signature no longer matches.
    header, payload, signature = token.split(".")
    flipped = ("B" if signature[0] != "B" else "C") + signature[1:]
    tampered = f"{header}.{payload}.{flipped}"
    with pytest.raises(InvalidSignatureError):
        oidc.validate_id_token(
            tampered, jwks=jwks, issuer=idp.issuer, audience=idp.client_id, nonce="n1"
        )


def test_nonce_mismatch_rejected(app):
    idp, jwks = _valid_context(app)
    token = idp.issue_id_token(nonce="issued-nonce")
    with pytest.raises(InvalidTokenError):
        oidc.validate_id_token(
            token, jwks=jwks, issuer=idp.issuer, audience=idp.client_id, nonce="expected-nonce"
        )


def test_wrong_audience_rejected(app):
    idp, jwks = _valid_context(app)
    token = idp.issue_id_token(nonce="n1")
    with pytest.raises(InvalidTokenError):
        oidc.validate_id_token(
            token, jwks=jwks, issuer=idp.issuer, audience="some-other-client", nonce="n1"
        )
