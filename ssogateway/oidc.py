"""OpenID Connect Authorization Code flow helpers.

Network access is confined to an injected ``httpx.AsyncClient`` so the same code
runs against the bundled mock IdP (via an ASGI transport) in tests and against a
real provider in production. ID-token validation is performed locally against a
JWKS document using PyJWT (RS256).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt.exceptions import InvalidTokenError


async def fetch_discovery(client: httpx.AsyncClient, discovery_url: str) -> dict[str, Any]:
    """Fetch and return the OIDC discovery document (``.well-known`` metadata)."""
    resp = await client.get(discovery_url)
    resp.raise_for_status()
    return resp.json()


async def fetch_jwks(client: httpx.AsyncClient, jwks_uri: str) -> dict[str, Any]:
    """Fetch the provider's JSON Web Key Set."""
    resp = await client.get(jwks_uri)
    resp.raise_for_status()
    return resp.json()


def build_authorize_url(
    discovery: dict[str, Any],
    *,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: str,
    nonce: str,
) -> str:
    """Construct the IdP authorization endpoint URL for the Authorization Code flow.

    ``state`` guards against CSRF on the callback; ``nonce`` binds the eventual
    ID token to this specific login attempt (replay protection).
    """
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
    }
    return f"{discovery['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code(
    client: httpx.AsyncClient,
    discovery: dict[str, Any],
    *,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
) -> dict[str, Any]:
    """Exchange an authorization ``code`` for tokens at the token endpoint."""
    resp = await client.post(
        discovery["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    resp.raise_for_status()
    return resp.json()


def _select_jwk(jwks: dict[str, Any], kid: str | None) -> dict[str, Any]:
    keys = jwks.get("keys", [])
    for key in keys:
        if kid is None or key.get("kid") == kid:
            return key
    raise InvalidTokenError(f"no matching JWK for kid={kid!r}")


def validate_id_token(
    id_token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str,
    nonce: str | None,
) -> dict[str, Any]:
    """Verify an ID token and return its claims.

    Checks the RS256 signature against the matching JWKS key and enforces the
    core OIDC claims: ``iss``, ``aud``, ``exp``/``iat`` presence and freshness,
    and the ``nonce`` bound at login. Raises :class:`InvalidTokenError` (or a
    subclass) on any failure.
    """
    header = jwt.get_unverified_header(id_token)
    jwk = _select_jwk(jwks, header.get("kid"))
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

    claims = jwt.decode(
        id_token,
        public_key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "iss", "aud"]},
    )

    if nonce is not None and claims.get("nonce") != nonce:
        raise InvalidTokenError("nonce mismatch")

    return claims
