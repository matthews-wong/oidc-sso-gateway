"""A minimal in-process OpenID Connect provider for local dev and tests.

It exposes the endpoints the gateway needs -- discovery, ``/authorize``,
``/token`` and ``/jwks`` -- and signs RS256 ID tokens with a freshly generated
RSA key whose public half is published via JWKS. It is deliberately not a
complete or hardened IdP; it exists so the gateway runs and is testable with no
external identity service.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Form, HTTPException, Query
from fastapi.responses import JSONResponse, RedirectResponse

_DEFAULT_KID = "mock-key-1"


def _generate_rsa_key(kid: str) -> tuple[bytes, dict[str, Any]]:
    """Generate an RSA-2048 keypair; return (PKCS8 private PEM, public JWK)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return private_pem, jwk


class MockIdP:
    """Holds the signing key and short-lived authorization codes for one issuer."""

    def __init__(
        self,
        issuer: str,
        client_id: str,
        *,
        sub: str = "mock-user-123",
        email: str = "mock.user@example.com",
        name: str = "Mock User",
        kid: str = _DEFAULT_KID,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.sub = sub
        self.email = email
        self.name = name
        self.kid = kid
        self._private_pem, self.public_jwk = _generate_rsa_key(kid)
        # Issued authorization codes -> the nonce they must echo. Single-use.
        self._codes: dict[str, Optional[str]] = {}

    def issue_code(self, nonce: Optional[str]) -> str:
        code = secrets.token_urlsafe(24)
        self._codes[code] = nonce
        return code

    def redeem_code(self, code: str) -> Optional[str]:
        """Consume ``code`` and return its bound nonce; raise if unknown."""
        if code not in self._codes:
            raise KeyError(code)
        return self._codes.pop(code)

    def issue_id_token(
        self,
        *,
        nonce: Optional[str],
        ttl_seconds: int = 3600,
        now: Optional[int] = None,
    ) -> str:
        """Mint a signed RS256 ID token. ``ttl_seconds`` may be negative for tests."""
        issued_at = int(time.time()) if now is None else now
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": self.sub,
            "aud": self.client_id,
            "iat": issued_at,
            "exp": issued_at + ttl_seconds,
            "email": self.email,
            "name": self.name,
        }
        if nonce is not None:
            claims["nonce"] = nonce
        return jwt.encode(claims, self._private_pem, algorithm="RS256", headers={"kid": self.kid})


def build_mock_idp_router(idp: MockIdP) -> APIRouter:
    """Return a router exposing ``idp`` as OIDC endpoints (mount under a prefix)."""
    router = APIRouter(tags=["mock-idp"])

    @router.get("/.well-known/openid-configuration")
    def discovery() -> dict[str, Any]:
        base = idp.issuer
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
        }

    @router.get("/jwks")
    def jwks() -> dict[str, Any]:
        return {"keys": [idp.public_jwk]}

    @router.get("/authorize")
    def authorize(
        response_type: str = Query(...),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query("openid"),
        state: Optional[str] = Query(None),
        nonce: Optional[str] = Query(None),
    ) -> RedirectResponse:
        # A real IdP would authenticate the end user here; the mock auto-approves.
        if response_type != "code":
            raise HTTPException(status_code=400, detail="unsupported_response_type")
        if client_id != idp.client_id:
            raise HTTPException(status_code=400, detail="unauthorized_client")

        code = idp.issue_code(nonce)
        params = {"code": code}
        if state is not None:
            params["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)

    @router.post("/token")
    def token(
        grant_type: str = Form(...),
        code: str = Form(...),
        redirect_uri: str = Form(None),
        client_id: str = Form(None),
        client_secret: str = Form(None),
    ) -> JSONResponse:
        if grant_type != "authorization_code":
            raise HTTPException(status_code=400, detail="unsupported_grant_type")
        try:
            nonce = idp.redeem_code(code)
        except KeyError:
            raise HTTPException(status_code=400, detail="invalid_grant")

        id_token = idp.issue_id_token(nonce=nonce)
        return JSONResponse(
            {
                "access_token": secrets.token_urlsafe(24),
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
            }
        )

    return router
