"""Gateway routes: OIDC login/callback/logout plus a protected ``/app/*`` passthrough.

The gateway performs the OIDC Authorization Code flow against a discovered IdP
(the bundled mock by default) and, on success, issues a signed session cookie.
Requests to ``/app/*`` without a valid session are redirected to ``/login``.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any, Optional
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from jwt.exceptions import InvalidTokenError

from . import oidc
from .config import MOCK_IDP_PREFIX, Settings, get_settings
from .mock_idp import MockIdP, build_mock_idp_router
from .session import SessionManager

PROTECTED_PREFIX = "/app"


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Create a default back-channel client only if a test hasn't injected one.
    created_client = False
    if getattr(app.state, "http_client", None) is None:
        app.state.http_client = httpx.AsyncClient(timeout=10.0)
        created_client = True
    try:
        yield
    finally:
        if created_client:
            await app.state.http_client.aclose()


def _current_user(request: Request) -> Optional[dict[str, Any]]:
    """Return the decoded session payload for this request, or ``None``."""
    settings: Settings = request.app.state.settings
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    return request.app.state.session_manager.decode(token)


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Build and return the gateway FastAPI app.

    Pass ``settings`` to override environment-derived configuration (useful in
    tests). When ``settings.use_mock_idp`` is true the bundled IdP is mounted at
    :data:`ssogateway.config.MOCK_IDP_PREFIX`.
    """
    settings = settings or get_settings()

    app = FastAPI(title="OIDC SSO Gateway", version="0.1.0", lifespan=_lifespan)
    app.state.settings = settings
    app.state.http_client = None  # populated by lifespan or a test
    app.state.session_manager = SessionManager(
        settings.session_secret, settings.session_ttl_seconds, salt="ssogw.session"
    )
    app.state.flow_manager = SessionManager(
        settings.session_secret, settings.flow_ttl_seconds, salt="ssogw.flow"
    )

    if settings.use_mock_idp:
        idp = MockIdP(
            issuer=f"{settings.public_base_url}{MOCK_IDP_PREFIX}",
            client_id=settings.oidc_client_id,
        )
        app.state.mock_idp = idp
        app.include_router(build_mock_idp_router(idp), prefix=MOCK_IDP_PREFIX)

    def _set_cookie(response, name: str, value: str, max_age: int) -> None:
        response.set_cookie(
            key=name,
            value=value,
            max_age=max_age,
            httponly=True,
            samesite="lax",
            secure=settings.cookies_secure,
            path="/",
        )

    @app.get("/")
    def index(request: Request) -> JSONResponse:
        user = _current_user(request)
        return JSONResponse(
            {
                "service": "oidc-sso-gateway",
                "authenticated": user is not None,
                "user": user,
                "login": "/login",
                "protected_example": "/app/dashboard",
            }
        )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/login")
    async def login(request: Request, next: str = Query("/app/")) -> RedirectResponse:
        client: httpx.AsyncClient = request.app.state.http_client
        discovery = await oidc.fetch_discovery(client, settings.oidc_discovery_url)

        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        authorize_url = oidc.build_authorize_url(
            discovery,
            client_id=settings.oidc_client_id,
            redirect_uri=settings.redirect_uri,
            scopes=settings.oidc_scopes,
            state=state,
            nonce=nonce,
        )

        response = RedirectResponse(authorize_url, status_code=302)
        flow_token = request.app.state.flow_manager.encode(
            {"state": state, "nonce": nonce, "next": next}
        )
        _set_cookie(response, settings.flow_cookie_name, flow_token, settings.flow_ttl_seconds)
        return response

    @app.get("/callback")
    async def callback(
        request: Request,
        code: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
        error: Optional[str] = Query(None),
    ) -> RedirectResponse:
        if error:
            raise HTTPException(status_code=400, detail=f"idp_error: {error}")

        flow_cookie = request.cookies.get(settings.flow_cookie_name)
        flow = request.app.state.flow_manager.decode(flow_cookie) if flow_cookie else None
        # Reject unless the callback matches the state we bound at /login (CSRF guard).
        if not flow or not code or not state or state != flow.get("state"):
            raise HTTPException(status_code=400, detail="invalid_state")

        client: httpx.AsyncClient = request.app.state.http_client
        discovery = await oidc.fetch_discovery(client, settings.oidc_discovery_url)
        tokens = await oidc.exchange_code(
            client,
            discovery,
            code=code,
            redirect_uri=settings.redirect_uri,
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
        )

        id_token = tokens.get("id_token")
        if not id_token:
            raise HTTPException(status_code=502, detail="missing_id_token")

        jwks = await oidc.fetch_jwks(client, discovery["jwks_uri"])
        try:
            claims = oidc.validate_id_token(
                id_token,
                jwks=jwks,
                issuer=discovery["issuer"],
                audience=settings.oidc_client_id,
                nonce=flow.get("nonce"),
            )
        except InvalidTokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid_id_token: {exc}")

        session_token = request.app.state.session_manager.encode(
            {"sub": claims["sub"], "email": claims.get("email"), "name": claims.get("name")}
        )
        next_url = flow.get("next") or "/app/"
        response = RedirectResponse(next_url, status_code=302)
        _set_cookie(
            response, settings.session_cookie_name, session_token, settings.session_ttl_seconds
        )
        response.delete_cookie(settings.flow_cookie_name, path="/")
        return response

    @app.get("/logout")
    def logout() -> RedirectResponse:
        response = RedirectResponse("/", status_code=302)
        response.delete_cookie(settings.session_cookie_name, path="/")
        return response

    @app.api_route(
        PROTECTED_PREFIX + "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    )
    async def protected(request: Request, path: str):
        """Protected passthrough. Unauthenticated -> 302 /login.

        With no real downstream configured this echoes the request and the
        authenticated identity, standing in for a reverse-proxy to an upstream
        service.
        """
        user = _current_user(request)
        if user is None:
            target = request.url.path
            return RedirectResponse(f"/login?next={quote(target)}", status_code=302)
        return JSONResponse(
            {
                "message": "authenticated request reached protected upstream",
                "path": "/" + path,
                "method": request.method,
                "user": user,
            }
        )

    return app


# ASGI entrypoint for ``uvicorn ssogateway.main:app``.
app = create_app()
