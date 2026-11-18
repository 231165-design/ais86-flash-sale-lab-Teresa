"""Login con proveedores externos (Google y GitHub) mediante OAuth 2.0.

Flujo "Authorization Code + PKCE" resuelto 100 % en el servidor:

  1. El navegador va a  GET /api/v1/auth/{proveedor}/login
  2. El servidor guarda state + code_verifier en una cookie firmada y redirige al proveedor.
  3. El proveedor vuelve a  GET /api/v1/auth/{proveedor}/callback?code=...&state=...
  4. El servidor valida el state, canjea el code, lee el perfil, crea/actualiza el usuario,
     crea una sesión (cookie HttpOnly) y redirige a "/".

No hay scripts de terceros en el navegador, así que la CSP existente (script-src 'self',
connect-src 'self') no necesita cambios. El login es OPCIONAL: ningún endpoint de negocio
(catálogo, pedidos, /_lab) exige sesión, para no romper el contrato de Semana 9.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .db import utcnow
from .models import AuthSession, BillingTask, Order, User, UserOrder
from .security import (
    ApiError,
    constant_time_equals,
    get_session,
    get_settings_from_request,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

SESSION_COOKIE = "flash_session"
STATE_COOKIE = "flash_oauth"
STATE_COOKIE_PATH = "/api/v1/auth"
STATE_TTL_SECONDS = 600
HTTP_TIMEOUT_SECONDS = 10.0


# --------------------------------------------------------------------------------------
# Utilidades criptográficas (puras, fáciles de probar)
# --------------------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_value(key: bytes, payload: dict[str, Any], ttl_seconds: int, now: float | None = None) -> str:
    issued = time.time() if now is None else now
    body = _b64url(
        json.dumps({**payload, "exp": int(issued) + ttl_seconds}, separators=(",", ":")).encode("utf-8")
    )
    signature = _b64url(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{signature}"


def unsign_value(key: bytes, token: str | None, now: float | None = None) -> dict[str, Any] | None:
    if not token or len(token) > 2048 or token.count(".") != 1:
        return None
    body, signature = token.split(".")
    expected = _b64url(hmac.new(key, body.encode("ascii", "ignore"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(_b64url_decode(body))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    current = time.time() if now is None else now
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(current):
        return None
    return payload


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------
# Proveedores
# --------------------------------------------------------------------------------------


class AuthFailure(Exception):
    """Fallo controlado del login. `code` es lo único que se muestra al usuario."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Profile:
    subject: str
    email: str
    name: str


@dataclass(frozen=True)
class ProviderConfig:
    id: str
    label: str
    authorize_url: str
    token_url: str
    scope: str
    client_id: str
    client_secret: str
    extra_authorize_params: dict[str, str]


def configured_providers(settings: Settings) -> dict[str, ProviderConfig]:
    """Solo se activan los proveedores con client_id y client_secret definidos en .env."""
    found: dict[str, ProviderConfig] = {}

    google_secret = settings.google_client_secret.get_secret_value().strip()
    if settings.google_client_id.strip() and google_secret:
        found["google"] = ProviderConfig(
            id="google",
            label="Google",
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            scope="openid email profile",
            client_id=settings.google_client_id.strip(),
            client_secret=google_secret,
            extra_authorize_params={"prompt": "select_account"},
        )

    github_secret = settings.github_client_secret.get_secret_value().strip()
    if settings.github_client_id.strip() and github_secret:
        found["github"] = ProviderConfig(
            id="github",
            label="GitHub",
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            scope="read:user user:email",
            client_id=settings.github_client_id.strip(),
            client_secret=github_secret,
            extra_authorize_params={},
        )

    return found


def redirect_uri(settings: Settings, provider_id: str) -> str:
    return f"{settings.public_base_url}/api/v1/auth/{provider_id}/callback"


def build_authorize_url(
    settings: Settings, config: ProviderConfig, state: str, code_verifier: str
) -> str:
    params = {
        "client_id": config.client_id,
        "redirect_uri": redirect_uri(settings, config.id),
        "response_type": "code",
        "scope": config.scope,
        "state": state,
        "code_challenge": pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
        **config.extra_authorize_params,
    }
    return f"{config.authorize_url}?{urlencode(params)}"


def _clean(value: object, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


async def _fetch_google_profile(
    client: httpx.AsyncClient,
    settings: Settings,
    config: ProviderConfig,
    code: str,
    code_verifier: str,
) -> Profile:
    token_response = await client.post(
        config.token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "redirect_uri": redirect_uri(settings, config.id),
            "code_verifier": code_verifier,
        },
        headers={"Accept": "application/json"},
    )
    if token_response.status_code != 200:
        raise AuthFailure("exchange_failed")
    access_token = token_response.json().get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AuthFailure("exchange_failed")

    info_response = await client.get(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    if info_response.status_code != 200:
        raise AuthFailure("profile_failed")
    info = info_response.json()

    subject = _clean(info.get("sub"), 128)
    email = _clean(info.get("email"), 320).lower()
    if not subject or not email:
        raise AuthFailure("no_email")
    if info.get("email_verified") is not True:
        raise AuthFailure("email_unverified")
    name = _clean(info.get("name"), 200) or email.split("@")[0]
    return Profile(subject=subject, email=email, name=name)


async def _fetch_github_profile(
    client: httpx.AsyncClient,
    settings: Settings,
    config: ProviderConfig,
    code: str,
    code_verifier: str,
) -> Profile:
    token_response = await client.post(
        config.token_url,
        data={
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": redirect_uri(settings, config.id),
            "code_verifier": code_verifier,
        },
        headers={"Accept": "application/json"},
    )
    if token_response.status_code != 200:
        raise AuthFailure("exchange_failed")
    access_token = token_response.json().get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AuthFailure("exchange_failed")

    api_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "flash-sale-lab",
    }
    user_response = await client.get("https://api.github.com/user", headers=api_headers)
    if user_response.status_code != 200:
        raise AuthFailure("profile_failed")
    user = user_response.json()

    emails_response = await client.get("https://api.github.com/user/emails", headers=api_headers)
    if emails_response.status_code != 200:
        raise AuthFailure("no_email")
    chosen = ""
    for entry in emails_response.json():
        if isinstance(entry, dict) and entry.get("primary") is True and entry.get("verified") is True:
            chosen = _clean(entry.get("email"), 320).lower()
            break
    if not chosen:
        raise AuthFailure("email_unverified")

    subject = str(user.get("id") or "")[:128]
    if not subject:
        raise AuthFailure("profile_failed")
    name = _clean(user.get("name"), 200) or _clean(user.get("login"), 200) or chosen.split("@")[0]
    return Profile(subject=subject, email=chosen, name=name)


_PROFILE_FETCHERS = {
    "google": _fetch_google_profile,
    "github": _fetch_github_profile,
}


# --------------------------------------------------------------------------------------
# Sesiones y dependencias reutilizables
# --------------------------------------------------------------------------------------


async def optional_user(request: Request) -> User | None:
    """Devuelve el usuario de la sesión actual o None. Úsala donde el login es opcional.

    Abre su PROPIA sesión de base de datos a propósito: así no interfiere con las
    transacciones de la ruta que la llama (por ejemplo, la creación de pedidos).
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 128:
        return None
    async with request.app.state.db.session_factory() as session:
        result = await session.execute(
            select(User)
            .join(AuthSession, AuthSession.user_id == User.id)
            .where(
                AuthSession.token_hash == hash_session_token(token),
                AuthSession.expires_at > utcnow(),
            )
        )
        return result.scalar_one_or_none()


async def require_user(user: User | None = Depends(optional_user)) -> User:
    """Úsala en rutas que SÍ exigen sesión (por ejemplo, un futuro 'mis pedidos')."""
    if user is None:
        raise ApiError(401, "UNAUTHORIZED", "Login required")
    return user


def _user_view(user: User) -> dict[str, str]:
    return {
        "id": str(user.id),
        "name": user.name,
        "email": user.email,
        "provider": user.provider,
    }


def order_view(order: Any, task: Any | None) -> dict[str, Any]:
    """Pedido + comprobante (factura) tal como se guardó en la base de datos."""
    snapshot = dict(order.snapshot)
    return {
        "id": str(order.id),
        "created_at": snapshot.get("created_at"),
        "total_cents": order.total_cents,
        "items": snapshot.get("items", []),
        "billing_status": task.status if task is not None else "not_requested",
        "invoice_id": task.invoice_id if task is not None else None,
        "invoice_number": task.invoice_number if task is not None else None,
    }


def _provider_or_404(settings: Settings, provider: str) -> ProviderConfig:
    config = configured_providers(settings).get(provider)
    if config is None:
        raise ApiError(404, "NOT_FOUND", "Login provider not available")
    return config


def _finish(
    settings: Settings,
    *,
    error: str | None = None,
    session_token: str | None = None,
) -> RedirectResponse:
    location = "/" if error is None else f"/?{urlencode({'auth_error': error})}"
    response = RedirectResponse(location, status_code=302)
    response.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
    if session_token is not None:
        response.set_cookie(
            SESSION_COOKIE,
            session_token,
            max_age=settings.session_ttl_seconds,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            path="/",
        )
    return response


# --------------------------------------------------------------------------------------
# Rutas
# --------------------------------------------------------------------------------------


@router.get("/providers")
async def list_providers(request: Request) -> dict[str, Any]:
    settings = get_settings_from_request(request)
    return {
        "providers": [
            {"id": config.id, "name": config.label}
            for config in configured_providers(settings).values()
        ]
    }


@router.get("/me")
async def me(user: User | None = Depends(optional_user)) -> dict[str, Any]:
    return {"user": _user_view(user) if user is not None else None}


@router.get("/me/orders")
async def my_orders(
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Pedidos del usuario con su comprobante (billing_tasks), del más nuevo al más antiguo."""
    rows = (
        await session.execute(
            select(Order, BillingTask)
            .join(UserOrder, UserOrder.order_id == Order.id)
            .outerjoin(BillingTask, BillingTask.order_id == Order.id)
            .where(UserOrder.user_id == user.id)
            .order_by(Order.created_at.desc())
            .limit(50)
        )
    ).all()
    return {"orders": [order_view(order, task) for order, task in rows]}


@router.post("/logout")
async def logout(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    settings = get_settings_from_request(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token and len(token) <= 128:
        async with session.begin():
            await session.execute(
                delete(AuthSession).where(AuthSession.token_hash == hash_session_token(token))
            )
    response = JSONResponse({"ok": True})
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )
    return response


@router.get("/{provider}/login")
async def login(provider: str, request: Request) -> RedirectResponse:
    settings = get_settings_from_request(request)
    config = _provider_or_404(settings, provider)

    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    cookie_value = sign_value(
        settings.auth_key(),
        {"p": config.id, "s": state, "v": code_verifier},
        STATE_TTL_SECONDS,
    )

    response = RedirectResponse(
        build_authorize_url(settings, config, state, code_verifier), status_code=302
    )
    response.set_cookie(
        STATE_COOKIE,
        cookie_value,
        max_age=STATE_TTL_SECONDS,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=STATE_COOKIE_PATH,
    )
    return response


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    settings = get_settings_from_request(request)
    config = _provider_or_404(settings, provider)

    if error is not None:
        return _finish(settings, error="denied")

    pending = unsign_value(settings.auth_key(), request.cookies.get(STATE_COOKIE))
    if (
        pending is None
        or pending.get("p") != config.id
        or not isinstance(pending.get("s"), str)
        or not isinstance(pending.get("v"), str)
        or state is None
        or not constant_time_equals(state, pending["s"])
        or not code
        or len(code) > 2048
    ):
        return _finish(settings, error="state")

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            profile = await _PROFILE_FETCHERS[config.id](
                client, settings, config, code, pending["v"]
            )
    except AuthFailure as failure:
        return _finish(settings, error=failure.code)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        logger.warning("oauth error provider=%s type=%s", config.id, type(exc).__name__)
        return _finish(settings, error="exchange_failed")

    now = utcnow()
    session_token = secrets.token_urlsafe(32)
    async with session.begin():
        user_id = (
            await session.execute(
                pg_insert(User)
                .values(
                    id=uuid.uuid4(),
                    provider=config.id,
                    provider_user_id=profile.subject,
                    email=profile.email,
                    name=profile.name,
                    created_at=now,
                    last_login_at=now,
                )
                .on_conflict_do_update(
                    constraint="uq_users_provider_subject",
                    set_={
                        "email": profile.email,
                        "name": profile.name,
                        "last_login_at": now,
                    },
                )
                .returning(User.id)
            )
        ).scalar_one()
        await session.execute(
            delete(AuthSession).where(
                AuthSession.user_id == user_id, AuthSession.expires_at <= now
            )
        )
        session.add(
            AuthSession(
                token_hash=hash_session_token(session_token),
                user_id=user_id,
                created_at=now,
                expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
            )
        )

    return _finish(settings, session_token=session_token)
