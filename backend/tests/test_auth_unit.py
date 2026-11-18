from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from app.auth import (
    build_authorize_url,
    configured_providers,
    hash_session_token,
    pkce_challenge,
    redirect_uri,
    sign_value,
    unsign_value,
)
from app.config import Settings

KEY = b"k" * 32


def make_settings(**overrides: str) -> Settings:
    base = {
        "database_url": "postgresql://u:p@localhost/db",
        "redis_url": "redis://localhost:6379/0",
        "lab_key": "x" * 40,
        "public_base_url": "http://localhost:8019/",
        "google_client_id": "",
        "google_client_secret": "",
        "github_client_id": "",
        "github_client_secret": "",
    }
    base.update(overrides)
    return Settings(**base)


def test_sign_roundtrip() -> None:
    token = sign_value(KEY, {"p": "google", "s": "abc"}, 60, now=1000)
    payload = unsign_value(KEY, token, now=1030)
    assert payload is not None
    assert payload["p"] == "google"
    assert payload["s"] == "abc"


def test_sign_rejects_tampering_and_wrong_key() -> None:
    token = sign_value(KEY, {"p": "google"}, 60, now=1000)
    body, signature = token.split(".")
    assert unsign_value(KEY, f"{body}x.{signature}", now=1001) is None
    assert unsign_value(b"z" * 32, token, now=1001) is None
    assert unsign_value(KEY, "basura", now=1001) is None
    assert unsign_value(KEY, None, now=1001) is None


def test_sign_expires() -> None:
    token = sign_value(KEY, {"p": "google"}, 60, now=1000)
    assert unsign_value(KEY, token, now=1059) is not None
    assert unsign_value(KEY, token, now=1061) is None


def test_pkce_matches_rfc7636_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_session_token_hash_is_stable_and_not_the_token() -> None:
    assert hash_session_token("abc") == hash_session_token("abc")
    assert hash_session_token("abc") != "abc"
    assert len(hash_session_token("abc")) == 64


def test_providers_only_when_fully_configured() -> None:
    assert configured_providers(make_settings()) == {}
    assert configured_providers(make_settings(google_client_id="id")) == {}
    both = make_settings(
        google_client_id="gid",
        google_client_secret="gsecret",
        github_client_id="hid",
        github_client_secret="hsecret",
    )
    assert set(configured_providers(both)) == {"google", "github"}


def test_authorize_url_contains_state_pkce_and_redirect() -> None:
    settings = make_settings(google_client_id="gid", google_client_secret="gsecret")
    config = configured_providers(settings)["google"]
    url = build_authorize_url(settings, config, "STATE123", "verifier-value")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert parsed.netloc == "accounts.google.com"
    assert query["state"] == ["STATE123"]
    assert query["client_id"] == ["gid"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [pkce_challenge("verifier-value")]
    assert query["redirect_uri"] == [redirect_uri(settings, "google")]
    assert redirect_uri(settings, "google") == "http://localhost:8019/api/v1/auth/google/callback"


def test_auth_key_changes_with_auth_secret() -> None:
    assert make_settings().auth_key() != make_settings(auth_secret="otra-clave-distinta").auth_key()
    assert len(make_settings().auth_key()) == 32


def test_order_view_includes_invoice_from_billing_task() -> None:
    from types import SimpleNamespace

    from app.auth import order_view

    order = SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        total_cents=5000,
        snapshot={"created_at": "2026-11-16T10:00:00Z", "items": [{"name": "Arc Mouse"}]},
    )
    task = SimpleNamespace(status="issued", invoice_id="inv_1", invoice_number="F001-0001")
    view = order_view(order, task)
    assert view["billing_status"] == "issued"
    assert view["invoice_number"] == "F001-0001"
    assert view["total_cents"] == 5000

    sin_factura = order_view(order, None)
    assert sin_factura["billing_status"] == "not_requested"
    assert sin_factura["invoice_number"] is None