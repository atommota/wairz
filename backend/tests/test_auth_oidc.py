"""Tests for the OIDC/JWT bearer auth (app/auth/oidc.py)."""

import time
import types

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth import oidc
from app.auth.oidc import AuthError, OIDCVerifier, auth_guard

ISSUER = "https://issuer.example.com"
AUD = "client-123"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _verifier(keypair, audience=AUD):
    _, pub = keypair
    v = OIDCVerifier(ISSUER, audience)
    # Bypass the network JWKS fetch — always resolve to our public key.
    v._jwk_client = types.SimpleNamespace(
        get_signing_key_from_jwt=lambda token: types.SimpleNamespace(key=pub)
    )
    return v


def _token(keypair, **claims):
    priv, _ = keypair
    payload = {"iss": ISSUER, "exp": int(time.time()) + 3600, "sub": "u1"}
    payload.update(claims)
    return jwt.encode(payload, priv, algorithm="RS256")


# --- verifier ---------------------------------------------------------------
def test_cognito_style_access_token_ok(keypair):
    # Cognito access tokens carry client_id (not aud).
    claims = _verifier(keypair).verify(_token(keypair, client_id=AUD, token_use="access"))
    assert claims["sub"] == "u1"


def test_generic_aud_claim_ok(keypair):
    assert _verifier(keypair).verify(_token(keypair, aud=AUD))["sub"] == "u1"


def test_aud_list_ok(keypair):
    assert _verifier(keypair).verify(_token(keypair, aud=["other", AUD]))["sub"] == "u1"


def test_audience_mismatch_rejected(keypair):
    with pytest.raises(AuthError):
        _verifier(keypair).verify(_token(keypair, client_id="someone-else"))


def test_wrong_issuer_rejected(keypair):
    with pytest.raises(AuthError):
        _verifier(keypair).verify(_token(keypair, iss="https://evil.example.com", client_id=AUD))


def test_expired_rejected(keypair):
    with pytest.raises(AuthError):
        _verifier(keypair).verify(_token(keypair, client_id=AUD, exp=int(time.time()) - 10))


def test_bad_signature_rejected(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = jwt.encode(
        {"iss": ISSUER, "exp": int(time.time()) + 3600, "client_id": AUD},
        other, algorithm="RS256",
    )
    with pytest.raises(AuthError):
        _verifier(keypair).verify(tok)


def test_no_audience_configured_accepts_any(keypair):
    assert _verifier(keypair, audience="").verify(_token(keypair))["sub"] == "u1"


# --- get_verifier gating ----------------------------------------------------
def test_get_verifier_none_when_disabled(monkeypatch):
    monkeypatch.setattr(oidc, "get_settings",
                        lambda: types.SimpleNamespace(auth_enabled=False))
    oidc.get_verifier.cache_clear()
    assert oidc.get_verifier() is None
    oidc.get_verifier.cache_clear()


def test_get_verifier_raises_without_issuer(monkeypatch):
    monkeypatch.setattr(oidc, "get_settings", lambda: types.SimpleNamespace(
        auth_enabled=True, oidc_issuer="", oidc_audience="", oidc_jwks_url=""))
    oidc.get_verifier.cache_clear()
    with pytest.raises(RuntimeError):
        oidc.get_verifier()
    oidc.get_verifier.cache_clear()


# --- middleware (throwaway app, no DB) --------------------------------------
def _guarded_app():
    app = FastAPI()
    app.middleware("http")(auth_guard)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/api/v1/thing")
    def thing():
        return {"thing": True}

    return TestClient(app)


def test_middleware_passthrough_when_disabled(monkeypatch):
    monkeypatch.setattr(oidc, "get_verifier", lambda: None)
    assert _guarded_app().get("/api/v1/thing").status_code == 200


def test_middleware_enforces_when_enabled(monkeypatch):
    stub = types.SimpleNamespace(verify=lambda t: {"sub": "u"} if t == "good"
                                 else (_ for _ in ()).throw(AuthError("bad")))
    monkeypatch.setattr(oidc, "get_verifier", lambda: stub)
    client = _guarded_app()
    assert client.get("/health").status_code == 200                          # allowlisted
    assert client.get("/api/v1/thing").status_code == 401                     # no token
    assert client.get("/api/v1/thing",
                      headers={"Authorization": "Bearer bad"}).status_code == 401
    assert client.get("/api/v1/thing",
                      headers={"Authorization": "Bearer good"}).status_code == 200
