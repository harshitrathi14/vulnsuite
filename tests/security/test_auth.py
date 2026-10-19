"""Cryptographic adversarial tests and API dependency authorization boundaries."""
import json
import time
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwk, jwt

from vulnsuite.api import auth
from vulnsuite.api.auth import AuthenticationError, AuthConfigurationError, JWTVerifier
from vulnsuite.core.config import AuthSettings

TENANT = "00000000-0000-0000-0000-000000000001"
ISSUER = "https://identity.example.org/realms/security"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def setup_auth(tmp_path, key):
    public = jwk.construct(key.public_key(), "RS256").to_dict()
    public.update(kid="signing-1", alg="RS256", use="sig", key_ops=["verify"])
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [public]}))
    settings = AuthSettings(oidc_issuer=ISSUER, jwks_path=path, clock_skew_seconds=0)
    return JWTVerifier(settings), path, public


def token(key, *, remove=(), headers=None, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": "vulnsuite-api", "sub": "person-123",
              "iat": now, "exp": now + 300, "tenant_id": TENANT, "roles": ["analyst"]}
    claims.update(overrides)
    for field in remove:
        claims.pop(field, None)
    return jwt.encode(claims, key, algorithm="RS256", headers=headers or {"kid": "signing-1"})


@pytest.mark.asyncio
async def test_valid_signed_identity_and_multiple_roles(setup_auth, key):
    verifier, _, _ = setup_auth
    principal = await verifier.verify(token(key, roles=["viewer", "analyst"]), TENANT)
    assert principal.sub == "person-123"
    assert str(principal.tenant_id) == TENANT
    assert principal.has_role("admin", "analyst")
    assert not principal.has_role("admin")


@pytest.mark.asyncio
@pytest.mark.parametrize("overrides", [
    {"iss": "https://untrusted.example.org"}, {"aud": "another-api"},
    {"exp": int(time.time()) - 60}, {"iat": int(time.time()) + 90},
    {"nbf": int(time.time()) + 90}, {"exp": int(time.time()) + 100000},
    {"iat": True}, {"exp": str(int(time.time()) + 300)}, {"sub": ""},
    {"tenant_id": "arbitrary-tenant"}, {"tenant_id": 42},
    {"roles": ["superuser"]}, {"roles": []}, {"roles": None},
    {"roles": ["viewer", "root"]}, {"roles": {"admin": True}},
])
async def test_invalid_signed_claims_are_rejected(setup_auth, key, overrides):
    verifier, _, _ = setup_auth
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key, **overrides))


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "aud", "sub", "tenant_id", "roles"])
async def test_required_claim_cannot_be_omitted(setup_auth, key, claim):
    with pytest.raises(AuthenticationError):
        await setup_auth[0].verify(token(key, remove=[claim]))


@pytest.mark.asyncio
async def test_forged_signature_and_other_tenant_rejected(setup_auth, key):
    verifier, _, _ = setup_auth
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(attacker))
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key), str(uuid4()))


@pytest.mark.asyncio
@pytest.mark.parametrize("header", [
    {"kid": "unknown"}, {"kid": "signing-1", "jku": "https://attacker.example/keys"},
    {"kid": "signing-1", "jwk": {"kty": "RSA"}},
    {"kid": "signing-1", "x5u": "https://attacker.example/cert"},
    {"kid": "signing-1", "crit": ["extension"]}, {"kid": "signing-1", "typ": "id_token"},
])
async def test_untrusted_key_selectors_and_headers_rejected(setup_auth, key, header):
    with pytest.raises(AuthenticationError):
        await setup_auth[0].verify(token(key, headers=header))


@pytest.mark.asyncio
async def test_unsigned_and_symmetric_tokens_rejected(setup_auth):
    verifier, _, _ = setup_auth
    forged = jwt.encode({"sub": "admin"}, "attacker-secret", algorithm="HS256",
                        headers={"kid": "signing-1"})
    for credential in (forged, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", "random", "x" * 17000):
        with pytest.raises(AuthenticationError):
            await verifier.verify(credential)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"alg": "RS512"}, {"use": "enc"}, {"key_ops": ["sign"]}, {"n": "invalid"},
    {"d": "private-material"},
])
async def test_invalid_keys_fail_closed(setup_auth, key, change):
    verifier, path, public = setup_auth
    public.update(change)
    path.write_text(json.dumps({"keys": [public]}))
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key))


@pytest.mark.asyncio
async def test_duplicate_key_ids_rejected(setup_auth, key):
    verifier, path, public = setup_auth
    path.write_text(json.dumps({"keys": [public, public]}))
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key))


@pytest.mark.asyncio
async def test_es256_and_nested_role_claim_supported(tmp_path):
    private = ec.generate_private_key(ec.SECP256R1())
    public = jwk.construct(private.public_key(), "ES256").to_dict()
    public["kid"] = "ec-1"
    path = tmp_path / "ec.json"
    path.write_text(json.dumps({"keys": [public]}))
    verifier = JWTVerifier(AuthSettings(
        oidc_issuer=ISSUER, jwks_path=path, jwt_algorithms=["ES256"],
        roles_claim="realm_access.roles", tenant_claim="tid"))
    now = int(time.time())
    credential = jwt.encode({"iss": ISSUER, "aud": "vulnsuite-api", "iat": now,
                             "exp": now + 300, "sub": "operator", "tid": TENANT,
                             "realm_access": {"roles": ["admin"]}}, private,
                            algorithm="ES256", headers={"kid": "ec-1"})
    assert (await verifier.verify(credential)).has_role("admin")


@pytest.mark.parametrize("overrides", [
    {}, {"oidc_issuer": "http://identity.example.org", "jwks_url": "https://identity.example/keys"},
    {"oidc_issuer": ISSUER}, {"oidc_issuer": ISSUER, "jwks_url": "http://identity.example/keys"},
    {"oidc_issuer": ISSUER, "jwks_url": "https://user:password@identity.example/keys"},
    {"oidc_issuer": ISSUER, "jwks_url": "https://identity.example/keys", "jwks_path": "/keys"},
    {"oidc_issuer": ISSUER, "jwks_path": "/keys", "jwt_algorithms": ["HS256"]},
])
def test_missing_or_unsafe_configuration_rejected(overrides):
    with pytest.raises(AuthConfigurationError):
        JWTVerifier(AuthSettings(**overrides))


@pytest.mark.asyncio
async def test_remote_jwks_is_pinned_cached_and_expires(setup_auth, key, monkeypatch):
    _, _, public = setup_auth
    calls = []
    def response(request):
        calls.append(str(request.url))
        if len(calls) > 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"keys": [public]})
    original = httpx.AsyncClient
    def client(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return original(transport=httpx.MockTransport(response), **kwargs)
    monkeypatch.setattr(auth.httpx, "AsyncClient", client)
    verifier = JWTVerifier(AuthSettings(oidc_issuer=ISSUER, jwks_url="https://identity.example/keys"))
    await verifier.verify(token(key))
    await verifier.verify(token(key))
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key, headers={"kid": "unknown"}))
    assert calls == ["https://identity.example/keys"]
    verifier._loaded_at -= 3601
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key))
    # Refresh failure must not leave a usable stale key in the cache.
    with pytest.raises(AuthenticationError):
        await verifier.verify(token(key))
    assert len(calls) == 2


def test_http_role_and_tenant_boundaries(setup_auth, key, monkeypatch):
    monkeypatch.setattr(auth, "get_verifier", lambda: setup_auth[0])
    app = FastAPI()
    @app.get("/read")
    def read(principal=Depends(auth.get_principal)):
        return {"tenant_id": str(principal.tenant_id)}
    @app.post("/admin")
    def admin(principal=Depends(auth.require_role("admin"))):
        return {"subject": principal.sub}
    client = TestClient(app)
    headers = {"Authorization": "Bearer " + token(key, roles=["viewer"]), "X-Tenant-Id": TENANT}
    assert client.get("/read", headers=headers).status_code == 200
    assert client.post("/admin", headers=headers).status_code == 403
    admin_headers = {**headers, "Authorization": "Bearer " + token(key, roles=["admin"])}
    assert client.post("/admin", headers=admin_headers).status_code == 200
    assert client.get("/read", headers={**headers, "X-Tenant-Id": str(uuid4())}).status_code == 401
    assert client.get("/read", headers={**headers, "X-Tenant-Id": "malformed"}).status_code == 400
    assert client.get("/read", headers={"Authorization": headers["Authorization"]}).status_code == 400
    assert client.get("/read").status_code == 401
    assert client.get("/read", headers={**headers, "Authorization": "Bearer arbitrary"}).status_code == 401


def test_unconfigured_api_never_accepts_bearer_string(monkeypatch):
    def no_config():
        raise AuthConfigurationError("not configured")
    monkeypatch.setattr(auth, "get_verifier", no_config)
    app = FastAPI()
    @app.get("/read")
    def read(principal=Depends(auth.get_principal)):
        return {"subject": principal.sub}
    response = TestClient(app).get("/read", headers={"Authorization": "Bearer arbitrary", "X-Tenant-Id": TENANT})
    assert response.status_code == 503


def test_main_api_uses_verified_identity_for_real_routes(setup_auth, key, monkeypatch):
    from vulnsuite.api import main

    monkeypatch.setattr(auth, "get_verifier", lambda: setup_auth[0])
    assert main.get_principal is auth.get_principal
    assert main.require_role is auth.require_role
    client = TestClient(main.app)
    headers = {"Authorization": "Bearer " + token(key, roles=["viewer"]), "X-Tenant-Id": TENANT}
    # These reject in authentication/authorization before DB/worker access.
    assert client.post("/api/v1/discover/azure", headers=headers).status_code == 403
    assert client.get("/api/v1/assets", headers={**headers, "X-Tenant-Id": str(uuid4())}).status_code == 401
    assert client.get("/api/v1/assets", headers={**headers, "Authorization": "Bearer arbitrary"}).status_code == 401
