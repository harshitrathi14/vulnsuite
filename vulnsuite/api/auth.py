"""External identity provider access-token verification and tenant-bound RBAC.

Only a configured issuer's public JWKS is trusted. No unsigned/development
fallback, shared signing secrets, or token-controlled discovery is supported.
"""
from __future__ import annotations

import asyncio
import json
import time
from functools import lru_cache
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from fastapi import Depends, Header, HTTPException, Request
from jose import jwk, jwt
from jose.exceptions import JOSEError
from pydantic import BaseModel, ConfigDict

from ..core.config import AuthSettings, get_settings

ROLES = frozenset({"admin", "analyst", "viewer", "auditor"})
MAX_JWKS_BYTES = 1024 * 1024


class AuthenticationError(ValueError):
    """Credentials cannot be authenticated; callers must deny the request."""


class AuthConfigurationError(ValueError):
    """Operator configuration is missing or unsafe."""


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)
    sub: str
    tenant_id: UUID
    roles: frozenset[str]
    email: str | None = None

    def has_role(self, *allowed: str) -> bool:
        return bool(self.roles.intersection(allowed))


def _https_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not parsed.fragment)
    except ValueError:
        return False


def _claim(claims: dict, path: str):
    value = claims
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise AuthenticationError("required access-token claim missing")
        value = value[part]
    return value


class JWTVerifier:
    """Reusable verifier. Call ``await verify(token, expected_tenant=...)``.

    Public keys expire from the cache even if the issuer becomes unavailable.
    Unknown key IDs do not trigger extra network requests within the cache TTL,
    limiting attacker-induced fetches. Publish rotation keys before using them.
    """

    def __init__(self, settings: AuthSettings):
        self.settings = settings.model_copy(deep=True)
        if not settings.oidc_issuer or not _https_url(settings.oidc_issuer):
            raise AuthConfigurationError("an HTTPS OIDC issuer is required")
        if not settings.oidc_audience or not settings.oidc_audience.strip():
            raise AuthConfigurationError("a dedicated API audience is required")
        if bool(settings.jwks_url) == bool(settings.jwks_path):
            raise AuthConfigurationError("configure exactly one trusted JWKS source")
        if settings.jwks_url and not _https_url(settings.jwks_url):
            raise AuthConfigurationError("JWKS URL must use HTTPS without credentials or fragments")
        if (not settings.jwt_algorithms
                or not set(settings.jwt_algorithms).issubset({"RS256", "ES256"})):
            raise AuthConfigurationError("only RS256 and ES256 verification are supported")
        for name in (settings.tenant_claim, settings.roles_claim):
            if not name or len(name) > 256 or any(not part for part in name.split(".")):
                raise AuthConfigurationError("claim paths must be nonempty dot-separated names")
        self._keys: list[dict] = []
        self._loaded_at = float("-inf")
        self._lock = asyncio.Lock()

    async def _load_keys(self) -> list[dict]:
        async with self._lock:
            if time.monotonic() - self._loaded_at < self.settings.jwks_cache_seconds:
                return self._keys
            # Clear before a refresh so a failed refresh cannot extend trust.
            self._keys = []
            try:
                if self.settings.jwks_path:
                    with self.settings.jwks_path.open("rb") as stream:
                        raw = stream.read(MAX_JWKS_BYTES + 1)
                else:
                    async with httpx.AsyncClient(
                        timeout=self.settings.jwks_timeout_seconds,
                        follow_redirects=False, trust_env=False,
                    ) as client:
                        async with client.stream("GET", self.settings.jwks_url) as response:
                            response.raise_for_status()
                            chunks = bytearray()
                            async for chunk in response.aiter_bytes():
                                chunks.extend(chunk)
                                if len(chunks) > MAX_JWKS_BYTES:
                                    raise ValueError("oversized JWKS")
                            raw = bytes(chunks)
                if len(raw) > MAX_JWKS_BYTES:
                    raise ValueError("oversized JWKS")
                document = json.loads(raw)
                keys = document.get("keys") if isinstance(document, dict) else None
                if (not isinstance(keys, list) or not 1 <= len(keys) <= 100
                        or not all(isinstance(key, dict) for key in keys)):
                    raise ValueError("invalid JWKS")
                # Private material must never be configured for verification.
                if any({"d", "p", "q", "dp", "dq", "qi", "k"}.intersection(key) for key in keys):
                    raise ValueError("JWKS contains private or symmetric key material")
                self._keys = keys
                self._loaded_at = time.monotonic()
                return keys
            except (OSError, ValueError, httpx.HTTPError):
                # A brief negative cache also prevents outages causing fetch storms.
                self._loaded_at = time.monotonic()
                raise AuthenticationError("trusted signing keys unavailable") from None

    async def verify(self, token: str, expected_tenant: UUID | str | None = None) -> Principal:
        if not isinstance(token, str) or not 1 <= len(token) <= 16384:
            raise AuthenticationError("invalid access token")
        try:
            header = jwt.get_unverified_header(token)
            alg, kid = header.get("alg"), header.get("kid")
            if (not isinstance(alg, str) or alg not in self.settings.jwt_algorithms
                    or not isinstance(kid, str) or not 1 <= len(kid) <= 256
                    or header.get("crit") or header.get("b64") is False
                    or any(name in header for name in ("jku", "jwk", "x5u"))
                    or header.get("typ", "JWT").lower() not in {"jwt", "at+jwt"}):
                raise AuthenticationError("unsupported access-token header")
            candidates = [key for key in await self._load_keys()
                          if key.get("kid") == kid]
            if len(candidates) != 1:
                raise AuthenticationError("unknown or ambiguous signing key")
            key = candidates[0]
            expected_type = "RSA" if alg == "RS256" else "EC"
            if (key.get("kty") != expected_type or key.get("use", "sig") != "sig"
                    or key.get("alg", alg) != alg
                    or ("key_ops" in key and key["key_ops"] != ["verify"])):
                raise AuthenticationError("signing key not permitted for this algorithm")
            public_key = jwk.construct(key, algorithm=alg)
            if alg == "RS256" and public_key.prepared_key.key_size < 2048:
                raise AuthenticationError("RSA signing key too small")
            if alg == "ES256" and key.get("crv") != "P-256":
                raise AuthenticationError("unsupported elliptic curve")
            claims = jwt.decode(
                token, public_key, algorithms=[alg],
                audience=self.settings.oidc_audience, issuer=self.settings.oidc_issuer,
                options={"require_exp": True, "require_iat": True, "require_sub": True,
                         "require_iss": True, "require_aud": True,
                         "leeway": self.settings.clock_skew_seconds},
            )
            now, skew = time.time(), self.settings.clock_skew_seconds
            for name in ("exp", "iat", "nbf"):
                if name in claims and type(claims[name]) is not int:
                    raise AuthenticationError("invalid token time claim")
            if (claims["iat"] > now + skew or claims["exp"] <= claims["iat"]
                    or claims["exp"] - claims["iat"] > self.settings.max_token_lifetime_seconds):
                raise AuthenticationError("access-token lifetime is not permitted")
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
                raise AuthenticationError("invalid subject")
            tenant = _claim(claims, self.settings.tenant_claim)
            if not isinstance(tenant, str):
                raise AuthenticationError("invalid signed tenant")
            tenant_id = UUID(tenant)
            if expected_tenant is not None and tenant_id != UUID(str(expected_tenant)):
                raise AuthenticationError("tenant does not match signed identity")
            role_claim = _claim(claims, self.settings.roles_claim)
            if isinstance(role_claim, str):
                role_claim = [role_claim]
            if (not isinstance(role_claim, list) or not role_claim
                    or not all(isinstance(role, str) and role in ROLES for role in role_claim)):
                raise AuthenticationError("no valid application roles")
            email = claims.get("email")
            return Principal(sub=subject, tenant_id=tenant_id, roles=frozenset(role_claim),
                             email=email if isinstance(email, str) else None)
        except AuthenticationError:
            raise
        except (JOSEError, ValueError, TypeError, AttributeError, KeyError):
            raise AuthenticationError("invalid access token") from None


@lru_cache(maxsize=1)
def get_verifier() -> JWTVerifier:
    return JWTVerifier(get_settings().auth)


async def _authenticate(
    authorization: Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    if not x_tenant_id:
        raise HTTPException(400, "missing X-Tenant-Id header")
    try:
        tenant_id = UUID(x_tenant_id)
    except ValueError:
        raise HTTPException(400, "invalid X-Tenant-Id header") from None
    try:
        return await get_verifier().verify(authorization[7:], expected_tenant=tenant_id)
    except AuthConfigurationError:
        raise HTTPException(503, "identity provider is not configured") from None
    except AuthenticationError:
        raise HTTPException(401, "invalid access token", headers={"WWW-Authenticate": "Bearer"}) from None


async def get_principal(
    request: Request, p: Principal = Depends(_authenticate),
) -> Principal:
    """Authenticated principal, also exposed on `request.state.principal`
    so the audit middleware can attribute the call (api/audit.py)."""
    request.state.principal = p
    return p


def require_role(*allowed: str):
    if not allowed or not set(allowed).issubset(ROLES):
        raise ValueError("unknown role policy")

    def _check(p: Principal = Depends(get_principal)) -> Principal:
        if not p.has_role(*allowed):
            raise HTTPException(403, "insufficient application role")
        return p

    return _check
