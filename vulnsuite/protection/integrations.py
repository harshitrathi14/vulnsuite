"""Explicitly configured HTTPS delivery and bounded Cloudflare WAF response.

No network request is made by constructing a connector or preparing a plan.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from .response import allowed_ip


class IntegrationError(RuntimeError):
    """Fixed error category safe for audit storage (never an upstream body)."""

    def __init__(self, code: str, retryable: bool = False):
        self.code, self.retryable = code, retryable
        super().__init__(code)


def _secret(config: dict, key: str) -> str:
    name = config.get(key)
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError(f"{key} must name a secret environment variable")
    value = os.environ.get(name, "")
    if len(value) < 24 or "\r" in value or "\n" in value:
        raise ValueError(f"{key} is missing or too short")
    return value


def _client(transport=None):
    # Disallow redirects (credential forwarding) and environment proxy/TLS overrides.
    return httpx.Client(verify=True, follow_redirects=False, trust_env=False,
                        timeout=httpx.Timeout(15.0, connect=5.0), transport=transport)


def _request(client, method, url, **kwargs):
    try:
        response = client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise IntegrationError("transport_error", retryable=True) from exc
    if response.status_code == 429 or response.status_code >= 500:
        raise IntegrationError("upstream_unavailable", retryable=True)
    if not 200 <= response.status_code < 300:
        raise IntegrationError("upstream_rejected")
    return response


class WebhookConnector:
    """Vendor-neutral SIEM/ticket bridge using signed JSON and idempotency keys."""

    def __init__(self, config: dict, *, transport=None):
        self.config, self.transport = dict(config), transport
        url = self.config.get("url", "")
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or parsed.query):
            raise ValueError("webhook must be a configured HTTPS URL without credentials/query")
        self.url = url
        self.token = _secret(config, "token_env")
        self.signing_key = _secret(config, "signing_key_env")

    def deliver(self, payload: dict, delivery_id: str) -> dict:
        UUID(delivery_id)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode()
        if len(body) > 262144:
            raise IntegrationError("payload_too_large")
        stamp = str(int(time.time()))
        signature = hmac.new(self.signing_key.encode(), stamp.encode() + b"." + body,
                             hashlib.sha256).hexdigest()
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                   "Idempotency-Key": delivery_id, "X-VulnSuite-Timestamp": stamp,
                   "X-VulnSuite-Signature": f"v1={signature}"}
        with _client(self.transport) as client:
            response = _request(client, "POST", self.url, content=body, headers=headers)
        return {"status": "delivered", "http_status": response.status_code}


class CloudflareWAFConnector:
    """Zone custom rules with an expiry expression evaluated at Cloudflare's edge.

The configured ruleset must be the zone http_request_firewall_custom entry point.
An unavailable cleanup worker cannot extend the rule's fixed expiry.
"""

    def __init__(self, config: dict, *, transport=None):
        self.config, self.transport = dict(config), transport
        for key in ("zone_id", "ruleset_id"):
            if not re.fullmatch(r"[a-f0-9]{32}", str(config.get(key, ""))):
                raise ValueError(f"invalid {key}")
        if not config.get("permitted_networks"):
            raise ValueError("explicit permitted_networks required")
        self.token = _secret(config, "token_env")
        self.base = ("https://api.cloudflare.com/client/v4/zones/" + config["zone_id"]
                     + "/rulesets/" + config["ruleset_id"])

    def prepare_block(self, ip: str, duration: int, request_id: str, now=None) -> dict:
        if isinstance(duration, bool) or not isinstance(duration, int) or not 60 <= duration <= 3600:
            raise ValueError("duration must be 60..3600 seconds")
        identifier = str(UUID(request_id))
        address = allowed_ip(ip, self.config.get("protected_networks", []),
                             self.config["permitted_networks"])
        created = int(time.time() if now is None else now)
        return {"provider": "cloudflare", "request_id": identifier,
                "zone_id": self.config["zone_id"], "ruleset_id": self.config["ruleset_id"],
                "ip": address, "created_at": created, "expires_at": created + duration,
                "ref": "vulnsuite_" + UUID(identifier).hex}

    def _validate(self, plan: dict) -> tuple[str, str]:
        for key in ("zone_id", "ruleset_id"):
            if plan.get(key) != self.config[key]:
                raise IntegrationError("scope_mismatch")
        if plan.get("provider") != "cloudflare":
            raise IntegrationError("scope_mismatch")
        ref = "vulnsuite_" + UUID(plan["request_id"]).hex
        if plan.get("ref") != ref:
            raise IntegrationError("invalid_reference")
        start, end = plan["created_at"], plan["expires_at"]
        if type(start) is not int or type(end) is not int or not 60 <= end - start <= 3600:
            raise IntegrationError("invalid_expiry")
        ip = allowed_ip(plan["ip"], self.config.get("protected_networks", []),
                        self.config["permitted_networks"])
        return ref, f"(ip.src eq {ip} and http.request.timestamp.sec lt {end})"

    def _api(self, client, method, suffix="", **kwargs) -> dict[str, Any]:
        response = _request(client, method, self.base + suffix,
                            headers={"Authorization": f"Bearer {self.token}"}, **kwargs)
        try:
            data = response.json()
            if data.get("success") is not True or not isinstance(data.get("result"), dict):
                raise ValueError("bad envelope")
            return data["result"]
        except (ValueError, AttributeError) as exc:
            raise IntegrationError("invalid_upstream_response", retryable=True) from exc

    def _find(self, client, ref, expression):
        ruleset = self._api(client, "GET")
        if (ruleset.get("id") != self.config["ruleset_id"]
                or ruleset.get("phase") != "http_request_firewall_custom"
                or ruleset.get("kind") != "zone"):
            raise IntegrationError("ruleset_not_zone_entrypoint")
        found = [r for r in ruleset.get("rules", []) if r.get("ref") == ref]
        if len(found) > 1:
            raise IntegrationError("duplicate_reference")
        if found and (found[0].get("expression") != expression
                      or found[0].get("action") != "block"
                      or found[0].get("enabled") is not True):
            raise IntegrationError("rule_changed_externally")
        if found and not re.fullmatch(r"[a-f0-9]{32}", str(found[0].get("id", ""))):
            raise IntegrationError("invalid_upstream_response")
        return found[0] if found else None

    def apply(self, plan: dict) -> dict:
        ref, expression = self._validate(plan)
        if plan["created_at"] > time.time() + 30:
            raise IntegrationError("future_plan")
        if plan["expires_at"] <= time.time():
            raise IntegrationError("plan_expired")
        with _client(self.transport) as client:
            rule = self._find(client, ref, expression)
            if rule is None:
                # Never replace a ruleset: this appends one independently owned rule.
                self._api(client, "POST", "/rules", json={"action": "block",
                          "expression": expression, "enabled": True, "ref": ref,
                          "description": "VulnSuite temporary response " + plan["request_id"]})
                rule = self._find(client, ref, expression)
            if rule is None:
                raise IntegrationError("rule_not_confirmed", retryable=True)
        return {"status": "applied", "provider": "cloudflare", "rule_id": rule["id"],
                "ref": ref, "expires_at": plan["expires_at"]}

    def rollback(self, plan: dict) -> dict:
        ref, expression = self._validate(plan)
        with _client(self.transport) as client:
            rule = self._find(client, ref, expression)
            if rule:
                self._api(client, "DELETE", "/rules/" + rule["id"])
        return {"status": "rolled_back", "ref": ref, "expires_at": plan["expires_at"]}


_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_UPN = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}$")
IDENTITY_ACTIONS = ("identity_revoke_sessions", "identity_disable_account")


def normalise_upn(user: str, default_domain: str | None) -> str:
    """Turn evidence ('CORP\\alice', 'alice', 'alice@corp.example') into a lowercase UPN."""
    if not isinstance(user, str) or not 1 <= len(user) <= 320 or any(ord(c) < 33 for c in user):
        raise ValueError("invalid user evidence")
    name = user.rsplit("\\", 1)[-1]
    if "@" not in name:
        if not default_domain:
            raise ValueError("user has no domain and no upn_domain is configured")
        name = f"{name}@{default_domain}"
    name = name.lower()
    if not _UPN.fullmatch(name):
        raise ValueError("invalid user principal name")
    return name


class EntraIDConnector:
    """Approved, bounded account response in Microsoft Entra ID through Graph.

    Two actions: revoke every refresh token and session of a user
    (one-shot) or disable sign-in for a fixed window, re-enabled by the worker at
    expiry. The application credential needs only User.ReadWrite.All (disable) or
    User.RevokeSessions.All (revoke) application permissions; limit it with an
    administrative unit in Entra where possible. Users listed in protected_users
    (break-glass and service accounts) and users outside allowed_domains are
    never acted on. Constructing the connector or preparing a plan sends nothing.
    """

    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self, config: dict, *, transport=None):
        self.config, self.transport = dict(config), transport
        for key in ("tenant_id", "client_id"):
            if not re.fullmatch(_GUID, str(config.get(key, ""))):
                raise ValueError(f"invalid {key}")
        domains = config.get("allowed_domains")
        if not isinstance(domains, list) or not domains or any(
                not isinstance(d, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", d) for d in domains):
            raise ValueError("explicit allowed_domains required")
        self.domains = {d.lower() for d in domains}
        protected = config.get("protected_users", [])
        if not isinstance(protected, list) or len(protected) > 1000:
            raise ValueError("protected_users must be a list")
        self.protected = {normalise_upn(p, None) for p in protected}
        self.secret = _secret(config, "client_secret_env")
        self.token_url = (f"https://login.microsoftonline.com/{config['tenant_id'].lower()}"
                          "/oauth2/v2.0/token")

    def _permitted(self, upn: str) -> str:
        if upn in self.protected:
            raise ValueError("user is protected by policy")
        if upn.rsplit("@", 1)[1] not in self.domains:
            raise ValueError("user domain outside response policy")
        return upn

    def prepare(self, action: str, user: str, duration: int, request_id: str, now=None) -> dict:
        if action not in IDENTITY_ACTIONS:
            raise ValueError("unsupported identity action")
        if isinstance(duration, bool) or not isinstance(duration, int) or not 60 <= duration <= 3600:
            raise ValueError("duration must be 60..3600 seconds")
        identifier = str(UUID(request_id))
        upn = self._permitted(normalise_upn(user, self.config.get("upn_domain")))
        created = int(time.time() if now is None else now)
        # Revocation is one-shot: expires_at is only its dispatch deadline.
        return {"provider": "entra_id", "action": action, "request_id": identifier,
                "tenant_id": self.config["tenant_id"].lower(), "user": upn,
                "created_at": created, "expires_at": created + duration,
                "ref": "vulnsuite_" + UUID(identifier).hex}

    def _validate(self, plan: dict) -> dict:
        if plan.get("provider") != "entra_id" or plan.get("tenant_id") != self.config["tenant_id"].lower():
            raise IntegrationError("scope_mismatch")
        if plan.get("action") not in IDENTITY_ACTIONS:
            raise IntegrationError("scope_mismatch")
        if plan.get("ref") != "vulnsuite_" + UUID(plan["request_id"]).hex:
            raise IntegrationError("invalid_reference")
        start, end = plan["created_at"], plan["expires_at"]
        if type(start) is not int or type(end) is not int or not 60 <= end - start <= 3600:
            raise IntegrationError("invalid_expiry")
        try:
            self._permitted(normalise_upn(plan["user"], None))
        except ValueError as exc:
            raise IntegrationError("scope_mismatch") from exc
        return plan

    def _token(self, client) -> str:
        response = _request(client, "POST", self.token_url, data={
            "client_id": self.config["client_id"], "client_secret": self.secret,
            "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
        try:
            token = response.json()["access_token"]
            if not isinstance(token, str) or not token:
                raise ValueError("empty token")
            return token
        except (ValueError, KeyError, AttributeError) as exc:
            raise IntegrationError("invalid_upstream_response", retryable=True) from exc

    def _user(self, client, token: str, upn: str) -> dict:
        from urllib.parse import quote
        response = _request(client, "GET", f"{self.GRAPH}/users/{quote(upn, safe='')}",
                            params={"$select": "id,userPrincipalName,accountEnabled"},
                            headers={"Authorization": f"Bearer {token}"})
        try:
            data = response.json()
            if (normalise_upn(data["userPrincipalName"], None) != upn
                    or not re.fullmatch(_GUID, str(data.get("id", "")))):
                raise IntegrationError("scope_mismatch")
            return {"id": data["id"], "enabled": data.get("accountEnabled")}
        except (ValueError, KeyError, AttributeError, TypeError) as exc:
            raise IntegrationError("invalid_upstream_response", retryable=True) from exc

    def apply(self, plan: dict) -> dict:
        plan = self._validate(plan)
        if plan["created_at"] > time.time() + 30:
            raise IntegrationError("future_plan")
        if plan["expires_at"] <= time.time():
            raise IntegrationError("plan_expired")
        with _client(self.transport) as client:
            token = self._token(client)
            user = self._user(client, token, plan["user"])
            headers = {"Authorization": f"Bearer {token}"}
            if plan["action"] == "identity_revoke_sessions":
                _request(client, "POST", f"{self.GRAPH}/users/{user['id']}/revokeSignInSessions", headers=headers)
                detail = "sessions_revoked"
            else:
                if user["enabled"] is False:
                    # Already disabled by someone else: never claim ownership of that state.
                    raise IntegrationError("account_already_disabled")
                _request(client, "PATCH", f"{self.GRAPH}/users/{user['id']}",
                         json={"accountEnabled": False}, headers=headers)
                detail = "account_disabled"
        return {"status": "applied", "provider": "entra_id", "detail": detail, "user": plan["user"],
                "object_id": user["id"], "ref": plan["ref"], "expires_at": plan["expires_at"]}

    def rollback(self, plan: dict) -> dict:
        plan = self._validate(plan)
        if plan["action"] != "identity_disable_account":
            return {"status": "rolled_back", "provider": "entra_id", "detail": "nothing_to_rollback",
                    "user": plan["user"], "ref": plan["ref"], "expires_at": plan["expires_at"]}
        with _client(self.transport) as client:
            token = self._token(client)
            user = self._user(client, token, plan["user"])
            if user["enabled"] is not True:
                _request(client, "PATCH", f"{self.GRAPH}/users/{user['id']}",
                         json={"accountEnabled": True}, headers={"Authorization": f"Bearer {token}"})
        return {"status": "rolled_back", "provider": "entra_id", "detail": "account_enabled",
                "user": plan["user"], "object_id": user["id"], "ref": plan["ref"],
                "expires_at": plan["expires_at"]}
