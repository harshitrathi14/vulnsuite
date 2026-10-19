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
