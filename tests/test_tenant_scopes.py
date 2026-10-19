"""'Own assets only': public network targets must sit inside a scope bound
to the tenant; hostnames are resolved before the decision; unresolvable
names are refused instead of waved through.

Fixtures use genuinely public ranges: Python's ipaddress treats the RFC 5737
documentation nets (203.0.113.0/24 etc.) as private."""
from __future__ import annotations

import asyncio
import ipaddress
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vulnsuite.core.scopes import (
    ScopeError,
    TenantScope,
    authorize_root_domains,
    classify_host,
    split_host_port,
    under_roots,
)

DOMAIN = TenantScope(kind="domain", value="Example.com.")
NET = TenantScope(kind="network", value="185.199.108.0/22")
SCOPES = [DOMAIN, NET]


def _resolver(table: dict[str, list[str]]):
    async def resolve(host: str):
        return [ipaddress.ip_address(a) for a in table.get(host, [])]
    return resolve


def _classify(host, scopes=SCOPES, table=None):
    return asyncio.run(classify_host(host, scopes, _resolver(table or {})))


# ---------- scope validation ----------

def test_scope_values_are_normalized() -> None:
    assert DOMAIN.value == "example.com"
    assert TenantScope(kind="network", value="185.199.108.77/22").value == "185.199.108.0/22"
    assert TenantScope(kind="network", value="140.82.112.9").value == "140.82.112.9/32"


@pytest.mark.parametrize(
    "kind, value, reason",
    [
        ("domain", "10.0.0.1", "hostname"),
        ("domain", "localhost", "bare label"),
        ("domain", "--example.com", "command-line option"),
        ("network", "0.0.0.0/0", "default route"),
        ("network", "::/0", "default route"),
        ("network", "not-a-network", "CIDR"),
    ],
)
def test_scope_rejects_bad_values(kind, value, reason) -> None:
    with pytest.raises(ValidationError, match=reason):
        TenantScope(kind=kind, value=value)


# ---------- classification ----------

@pytest.mark.parametrize("host", ["10.1.2.3", "192.168.0.0/16", "127.0.0.1", "fd00::1"])
def test_private_literals_need_no_scope(host) -> None:
    assert _classify(host, scopes=[]) == "private"


def test_public_literal_inside_network_scope_is_scoped() -> None:
    assert _classify("185.199.108.9") == "scoped"
    assert _classify("185.199.108.0/26") == "scoped"


def test_public_literal_outside_scope_is_refused() -> None:
    with pytest.raises(ScopeError, match="not inside any network scope"):
        _classify("140.82.112.7")
    with pytest.raises(ScopeError):
        _classify("185.199.104.0/21")     # straddles the scope boundary


def test_hostname_under_domain_scope_is_scoped_without_dns() -> None:
    assert _classify("API.Example.com", table={}) == "scoped"


def test_hostname_resolving_private_is_private() -> None:
    assert _classify("db.internal", table={"db.internal": ["10.0.0.5"]}) == "private"


def test_hostname_resolving_public_outside_scope_is_refused() -> None:
    # This was the bypass: a hostname skipped the private-range check.
    with pytest.raises(ScopeError, match="140.82.112.7"):
        _classify("victim.net", table={"victim.net": ["140.82.112.7"]})


def test_hostname_resolving_into_network_scope_is_scoped() -> None:
    assert _classify("edge.other.org", table={"edge.other.org": ["185.199.108.40"]}) == "scoped"


def test_mixed_answers_require_every_public_address_in_scope() -> None:
    with pytest.raises(ScopeError):
        _classify("multi.org", table={"multi.org": ["185.199.108.40", "140.82.112.1"]})


def test_unresolvable_hostname_is_refused() -> None:
    with pytest.raises(ScopeError, match="does not resolve"):
        _classify("ghost.example.net", table={})


def test_split_host_port() -> None:
    assert split_host_port("api.example.com:8443") == "api.example.com"
    assert split_host_port("[2001:db8::1]:443") == "2001:db8::1"
    assert split_host_port("2001:db8::1") == "2001:db8::1"


# ---------- ASM roots ----------

def test_root_domains_must_be_inside_domain_scope() -> None:
    assert authorize_root_domains(["Example.com", "sub.example.com"], SCOPES) == ["example.com", "sub.example.com"]
    with pytest.raises(ScopeError, match=r"\['notexample.com'\]"):
        authorize_root_domains(["example.com", "notexample.com"], SCOPES)


def test_under_roots_filters_cname_strays() -> None:
    hosts = ["www.example.com", "example.com", "cdn.provider.net", "evil-example.com"]
    assert under_roots(hosts, ["example.com"]) == ["www.example.com", "example.com"]


# ---------- nmap collector resolves hostnames ----------

def _nmap(monkeypatch, table, **kwargs):
    from vulnsuite.collectors.network import nmap_passive
    monkeypatch.setattr(nmap_passive.shutil, "which", lambda b: "/usr/bin/nmap")
    return nmap_passive.NmapPassiveCollector(resolver=_resolver(table), **kwargs)


def test_nmap_refuses_hostname_resolving_to_public(monkeypatch) -> None:
    c = _nmap(monkeypatch, {"victim.net": ["140.82.112.7"]})
    with pytest.raises(PermissionError, match="public target"):
        asyncio.run(c._validate_target("victim.net"))


def test_nmap_refuses_unresolvable_hostname(monkeypatch) -> None:
    c = _nmap(monkeypatch, {})
    with pytest.raises(PermissionError, match="does not resolve"):
        asyncio.run(c._validate_target("ghost.example.net"))


def test_nmap_allows_private_and_authorised_public(monkeypatch) -> None:
    c = _nmap(monkeypatch, {"db.internal": ["10.0.0.5"]})
    asyncio.run(c._validate_target("db.internal"))
    asyncio.run(c._validate_target("10.0.0.0/24"))
    c = _nmap(monkeypatch, {"edge.example.com": ["185.199.108.4"]}, allow_public=True)
    asyncio.run(c._validate_target("edge.example.com"))


def test_nmap_scan_reports_refusal_as_error_not_crash(monkeypatch) -> None:
    c = _nmap(monkeypatch, {"victim.net": ["140.82.112.7"]})
    result = asyncio.run(c.scan("victim.net", uuid4(), uuid4()))
    assert result.findings == [] and "Refusing scan" in result.errors[0]


# ---------- worker gate ----------

def test_domain_discovery_refuses_unscoped_root(monkeypatch) -> None:
    from vulnsuite.workers import tasks

    async def fake_scopes(tenant_id):
        return [DOMAIN]

    monkeypatch.setattr(tasks, "load_scopes", fake_scopes)
    monkeypatch.setattr(tasks.settings.scanning, "offline_mode", False)
    with pytest.raises(ScopeError, match="victim.net"):
        tasks.discover_domains(str(uuid4()), ["victim.net"])
