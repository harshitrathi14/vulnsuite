"""
VulnSuite - Per-tenant target scopes ("own assets only")

The passive-scanning promise only holds if a tenant can scan what it
owns. Private address space is treated as owned by definition. Anything
public — an IP, a CIDR, or a hostname that resolves to one — must fall
inside a *scope* an admin has bound to the tenant:

  domain   example.com        -> example.com and every subdomain
  network  203.0.113.0/24     -> any address or sub-range inside it

Hostnames are resolved before the decision; an unresolvable name is
refused rather than waved through (that was the bypass: the old check
only looked at IP literals). `classify_host` is pure given a resolver,
so it is unit-testable without DNS. Checked in the API (403) and again
in the worker, like cloud bindings and the DAST allowlist.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from enum import Enum
from typing import Awaitable, Callable, Iterable, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from . import targets as _targets

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeKind(str, Enum):
    DOMAIN = "domain"
    NETWORK = "network"


class ScopeError(PermissionError):
    """The target is public and not inside any scope bound to the tenant."""


class TenantScope(BaseModel):
    model_config = ConfigDict(use_enum_values=True, frozen=True)

    kind: ScopeKind
    value: str
    note: str = ""

    @model_validator(mode="after")
    def _validate(self) -> "TenantScope":
        value = _targets.safe_token(self.value, "value").lower().rstrip(".")
        if self.kind == ScopeKind.DOMAIN.value:
            if not _targets.is_hostname(value) or _targets.is_ip_or_network(value):
                raise ValueError("domain scope must be a hostname")
            if "." not in value:
                raise ValueError("domain scope must be a registrable domain, not a bare label")
        else:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError("network scope must be an IP address or CIDR") from exc
            if net.prefixlen == 0:
                raise ValueError("network scope must not be the default route")
            value = str(net)
        object.__setattr__(self, "value", value)
        return self


# ---------- pure helpers ----------

def is_private_address(addr: IPAddress | IPNetwork) -> bool:
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def domain_in_scope(host: str, scopes: Iterable[TenantScope]) -> bool:
    host = host.lower().rstrip(".")
    return any(
        s.kind == ScopeKind.DOMAIN.value and (host == s.value or host.endswith("." + s.value))
        for s in scopes
    )


def network_in_scope(net: IPNetwork, scopes: Iterable[TenantScope]) -> bool:
    for s in scopes:
        if s.kind != ScopeKind.NETWORK.value:
            continue
        allowed = ipaddress.ip_network(s.value)
        if net.version == allowed.version and net.subnet_of(allowed):
            return True
    return False


def split_host_port(value: str) -> str:
    """'host', 'host:port', '[v6]' or '[v6]:port' -> host."""
    if value.startswith("["):
        return value[1:value.index("]")]
    if value.count(":") == 1:
        return value.split(":")[0]
    return value


async def resolve_addresses(host: str) -> list[IPAddress]:
    """All A/AAAA answers for `host`; [] when it does not resolve."""
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []
    out: list[IPAddress] = []
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr not in out:
            out.append(addr)
    return out


Resolver = Callable[[str], Awaitable[list[IPAddress]]]
HostClass = Literal["private", "scoped"]


async def classify_host(
    host: str,
    scopes: Iterable[TenantScope],
    resolver: Resolver = resolve_addresses,
) -> HostClass:
    """'private' when every address is RFC1918/loopback/link-local,
    'scoped' when the target is public but inside a tenant scope.
    Raises ScopeError otherwise — including when DNS gives no answer."""
    scopes = list(scopes)
    if _targets.is_ip_or_network(host):
        net = ipaddress.ip_network(host, strict=False)
        if is_private_address(net):
            return "private"
        if network_in_scope(net, scopes):
            return "scoped"
        raise ScopeError(f"public target {host!r} is not inside any network scope bound to this tenant")

    if domain_in_scope(host, scopes):
        return "scoped"
    addresses = await resolver(host)
    if not addresses:
        raise ScopeError(f"{host!r} does not resolve; refusing to scan an unverifiable target")
    public = [a for a in addresses if not is_private_address(a)]
    if not public:
        return "private"
    outside = [str(a) for a in public if not network_in_scope(ipaddress.ip_network(a), scopes)]
    if outside:
        raise ScopeError(
            f"{host!r} resolves to public address(es) {outside} outside every scope bound to this tenant"
        )
    return "scoped"


def authorize_root_domains(root_domains: Iterable[str], scopes: Iterable[TenantScope]) -> list[str]:
    """ASM enumerates and then probes *public* hosts under each root, so
    every root must sit inside a domain scope. Returns the normalized roots."""
    scopes = list(scopes)
    roots = [r.lower().rstrip(".") for r in root_domains]
    outside = [r for r in roots if not domain_in_scope(r, scopes)]
    if outside:
        raise ScopeError(f"root domain(s) not inside any domain scope bound to this tenant: {outside}")
    return roots


def under_roots(hosts: Iterable[str], roots: Iterable[str]) -> list[str]:
    """Keep only hosts that are the root or a subdomain of one of `roots`."""
    roots = [r.lower().rstrip(".") for r in roots]
    out: list[str] = []
    for h in hosts:
        hl = h.lower().rstrip(".")
        if any(hl == r or hl.endswith("." + r) for r in roots):
            out.append(h)
    return out


# ---------- persistence ----------

async def load_scopes(tenant_id: UUID) -> list[TenantScope]:
    from sqlalchemy import select

    from .db import TenantScopeRow, tenant_session

    async with tenant_session(tenant_id) as session:
        rows = (await session.execute(select(TenantScopeRow))).scalars().all()
    return [TenantScope(kind=r.kind, value=r.value, note=r.note or "") for r in rows]
