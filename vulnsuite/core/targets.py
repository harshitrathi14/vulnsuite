"""
VulnSuite - Scan-target hardening

Every string in `ScanTargets` ends up either on a scanner's command line
or inside a target-list file that a scanner reads line by line. These
rules make sure a target can only ever be a *target*:

- never an option      (no leading "-": `host="--script=x.nse"` is an nmap flag)
- never an extra line  (no control chars: "a.com\\nb.com" adds a subfinder target)
- never a path escape  (no ".." segments; worker-side confinement to a
                        per-deployment workspace root, symlinks resolved)

The format checks run wherever `ScanTargets` is validated — the API binds
request bodies to it and the worker re-validates — so a bypassed API
check is still caught at scan time. Path confinement depends on the
worker's filesystem, so it runs only in the worker (`confine_paths`).
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s")

# RFC 1123 hostname; trailing dot tolerated.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$",
    re.IGNORECASE,
)
# OCI reference: [registry[:port]/]path[:tag][@sha256:digest]
_OCI_REFERENCE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?"
    r"(?:@sha256:[a-f0-9]{64})?$"
)
_KUBE_CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,252}$")
_AWS_ACCOUNT = re.compile(r"^[0-9]{12}$")
_GCP_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class TargetValidationError(ValueError):
    pass


# ---------- building blocks ----------

def safe_token(value: str, field: str, *, allow_spaces: bool = False) -> str:
    """Baseline for every target string: non-empty, printable, not an option."""
    value = value.strip()
    if not value:
        raise TargetValidationError(f"{field}: empty value")
    if _CONTROL_CHARS.search(value):
        raise TargetValidationError(f"{field}: control characters are not allowed")
    if value.startswith("-"):
        raise TargetValidationError(
            f"{field}: {value!r} looks like a command-line option, not a target"
        )
    if not allow_spaces and _WHITESPACE.search(value):
        raise TargetValidationError(f"{field}: whitespace is not allowed in {value!r}")
    return value


def safe_path(value: str, field: str) -> str:
    """A filesystem path. Spaces are fine; ".." segments are not."""
    value = safe_token(value, field, allow_spaces=True)
    if any(part == ".." for part in Path(value).parts):
        raise TargetValidationError(f"{field}: parent-directory segments are not allowed")
    return value


def is_hostname(value: str) -> bool:
    return bool(_HOSTNAME.match(value))


def is_ip_or_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def safe_host(value: str, field: str, *, allow_network: bool = False) -> str:
    """Hostname, IP address, or (optionally) CIDR range."""
    value = safe_token(value, field)
    if is_hostname(value):
        return value
    if is_ip_or_network(value):
        if "/" in value and not allow_network:
            raise TargetValidationError(f"{field}: network ranges are not allowed")
        return value
    raise TargetValidationError(f"{field}: {value!r} is not a valid hostname or IP")


def safe_host_port(value: str, field: str) -> str:
    """host, ip, [ipv6], or any of those with :port."""
    value = safe_token(value, field)
    host, port = value, None
    if value.startswith("["):                     # [v6]:port
        end = value.find("]")
        if end == -1:
            raise TargetValidationError(f"{field}: unterminated IPv6 literal")
        host, rest = value[1:end], value[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise TargetValidationError(f"{field}: {value!r} is malformed")
            port = rest[1:]
    elif value.count(":") == 1:                   # host:port
        host, port = value.split(":")
    if port is not None and not (port.isdigit() and 0 < int(port) < 65536):
        raise TargetValidationError(f"{field}: {port!r} is not a valid port")
    safe_host(host, field)
    return value


def safe_url(value: str, field: str) -> str:
    value = safe_token(value, field)
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TargetValidationError(f"{field}: {value!r} is not a valid URL") from exc
    if parts.scheme not in {"http", "https"}:
        raise TargetValidationError(f"{field}: only http(s) URLs are allowed")
    if not parts.hostname:
        raise TargetValidationError(f"{field}: URL has no host")
    if parts.username or parts.password:
        raise TargetValidationError(f"{field}: credentials in URLs are not allowed")
    return value


def safe_oci_reference(value: str, field: str) -> str:
    value = safe_token(value, field)
    if not _OCI_REFERENCE.match(value):
        raise TargetValidationError(f"{field}: {value!r} is not a valid image reference")
    return value


def safe_kube_context(value: str, field: str) -> str:
    value = safe_token(value, field)
    if not _KUBE_CONTEXT.match(value):
        raise TargetValidationError(f"{field}: {value!r} is not a valid kube context name")
    return value


def safe_aws_account(value: str, field: str) -> str:
    value = safe_token(value, field)
    if not _AWS_ACCOUNT.match(value):
        raise TargetValidationError(f"{field}: {value!r} is not a 12-digit AWS account ID")
    return value


def safe_gcp_project(value: str, field: str) -> str:
    value = safe_token(value, field)
    if not _GCP_PROJECT.match(value):
        raise TargetValidationError(f"{field}: {value!r} is not a valid GCP project ID")
    return value


def safe_path_or_url(value: str, field: str) -> str:
    stripped = value.strip()
    if stripped.lower().startswith(("http://", "https://")):
        return safe_url(stripped, field)
    return safe_path(stripped, field)


# ---------- worker-side path confinement ----------

# ScanTargets fields that name something on the worker's filesystem.
PATH_FIELDS: tuple[str, ...] = (
    "repo",
    "kubeconfig_path",
    "iac_paths",
    "terraform_plan_paths",
    "helm_chart_paths",
    "k8s_manifest_paths",
    "sbom_paths",
    "vex_paths",
)


def confine_path(value: str, root: Path, field: str) -> str:
    """Resolve `value` (relative paths are taken from `root`) and refuse
    anything that lands outside `root` once symlinks are followed."""
    root = root.resolve()
    candidate = Path(value)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise TargetValidationError(
            f"{field}: {value!r} is outside the scan workspace {str(root)!r}"
        )
    return str(resolved)


def confine_paths(targets, root: Path):
    """Return a copy of `targets` with every path field resolved under `root`.

    Raises TargetValidationError naming the first offending field. Any
    pydantic model with the PATH_FIELDS attributes is accepted so this
    stays importable without core.schema.
    """
    update: dict = {}
    for field in PATH_FIELDS:
        value = getattr(targets, field, None)
        if not value:
            continue
        if isinstance(value, list):
            update[field] = [confine_path(v, root, field) for v in value]
        else:
            update[field] = confine_path(value, root, field)
    return targets.model_copy(update=update) if update else targets
