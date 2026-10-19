"""Scan-target hardening: a target must never become a scanner option,
an extra target-file line, or a path outside the scan workspace."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnsuite.core.schema import ScanTargets
from vulnsuite.core.targets import TargetValidationError, confine_paths


# ---------- argument injection ----------

@pytest.mark.parametrize(
    "field, value",
    [
        ("host", "--script=/tmp/evil.nse"),
        ("host", "-iL"),
        ("tls_endpoint", "--file=/etc/passwd"),
        ("repo", "--config=/tmp/x"),
        ("image", "--input=/tmp/x.tar"),
        ("kube_context", "--kubeconfig=/root/.kube/config"),
        ("kubeconfig_path", "-"),
    ],
)
def test_scalar_targets_reject_option_like_values(field, value) -> None:
    with pytest.raises(ValidationError, match="command-line option"):
        ScanTargets(**{field: value})


@pytest.mark.parametrize(
    "field",
    ["iac_paths", "root_domains", "api_base_urls", "sbom_paths", "vex_paths",
     "artifacts", "aws_accounts", "gcp_projects", "api_specs"],
)
def test_list_targets_reject_option_like_values(field) -> None:
    with pytest.raises(ValidationError, match="command-line option"):
        ScanTargets(**{field: ["--template=/tmp/x"]})


# ---------- target-file line injection ----------

def test_newline_in_root_domain_is_rejected() -> None:
    # subfinder/nuclei read targets from a file, one per line
    with pytest.raises(ValidationError, match="control characters"):
        ScanTargets(root_domains=["example.com\nvictim.com"])


def test_nul_byte_in_path_is_rejected() -> None:
    with pytest.raises(ValidationError, match="control characters"):
        ScanTargets(repo="/workspace/repo\x00")


# ---------- format rules ----------

def test_host_accepts_hostnames_ips_and_ranges() -> None:
    for value in ["db.internal", "10.0.0.5", "10.0.0.0/24", "2001:db8::1", "localhost"]:
        assert ScanTargets(host=value).host == value


@pytest.mark.parametrize("value", ["a b", "db_internal", "http://x", "x;ls", "-x.com"])
def test_host_rejects_junk(value) -> None:
    with pytest.raises(ValidationError):
        ScanTargets(host=value)


def test_root_domains_reject_network_ranges() -> None:
    with pytest.raises(ValidationError, match="network ranges"):
        ScanTargets(root_domains=["10.0.0.0/8"])


def test_tls_endpoint_accepts_host_port_forms() -> None:
    for value in ["api.example.com", "api.example.com:8443", "10.1.2.3:443", "[2001:db8::1]:443"]:
        assert ScanTargets(tls_endpoint=value).tls_endpoint == value
    with pytest.raises(ValidationError, match="valid port"):
        ScanTargets(tls_endpoint="api.example.com:99999")


@pytest.mark.parametrize(
    "value",
    ["nginx", "python:3.12-slim", "ghcr.io/demo/api:1.0", "localhost:5000/app",
     "registry.example.com/team/app@sha256:" + "a" * 64],
)
def test_image_accepts_oci_references(value) -> None:
    assert ScanTargets(image=value).image == value


@pytest.mark.parametrize("value", ["Ghcr.io/Demo/API", "app:tag with space", "app:/etc/passwd"])
def test_image_rejects_non_references(value) -> None:
    with pytest.raises(ValidationError):
        ScanTargets(image=value)


@pytest.mark.parametrize(
    "value, reason",
    [
        ("https://user:pw@api.example.com", "credentials"),
        ("ftp://api.example.com", "http"),
        ("javascript:alert(1)", "http"),
        ("https://", "no host"),
    ],
)
def test_api_base_urls_rejects_unsafe_urls(value, reason) -> None:
    with pytest.raises(ValidationError, match=reason):
        ScanTargets(api_base_urls=[value])


def test_cloud_identifiers_are_format_checked() -> None:
    assert ScanTargets(aws_accounts=["123456789012"]).aws_accounts == ["123456789012"]
    assert ScanTargets(gcp_projects=["my-project-123"]).gcp_projects == ["my-project-123"]
    with pytest.raises(ValidationError, match="12-digit"):
        ScanTargets(aws_accounts=["12345"])
    with pytest.raises(ValidationError, match="GCP project"):
        ScanTargets(gcp_projects=["My_Project"])


def test_api_specs_accepts_paths_and_https_urls() -> None:
    t = ScanTargets(api_specs=["specs/openapi.yaml", "https://api.example.com/openapi.json"])
    assert len(t.api_specs) == 2


def test_relative_paths_and_spaces_still_accepted() -> None:
    t = ScanTargets(repo="checkouts/my repo", iac_paths=["infra", "infra"])
    assert t.repo == "checkouts/my repo"
    assert t.iac_paths == ["infra"]


def test_parent_segments_are_rejected() -> None:
    with pytest.raises(ValidationError, match="parent-directory"):
        ScanTargets(sbom_paths=["../../etc/shadow"])


def test_blank_values_are_dropped_not_rejected() -> None:
    t = ScanTargets(host="  ", iac_paths=["", "  ", "infra"])
    assert t.host is None
    assert t.iac_paths == ["infra"]


# ---------- workspace confinement ----------

def test_confine_paths_resolves_relative_paths_under_root(tmp_path) -> None:
    (tmp_path / "repo").mkdir()
    t = confine_paths(ScanTargets(repo="repo", iac_paths=["repo/infra"]), tmp_path)
    assert t.repo == str((tmp_path / "repo").resolve())
    assert t.iac_paths == [str((tmp_path / "repo" / "infra").resolve())]


def test_confine_paths_accepts_absolute_paths_inside_root(tmp_path) -> None:
    inside = tmp_path / "tenant-a" / "repo"
    inside.mkdir(parents=True)
    assert confine_paths(ScanTargets(repo=str(inside)), tmp_path).repo == str(inside.resolve())


def test_confine_paths_rejects_absolute_paths_outside_root(tmp_path) -> None:
    with pytest.raises(TargetValidationError, match="outside the scan workspace"):
        confine_paths(ScanTargets(kubeconfig_path="/root/.kube/config"), tmp_path)


def test_confine_paths_rejects_other_tenant_workspace(tmp_path) -> None:
    (tmp_path / "tenant-a").mkdir()
    (tmp_path / "tenant-b" / "repo").mkdir(parents=True)
    with pytest.raises(TargetValidationError, match="outside"):
        confine_paths(ScanTargets(repo=str(tmp_path / "tenant-b" / "repo")), tmp_path / "tenant-a")


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_confine_paths_follows_symlinks(tmp_path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    secret = tmp_path / "secret"
    secret.mkdir()
    (root / "link").symlink_to(secret)
    with pytest.raises(TargetValidationError, match="outside"):
        confine_paths(ScanTargets(sbom_paths=["link/sbom.json"]), root)


def test_confine_paths_leaves_non_path_fields_alone(tmp_path) -> None:
    t = confine_paths(ScanTargets(host="10.0.0.1", image="nginx"), tmp_path)
    assert (t.host, t.image) == ("10.0.0.1", "nginx")


# ---------- collectors put "--" before the positional target ----------

class _Captured(Exception):
    def __init__(self, cmd):
        self.cmd = cmd


def _capture_exec(monkeypatch, module):
    async def fake_exec(*cmd, **kwargs):
        raise _Captured(list(cmd))
    # binaries aren't installed in CI; constructors only check PATH presence
    monkeypatch.setattr(module.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", fake_exec)


def _argv(coro):
    try:
        asyncio.run(coro)
    except _Captured as c:
        return c.cmd
    raise AssertionError("subprocess was not invoked")


def test_trivy_terminates_options_before_target(monkeypatch) -> None:
    from vulnsuite.collectors.sca import trivy
    _capture_exec(monkeypatch, trivy)
    argv = _argv(trivy.TrivyCollector()._run("/ws/repo", "fs"))
    assert argv[-2:] == ["--", "/ws/repo"]


def test_dockle_terminates_options_before_image(monkeypatch) -> None:
    from vulnsuite.collectors.container import dockle
    _capture_exec(monkeypatch, dockle)
    argv = _argv(dockle.DockleCollector()._run("nginx:1.25"))
    assert argv[-2:] == ["--", "nginx:1.25"]


def test_syft_flags_precede_separator(monkeypatch) -> None:
    from vulnsuite.collectors.supply_chain import syft
    _capture_exec(monkeypatch, syft)
    argv = _argv(syft.SyftCollector().export_sbom("ghcr.io/demo/api:1.0"))
    assert argv[-2:] == ["--", "ghcr.io/demo/api:1.0"]
    assert argv.index("-o") < argv.index("--")
