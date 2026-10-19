"""Static checks on the deployment files: every download is pinned and
verified, nothing runs as root or pulls "latest", Redis requires a
password, the schema owner is separated from the runtime role, and CORS
is explicit."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnsuite.core.config import ApiSettings, DatabaseSettings, Settings

DEPLOY = Path(__file__).resolve().parents[1] / "vulnsuite" / "deploy"
DOCKERFILE = (DEPLOY / "Dockerfile").read_text()
COMPOSE = (DEPLOY / "docker-compose.yml").read_text()


def _dockerfile_download_urls() -> list[str]:
    args = dict(re.findall(r"^ARG (\w+)=(\S+)$", DOCKERFILE, flags=re.M))
    urls = re.findall(r'fetch-verified "([^"]+)"', DOCKERFILE)
    assert urls, "Dockerfile has no fetch-verified downloads"
    resolved = []
    for url in urls:
        resolved.append(re.sub(r"\$\{(\w+)\}", lambda m: args[m.group(1)], url))
    assert all("${" not in u for u in resolved)
    return resolved


# ---------- Dockerfile ----------

def test_no_raw_downloads_or_pipe_to_shell_in_dockerfile() -> None:
    body = "\n".join(l for l in DOCKERFILE.splitlines() if not l.lstrip().startswith("#"))
    assert "| bash" not in body and "| sh" not in body
    assert "releases/latest" not in body
    # curl may be *installed* (fetch-verified uses it) but never invoked directly
    assert not re.search(r"\bcurl\s+-", body), "all downloads must go through fetch-verified"
    assert not re.search(r"RUN\s+curl\b", body)


def test_runtime_runs_as_unprivileged_user() -> None:
    lines = [l for l in DOCKERFILE.splitlines() if l.startswith("USER ")]
    assert lines and lines[-1] == "USER 10001:10001"
    # USER must come after pip install and before CMD
    assert DOCKERFILE.index("pip install") < DOCKERFILE.index("USER 10001") < DOCKERFILE.index("CMD [")


def test_every_download_is_pinned_in_checksums_file() -> None:
    pins = DEPLOY / "checksums.sha256"
    assert pins.exists(), "deploy/checksums.sha256 missing: run deploy/pin-checksums.sh"
    pinned = {}
    for line in pins.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        sha, url = line.split()[:2]
        assert re.fullmatch(r"[0-9a-f]{64}", sha), line
        pinned[url] = sha
    missing = [u for u in _dockerfile_download_urls() if u not in pinned]
    assert not missing, f"downloads without a pinned checksum: {missing}"


def test_fetch_verified_refuses_mismatch_and_missing_pin(tmp_path) -> None:
    script = (DEPLOY / "fetch-verified.sh").read_text()
    assert 'sha256sum "$dest"' in script
    assert "ALLOW_UNVERIFIED_DOWNLOADS" in script
    # a mismatch must never be bypassable: the bypass sits only on the missing-pin branch
    mismatch_branch = script[script.index('if [ "$actual" != "$expected" ]'):]
    assert "ALLOW_UNVERIFIED_DOWNLOADS" not in mismatch_branch


# ---------- Compose ----------

def test_redis_requires_a_password() -> None:
    assert "--requirepass" in COMPOSE
    assert 'VULNSUITE_REDIS_URL: "redis://:${REDIS_PASSWORD' in COMPOSE
    assert "redis://redis:6379" not in COMPOSE


def test_api_gets_a_distinct_schema_owner_connection() -> None:
    assert "VULNSUITE_DB_MIGRATION_URL" in COMPOSE
    assert "vulnsuite_migrator:" in COMPOSE and "vulnsuite_app:" in COMPOSE
    assert "VULNSUITE_MIGRATOR_DB_PASSWORD" in COMPOSE
    # workers must not receive the schema-owner URL via the shared env block
    common = COMPOSE[COMPOSE.index("x-common-env"):COMPOSE.index("services:")]
    assert "MIGRATION_URL" not in common


def test_bootstrap_script_creates_both_roles_without_create_for_runtime() -> None:
    script = (DEPLOY / "postgres" / "10-application-role.sh").read_text()
    assert "CREATE ROLE vulnsuite_migrator" in script and "CREATE ROLE vulnsuite_app" in script
    assert "GRANT USAGE, CREATE ON SCHEMA public TO vulnsuite_migrator;" in script
    assert "GRANT USAGE ON SCHEMA public TO vulnsuite_app;" in script
    assert "CREATE ON SCHEMA public TO vulnsuite_app" not in script


# ---------- config ----------

def test_cors_origins_must_be_explicit() -> None:
    assert ApiSettings(cors_origins=["https://console.example.com/"]).cors_origins == ["https://console.example.com"]
    for bad in (["*"], ["console.example.com"], ["https://a.com, https://b.com"]):
        with pytest.raises(ValidationError):
            ApiSettings(cors_origins=bad)


def test_production_requires_separate_migration_role() -> None:
    issues = Settings(environment="production", database=DatabaseSettings(url="postgresql+asyncpg://app:x@db/v")).validate_production()
    assert any("migration_url required" in i for i in issues)
    same = DatabaseSettings(url="postgresql+asyncpg://app:x@db/v", migration_url="postgresql+asyncpg://app:x@db/v")
    issues = Settings(environment="production", database=same).validate_production()
    assert any("different role" in i for i in issues)


def test_unused_default_session_secret_is_gone() -> None:
    assert "change-me-in-production" not in (Path(__file__).resolve().parents[1] / "vulnsuite" / "core" / "config.py").read_text()
