"""VulnSuite - Central configuration (Pydantic Settings).

All env vars, secrets, and feature flags live here. Loaded once at
process start, injected via DI into everything that needs it. In
production, secrets come from Azure Key Vault via the worker's
managed identity; the env vars below are populated by the init
container, never baked into images.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_DB_")
    url: str = "postgresql+asyncpg://vulnsuite:vulnsuite@localhost:5432/vulnsuite"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


class RedisSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_REDIS_")
    url: str = "redis://localhost:6379/0"
    epss_ttl_seconds: int = 86400


class AzureSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AZURE_")
    client_id: str | None = None
    client_secret: SecretStr | None = None
    tenant_id: str | None = None
    subscription_id: str | None = None
    key_vault_url: str | None = None

    @property
    def configured(self) -> bool:
        return all([
            self.client_id, self.client_secret,
            self.tenant_id, self.subscription_id,
        ])


class AWSSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AWS_")
    access_key_id: str | None = None
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None
    region: str = "ap-south-1"
    profile: str | None = None


class GCPSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GCP_")
    project_id: str | None = None
    organization_id: str | None = None
    credentials_path: Path | None = None


class ToolSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_TOOL_")
    trivy_binary: str = "trivy"
    checkov_binary: str = "checkov"
    kubescape_binary: str = "kubescape"
    subfinder_binary: str = "subfinder"
    httpx_binary: str = "httpx"
    nuclei_binary: str = "nuclei"
    zap_binary: str = "zap.sh"
    syft_binary: str = "syft"
    cosign_binary: str = "cosign"
    kubectl_binary: str = "kubectl"
    aws_binary: str = "aws"
    gcloud_binary: str = "gcloud"


class ScanningSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_SCAN_")
    max_parallel_collectors: int = 4
    per_collector_timeout: int = 1800
    offline_mode: bool = False         # air-gapped BFSI deployments
    external_module_downloads: bool = False
    offline_epss_csv: Path | None = None
    offline_trivy_db: Path | None = None
    offline_osv_db: Path | None = None
    offline_semgrep_rules: Path | None = None


class KubernetesSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_K8S_")
    kubeconfig_path: Path | None = None
    excluded_namespaces: list[str] = Field(
        default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease"]
    )


class ASMSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_ASM_")
    allow_connect_validation: bool = True
    allow_nmap_validation: bool = False
    max_subdomains_per_root: int = 500
    connect_timeout_seconds: int = 20


class APISecuritySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_APISEC_")
    dast_allowlist: list[str] = Field(default_factory=list)
    allow_active_scan: bool = False
    zap_max_minutes: int = 20
    nuclei_severity_floor: str = "medium"


class SupplyChainSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_SUPPLYCHAIN_")
    verify_signatures: bool = True
    prefer_keyless_verify: bool = True
    # Keyless (Sigstore/Fulcio) identity policy. Both must be set for a keyless
    # verification to succeed; otherwise we downgrade to key-based if a key is set.
    cosign_certificate_identity: str | None = None
    cosign_certificate_identity_regexp: str | None = None
    cosign_certificate_oidc_issuer: str | None = None
    cosign_certificate_oidc_issuer_regexp: str | None = None
    # Path to a cosign public key (PEM) when keyless isn't usable (air-gap, etc.).
    cosign_public_key_path: Path | None = None
    # If set, also run `cosign verify-attestation` and require this predicate type.
    # Common values: "slsaprovenance", "cyclonedx", "spdx".
    require_attestation_type: str | None = None


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_AUTH_")
    oidc_issuer: str | None = None
    oidc_audience: str = "vulnsuite-api"
    jwt_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    session_secret: SecretStr = SecretStr("change-me-in-production")
    session_ttl_seconds: int = 28800      # 8h work day


class ComplianceSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_COMPLIANCE_")
    certin_enabled: bool = True
    certin_reporting_window_hours: int = 6      # mandated by CERT-In
    rbi_csf_enabled: bool = True
    iso27001_enabled: bool = True
    pci_dss_enabled: bool = False                # opt-in per tenant


class ReportingSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_REPORT_")
    output_dir: Path = Path("/var/lib/vulnsuite/reports")
    classification_banner: str = "CONFIDENTIAL — INTERNAL USE ONLY"
    signing_key_path: Path | None = None     # optional PDF signing


class Settings(BaseSettings):
    """Root settings object."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="VULNSUITE_",
        extra="ignore",
    )

    environment: str = "development"      # development | staging | production
    log_level: str = "INFO"
    tenant_default_id: str = "00000000-0000-0000-0000-000000000001"

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    azure: AzureSettings = Field(default_factory=AzureSettings)
    aws: AWSSettings = Field(default_factory=AWSSettings)
    gcp: GCPSettings = Field(default_factory=GCPSettings)
    tools: ToolSettings = Field(default_factory=ToolSettings)
    scanning: ScanningSettings = Field(default_factory=ScanningSettings)
    kubernetes: KubernetesSettings = Field(default_factory=KubernetesSettings)
    asm: ASMSettings = Field(default_factory=ASMSettings)
    api_security: APISecuritySettings = Field(default_factory=APISecuritySettings)
    supply_chain: SupplyChainSettings = Field(default_factory=SupplyChainSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    compliance: ComplianceSettings = Field(default_factory=ComplianceSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def validate_production(self) -> list[str]:
        """Return list of misconfigurations blocking production use."""
        issues: list[str] = []
        if self.is_production:
            if self.auth.session_secret.get_secret_value() == "change-me-in-production":
                issues.append("auth.session_secret must be set in production")
            if not self.auth.oidc_issuer:
                issues.append("auth.oidc_issuer required in production")
            if self.database.echo:
                issues.append("database.echo must be False in production")
            if self.database.url.startswith("postgresql+asyncpg://vulnsuite:vulnsuite@"):
                issues.append("default DB credentials detected in production")
        return issues


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton accessor. Use this everywhere instead of Settings()."""
    return Settings()
