"""VulnSuite - Central configuration (Pydantic Settings).

All env vars, secrets, and feature flags live here. Loaded once at
process start, injected via DI into everything that needs it. In
production, secrets come from Azure Key Vault via the worker's
managed identity; the env vars below are populated by the init
container, never baked into images.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_DB_")
    url: str = "postgresql+asyncpg://vulnsuite:vulnsuite@localhost:5432/vulnsuite"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False
    # Schema-owner connection used only by init_db (DDL, RLS, grants).
    # Required in production so the runtime role never owns the tables.
    migration_url: str | None = None
    app_role: str = "vulnsuite_app"      # runtime role that receives DML grants


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
    # Directory every path-type scan target (repo, iac_paths, sbom_paths,
    # kubeconfig_path, ...) must resolve under. Unset = paths are only
    # format-checked, and the worker logs a warning at each scan.
    workspace_root: Path | None = None
    # Tenants the nightly beat job runs Azure discovery for (JSON list of
    # tenant UUIDs in the env var). Each still needs an Azure binding.
    scheduled_discovery_tenants: list[str] = Field(default_factory=list)
    offline_epss_csv: Path | None = None
    offline_kev_json: Path | None = None     # CISA KEV mirror for air-gapped escalation
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


class AssetPolicySettings(BaseSettings):
    """Tag-driven asset criticality/exposure (applied at discovery)."""
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_ASSETPOLICY_")

    auto_criticality: bool = True
    prod_tags: list[str] = Field(
        default_factory=lambda: ["prod", "production", "prd"]
    )
    staging_tags: list[str] = Field(
        default_factory=lambda: ["staging", "stage", "stg", "uat", "preprod", "pre-prod"]
    )
    dev_tags: list[str] = Field(
        default_factory=lambda: ["dev", "development", "sandbox", "test", "qa", "demo"]
    )
    sensitive_tags: list[str] = Field(
        default_factory=lambda: ["pii", "pci", "phi", "financial", "payments", "confidential"]
    )
    internet_tags: list[str] = Field(
        default_factory=lambda: ["internet", "public", "external", "internet-facing", "dmz"]
    )


class RiskSettings(BaseSettings):
    """Deterministic risk escalation thresholds (CISA KEV / live exploitation)."""
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_RISK_")

    escalation_enabled: bool = True
    kev_floor_score: float = 7.0            # KEV-listed -> at least this score (7.0 = P0)
    active_exploit_floor_score: float = 7.0  # live in-the-wild exploitation -> at least P0


class AISettings(BaseSettings):
    """Claude Fable 5 enrichment layer (Phase 3).

    OFF by default: BFSI deployments must opt in, because enrichment
    sends redacted finding metadata to the Anthropic API. The layer is
    force-disabled whenever scanning.offline_mode is set (air-gap),
    regardless of these flags — see ai/client.ai_active().
    """
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_AI_")

    enabled: bool = False
    model: str = "claude-fable-5"
    api_key: SecretStr | None = None          # falls back to ANTHROPIC_API_KEY env
    request_timeout_seconds: float = 180.0

    # Per-feature switches (only honoured when enabled=True)
    triage_enabled: bool = True
    remediation_enabled: bool = True
    correlation_enabled: bool = True
    compliance_enabled: bool = True
    narrative_enabled: bool = True
    copilot_enabled: bool = True
    threat_intel_enabled: bool = True          # live web exploitation-status checks
    copilot_web_search: bool = True            # let the copilot search the live web
    dedup_assist_enabled: bool = False         # suggestions-only; opt-in

    # Cost/latency shaping
    use_batches: bool = True                   # Batches API (50% price) for big scans
    batch_threshold: int = 50                  # findings above this go via batches
    max_findings_per_call: int = 40
    max_correlation_findings: int = 300        # cap for the single attack-chain call
    remediation_buckets: list[str] = Field(default_factory=lambda: ["P0", "P1"])
    threat_intel_buckets: list[str] = Field(default_factory=lambda: ["P0", "P1"])
    max_cves_per_intel_call: int = 8
    max_snippet_chars: int = 2000
    copilot_max_turns: int = 8

    # Task budget (beta) for the deep correlation call: Fable 5 sees a
    # running countdown and plans its analysis to fit. 0 disables.
    correlation_task_budget: int = 64000       # minimum the API accepts is 20000

    # Fable 5 effort per feature: low|medium|high|xhigh|max
    triage_effort: str = "medium"
    remediation_effort: str = "high"
    correlation_effort: str = "max"
    compliance_effort: str = "medium"
    narrative_effort: str = "high"
    copilot_effort: str = "high"
    threat_intel_effort: str = "high"


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_AUTH_")
    oidc_issuer: str | None = None
    oidc_audience: str = "vulnsuite-api"
    jwt_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    # Exactly one trusted JWKS source; token headers never select a URL/key.
    jwks_url: str | None = None
    jwks_path: Path | None = None
    jwks_cache_seconds: int = Field(default=300, ge=1, le=3600)
    jwks_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30)
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"
    clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    max_token_lifetime_seconds: int = Field(default=28800, ge=60, le=86400)
    # The former session_secret / session_ttl_seconds were never read by
    # any code path; a default "change-me" secret is a liability, so gone.


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


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_API_")
    # Browser origins allowed to call the API with credentials, e.g.
    # ["https://console.example.com"]. Empty = no CORS headers at all
    # (same-origin only). "*" is refused: with credentials it is both
    # rejected by browsers and a CSRF foot-gun, and it was the old default.
    cors_origins: list[str] = Field(default_factory=list)

    @field_validator("cors_origins")
    @classmethod
    def _origins(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for v in values:
            v = v.strip().rstrip("/")
            if v == "*" or not re.match(r"^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?$", v):
                raise ValueError(f"cors_origins entry {v!r} must be an explicit http(s)://host[:port] origin")
            out.append(v)
        return out


class AuditSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNSUITE_AUDIT_")
    enabled: bool = True
    include_reads: bool = True     # also record GET calls (who viewed what)


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
    asset_policy: AssetPolicySettings = Field(default_factory=AssetPolicySettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    ai: AISettings = Field(default_factory=AISettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    compliance: ComplianceSettings = Field(default_factory=ComplianceSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def validate_production(self) -> list[str]:
        """Return list of misconfigurations blocking production use."""
        issues: list[str] = []
        if self.is_production:
            if not self.auth.oidc_issuer:
                issues.append("auth.oidc_issuer required in production")
            if bool(self.auth.jwks_url) == bool(self.auth.jwks_path):
                issues.append("exactly one auth.jwks_url or auth.jwks_path required in production")
            if self.database.echo:
                issues.append("database.echo must be False in production")
            if self.database.url.startswith("postgresql+asyncpg://vulnsuite:vulnsuite@"):
                issues.append("default DB credentials detected in production")
            if not self.database.migration_url:
                issues.append(
                    "database.migration_url required in production "
                    "(the runtime role must not own the schema)"
                )
            if self.database.migration_url and self.database.migration_url == self.database.url:
                issues.append("database.migration_url must use a different role than database.url")
        return issues


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton accessor. Use this everywhere instead of Settings()."""
    return Settings()
