"""
VulnSuite - Common Finding Schema (Pydantic v2)

This is the canonical data contract for every collector in the suite.
All scanner outputs MUST be normalized into `Finding` before being
persisted or risk-scored. Do not add tool-specific fields here; put
them inside `evidence` (free-form dict).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator


# ---------- Enums ----------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"          # risk accepted by business
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"


class AssetType(str, Enum):
    REPO = "repo"
    HOST = "host"
    IMAGE = "image"
    CLOUD_RESOURCE = "cloud_resource"
    CLOUD_ACCOUNT = "cloud_account"
    ENDPOINT = "endpoint"
    DATABASE = "database"
    DOMAIN = "domain"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    ARTIFACT = "artifact"


class Module(str, Enum):
    SCA = "sca"
    SAST = "sast"
    SECRETS = "secrets"
    NETWORK = "network"
    CLOUD = "cloud"
    CONTAINER = "container"
    DISCOVERY = "discovery"
    IAC = "iac"
    KUBERNETES = "kubernetes"
    ASM = "asm"
    API_SECURITY = "api_security"
    SUPPLY_CHAIN = "supply_chain"


class ExposureFactor(float, Enum):
    INTERNET = 1.0
    INTERNAL = 0.6
    ISOLATED = 0.3


class DASTMode(str, Enum):
    OFF = "off"
    BASELINE = "baseline"
    ACTIVE = "active"


# ---------- Models ----------

class Asset(BaseModel):
    """A thing we scan. Criticality is business-assigned (1-5)."""
    model_config = ConfigDict(use_enum_values=True)

    asset_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    name: str
    asset_type: AssetType
    criticality: int = Field(ge=1, le=5, description="1=sandbox, 5=prod-critical")
    exposure: ExposureFactor = ExposureFactor.INTERNAL
    owner: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class Evidence(BaseModel):
    """Free-form evidence block. Collectors stash tool-specific data here."""
    model_config = ConfigDict(extra="allow")

    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    raw: dict[str, Any] | None = None


class Finding(BaseModel):
    """Canonical finding. Every collector emits this."""
    model_config = ConfigDict(use_enum_values=True)

    finding_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    asset_id: UUID
    tool: str                               # e.g. "trivy", "gitleaks"
    module: Module
    title: str
    description: str = ""
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_base: float = Field(default=0.0, ge=0.0, le=10.0)
    epss: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: Severity = Severity.INFO
    evidence: Evidence = Field(default_factory=Evidence)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    status: Status = Status.OPEN
    risk_score: float = 0.0                 # filled by risk_engine
    risk_bucket: str | None = None          # P0..P4, filled by risk_engine

    @field_validator("cve", "cwe")
    @classmethod
    def _upper(cls, v: list[str]) -> list[str]:
        return [x.upper().strip() for x in v if x]


class ScanResult(BaseModel):
    """Envelope returned by every collector."""
    tool: str
    module: Module
    asset_id: UUID
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    errors: list[str] = Field(default_factory=list)

    @property
    def count_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity if isinstance(f.severity, str) else f.severity.value] += 1
        return out


class ScanTargets(BaseModel):
    """Typed scan request surface for all current and Phase 2 collectors."""
    model_config = ConfigDict(use_enum_values=True)

    # Existing Phase 1/4 targets
    repo: str | None = None
    image: str | None = None
    host: str | None = None
    tls_endpoint: str | None = None
    azure: bool = False

    # Phase 2 targets
    iac_paths: list[str] = Field(default_factory=list)
    terraform_plan_paths: list[str] = Field(default_factory=list)
    helm_chart_paths: list[str] = Field(default_factory=list)
    k8s_manifest_paths: list[str] = Field(default_factory=list)
    kube_context: str | None = None
    kubeconfig_path: str | None = None
    root_domains: list[str] = Field(default_factory=list)
    api_specs: list[str] = Field(default_factory=list)
    api_base_urls: list[str] = Field(default_factory=list)
    sbom_paths: list[str] = Field(default_factory=list)
    vex_paths: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    aws_accounts: list[str] = Field(default_factory=list)
    gcp_projects: list[str] = Field(default_factory=list)
    dast_mode: DASTMode = DASTMode.OFF

    @field_validator(
        "iac_paths",
        "terraform_plan_paths",
        "helm_chart_paths",
        "k8s_manifest_paths",
        "root_domains",
        "api_specs",
        "api_base_urls",
        "sbom_paths",
        "vex_paths",
        "artifacts",
        "aws_accounts",
        "gcp_projects",
    )
    @classmethod
    def _normalize_list(cls, values: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for value in values:
            normalized = value.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                out.append(normalized)
        return out

    @model_validator(mode="after")
    def _validate_relationships(self) -> "ScanTargets":
        if self.dast_mode != DASTMode.OFF and not (self.api_base_urls or self.api_specs):
            raise ValueError("dast_mode requires api_base_urls or api_specs")
        return self

    def has_any(self) -> bool:
        return any(
            [
                self.repo,
                self.image,
                self.host,
                self.tls_endpoint,
                self.azure,
                self.iac_paths,
                self.terraform_plan_paths,
                self.helm_chart_paths,
                self.k8s_manifest_paths,
                self.kube_context,
                self.kubeconfig_path,
                self.root_domains,
                self.api_specs,
                self.api_base_urls,
                self.sbom_paths,
                self.vex_paths,
                self.artifacts,
                self.aws_accounts,
                self.gcp_projects,
            ]
        )

    def iac_scan_paths(self) -> list[str]:
        return list(
            dict.fromkeys(
                self.iac_paths
                + self.terraform_plan_paths
                + self.helm_chart_paths
                + self.k8s_manifest_paths
                + self.api_specs
            )
        )
