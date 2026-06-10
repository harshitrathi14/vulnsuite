"""VulnSuite AI - Structured output contracts (Pydantic v2).

Every Claude call in this package is forced through one of these
models via structured outputs, so downstream code never parses
free-form prose. Keep constraints light: server-side JSON-schema
enforcement rejects numeric bounds, so ranges are documented in
descriptions and clamped in code where they matter.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


# ---------- Triage ----------

class Exploitability(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SuggestedStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    FALSE_POSITIVE = "false_positive"


class TriageVerdict(BaseModel):
    finding_id: str = Field(description="UUID of the finding being triaged, echoed back verbatim")
    fp_likelihood: float = Field(
        description="Probability 0.0-1.0 that this finding is a false positive"
    )
    confidence: float = Field(
        description="Model confidence 0.0-1.0 in this verdict"
    )
    exploitability: Exploitability = Field(
        description="Practical exploitability given the evidence (not just CVSS)"
    )
    reasoning: str = Field(description="Two or three sentences justifying the verdict")
    suggested_status: SuggestedStatus = Field(
        description="false_positive only when fp_likelihood is high and reasoning is concrete"
    )


class TriageBatchResult(BaseModel):
    verdicts: list[TriageVerdict]


# ---------- Remediation ----------

class RemediationPlan(BaseModel):
    finding_id: str = Field(description="UUID of the finding, echoed back verbatim")
    summary: str = Field(description="One-sentence fix summary an engineer can act on")
    steps: list[str] = Field(description="Ordered, concrete remediation steps")
    patch: str | None = Field(
        default=None,
        description="Unified diff or code snippet when file/line evidence allows one; else null",
    )
    validation: str = Field(description="How to verify the fix landed (command, test, re-scan)")
    estimated_effort: str = Field(description="One of: trivial, hours, days, sprint")


class RemediationBatchResult(BaseModel):
    plans: list[RemediationPlan]


# ---------- Attack-chain correlation ----------

class ChainSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class AttackChain(BaseModel):
    finding_ids: list[str] = Field(
        description="UUIDs of the findings that compose this chain, in attack order"
    )
    narrative: str = Field(
        description="Attacker's-eye walkthrough: entry point -> pivot -> impact"
    )
    composite_severity: ChainSeverity = Field(
        description="Severity of the chain as a whole, not of any single link"
    )
    likelihood: float = Field(description="Probability 0.0-1.0 a motivated attacker completes the chain")
    suggested_bucket: str = Field(
        description="P0-P4 bucket the chain as a whole deserves (advisory)"
    )
    kill_chain_stage: str = Field(
        description="Dominant stage: recon, initial-access, execution, persistence, "
        "privilege-escalation, lateral-movement, exfiltration, impact"
    )


class CorrelationResult(BaseModel):
    chains: list[AttackChain]
    posture_note: str = Field(
        description="One short paragraph on the asset's overall attack surface"
    )


# ---------- Chain verification (adversarial second pass) ----------

class ChainVerdict(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


class ChainVerification(BaseModel):
    chain_index: int = Field(description="0-based index of the chain in the list you were given")
    verdict: ChainVerdict = Field(
        description="refuted when any link is implausible or the composition does not hold"
    )
    adjusted_likelihood: float = Field(
        description="Your own calibrated 0.0-1.0 likelihood, replacing the finder's"
    )
    note: str = Field(description="One or two sentences: why it holds or where it breaks")


class ChainVerificationResult(BaseModel):
    verifications: list[ChainVerification]


# ---------- Threat intelligence (live web) ----------

class IntelStatus(str, Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class ThreatIntelVerdict(BaseModel):
    cve: str = Field(description="CVE ID, echoed back verbatim")
    actively_exploited: IntelStatus = Field(
        description="Evidence of in-the-wild exploitation right now"
    )
    kev_listed: IntelStatus = Field(description="Present in CISA Known Exploited Vulnerabilities")
    public_poc: IntelStatus = Field(
        description="Public proof-of-concept or weaponized exploit (Metasploit, ExploitDB, GitHub)"
    )
    patch_available: IntelStatus
    exploit_maturity: str = Field(
        description="One of: none-observed, poc, weaponized, mass-exploitation"
    )
    summary: str = Field(description="2-3 sentences: current threat picture for this CVE")
    sources: list[str] = Field(description="URLs supporting the verdict")


class ThreatIntelBatchResult(BaseModel):
    verdicts: list[ThreatIntelVerdict]


# ---------- Compliance (RBI CSF) ----------

class RBIMappingVerdict(BaseModel):
    finding_id: str = Field(description="UUID of the finding, echoed back verbatim")
    control_ids: list[str] = Field(description="RBI CSF control IDs, e.g. ['6.3', '6.14']")
    rationale: str = Field(description="One sentence per control explaining the mapping")


class ComplianceMappingResult(BaseModel):
    mappings: list[RBIMappingVerdict]


# ---------- Narrative / reporting ----------

class ExecutiveSummary(BaseModel):
    headline: str = Field(description="One sentence a board member reads first")
    posture_assessment: str = Field(
        description="Two short paragraphs: where the organisation stands and why"
    )
    top_risks: list[str] = Field(description="3-5 bullet points, most material risk first")
    recommended_actions: list[str] = Field(
        description="3-5 prioritized actions with rough timeframes"
    )


# ---------- Dedup assist ----------

class MergeSuggestion(BaseModel):
    primary_finding_id: str = Field(description="UUID of the finding that should survive")
    duplicate_finding_ids: list[str] = Field(
        description="UUIDs of findings that appear to describe the same underlying issue"
    )
    rationale: str = Field(description="Why these are the same issue despite different wording")
    confidence: float = Field(description="0.0-1.0; only suggestions >= 0.8 are surfaced")


class DedupSuggestions(BaseModel):
    suggestions: list[MergeSuggestion]


# ---------- Copilot ----------

class CopilotAnswer(BaseModel):
    answer: str
    tool_calls: int = 0
