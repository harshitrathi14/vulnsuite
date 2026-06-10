"""VulnSuite - Celery tasks: scan, discover, report."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from celery import shared_task

from ..collectors.api_security.nuclei import NucleiCollector
from ..collectors.api_security.zap import ZAPAutomationCollector
from ..collectors.asm.httpx import HttpxCollector
from ..collectors.asm.subfinder import SubfinderCollector
from ..collectors.cloud.prowler_aws import ProwlerAWSCollector
from ..collectors.cloud.prowler_azure import ProwlerAzureCollector
from ..collectors.cloud.prowler_gcp import ProwlerGCPCollector
from ..collectors.container.dockle import DockleCollector
from ..collectors.discovery.aws_inventory import AWSInventoryCollector
from ..collectors.discovery.gcp_inventory import GCPInventoryCollector
from ..collectors.iac.checkov import CheckovCollector
from ..collectors.iac.trivy_config import TrivyConfigCollector
from ..collectors.kubernetes.inventory import KubernetesInventoryCollector, WorkloadImageRef
from ..collectors.kubernetes.kubescape import KubescapeCollector
from ..collectors.network.nmap_passive import NmapPassiveCollector
from ..collectors.network.testssl import TestSSLCollector
from ..collectors.sast.bandit import BanditCollector
from ..collectors.sast.semgrep import SemgrepCollector
from ..collectors.sca.osv_scanner import OSVScannerCollector
from ..collectors.sca.pip_audit import PipAuditCollector
from ..collectors.sca.trivy import TrivyCollector
from ..collectors.secrets.gitleaks import GitleaksCollector
from ..collectors.secrets.trufflehog import TruffleHogCollector
from ..collectors.supply_chain.cosign import CosignCollector, CosignPolicy
from ..collectors.supply_chain.syft import SyftCollector
from ..collectors.supply_chain.vex import VEXProcessor
from ..ai.client import AIEnrichmentError, ai_active
from ..compliance.certin_export import build_incident_report, write_report
from ..core.config import get_settings
from ..core.db import FindingRow, tenant_session, upsert_assets
from ..core.epss_provider import build_default_provider
from ..core.orchestrator import CollectorCall, Orchestrator, OrchestratorConfig
from ..core.risk_engine import RiskEngine
from ..core.schema import (
    Asset,
    AssetType,
    DASTMode,
    Evidence,
    ExposureFactor,
    Finding,
    Module,
    ScanResult,
    ScanTargets,
)

logger = logging.getLogger(__name__)
settings = get_settings()


def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    try:
        loop = asyncio.get_running_loop()
        return asyncio.run_coroutine_threadsafe(coro, loop).result()
    except RuntimeError:
        return asyncio.run(coro)


def _not_run_result(tool: str, module: Module, asset_id: UUID, reason: str) -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult(
        tool=tool,
        module=module,
        asset_id=asset_id,
        started_at=now,
        finished_at=now,
        findings=[],
        errors=[f"not run: {reason}"],
    )


def _skip_call(tool: str, module: Module, asset_id: UUID, reason: str) -> CollectorCall:
    async def _call() -> ScanResult:
        return _not_run_result(tool, module, asset_id, reason)

    return _call


def _merge_raw(existing: dict | None, patch: dict) -> dict:
    out = dict(existing or {})
    out.update(patch)
    return out


def _rewrite_result_module(
    result: ScanResult,
    module: Module,
    raw_patch: dict | None = None,
) -> ScanResult:
    findings = []
    for finding in result.findings:
        evidence = finding.evidence.model_copy(
            update={"raw": _merge_raw(finding.evidence.raw, raw_patch or {})}
        )
        findings.append(finding.model_copy(update={"module": module, "evidence": evidence}))
    return result.model_copy(update={"module": module, "findings": findings})


def _is_allowlisted_target(target: str, allowlist: list[str]) -> bool:
    host = urlparse(target).hostname or target
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowlist)


def validate_dast_targets(targets: ScanTargets) -> None:
    if targets.dast_mode == DASTMode.OFF:
        return
    if not targets.api_base_urls:
        raise ValueError("dast_mode requires api_base_urls for allowlist enforcement")
    if not settings.api_security.dast_allowlist:
        raise ValueError("DAST allowlist is empty; configure VULNSUITE_APISEC_DAST_ALLOWLIST")
    disallowed = [url for url in targets.api_base_urls if not _is_allowlisted_target(url, settings.api_security.dast_allowlist)]
    if disallowed:
        raise ValueError(f"DAST target(s) not allowlisted: {disallowed}")
    if targets.dast_mode == DASTMode.ACTIVE and not settings.api_security.allow_active_scan:
        raise ValueError("active DAST is disabled by policy")


async def _scan_kubernetes_image(ref: WorkloadImageRef, tenant_id: UUID, asset_id: UUID) -> ScanResult:
    result = await TrivyCollector().scan(ref.image, "image", tenant_id, asset_id)
    return _rewrite_result_module(
        result,
        Module.KUBERNETES,
        {
            "cluster": ref.cluster,
            "namespace": ref.namespace,
            "kind": ref.kind,
            "name": ref.name,
            "workload_image": ref.image,
        },
    )


async def _scan_asm_tls(host: str, tenant_id: UUID, asset_id: UUID) -> ScanResult:
    result = await TestSSLCollector().scan(host, tenant_id, asset_id)
    return _rewrite_result_module(result, Module.ASM, {"host": host, "asm_source": "subfinder"})


async def _scan_asm_host(host: str, tenant_id: UUID, asset_id: UUID) -> ScanResult:
    result = await NmapPassiveCollector(allow_public=True).scan(host, tenant_id, asset_id)
    return _rewrite_result_module(result, Module.ASM, {"host": host, "asm_source": "subfinder"})


@shared_task(name="vulnsuite.workers.tasks.scan_asset", bind=True, max_retries=2)
def scan_asset(
    self,
    tenant_id: str,
    asset_id: str,
    asset_name: str,
    asset_type: str,
    criticality: int,
    exposure: float,
    targets: dict,
) -> dict:
    """Run all applicable collectors against a single asset."""

    async def _run() -> dict:
        target_model = ScanTargets.model_validate(targets)
        validate_dast_targets(target_model)

        asset = Asset(
            asset_id=UUID(asset_id),
            tenant_id=UUID(tenant_id),
            name=asset_name,
            asset_type=AssetType(asset_type),
            criticality=criticality,
            exposure=ExposureFactor(exposure),
        )

        epss = await build_default_provider(
            redis_url=settings.redis.url,
            offline_csv_path=str(settings.scanning.offline_epss_csv)
            if settings.scanning.offline_epss_csv
            else None,
        )
        risk = RiskEngine(epss_provider=epss)
        orch = Orchestrator(
            risk,
            OrchestratorConfig(
                max_parallel_collectors=settings.scanning.max_parallel_collectors,
                per_collector_timeout=settings.scanning.per_collector_timeout,
            ),
        )

        calls: list[CollectorCall] = []
        post_processors = []
        tid, aid = asset.tenant_id, asset.asset_id
        temp_sboms: list[Path] = []

        try:
            if repo := target_model.repo:
                calls += [
                    lambda p=repo: TrivyCollector().scan(p, "fs", tid, aid),
                    lambda p=repo: PipAuditCollector().scan(p, "project", tid, aid),
                    lambda p=repo: OSVScannerCollector().scan(p, tid, aid),
                    lambda p=repo: GitleaksCollector().scan(p, tid, aid),
                    lambda p=repo: TruffleHogCollector().scan(p, "filesystem", tid, aid),
                    lambda p=repo: SemgrepCollector().scan(p, tid, aid),
                    lambda p=repo: BanditCollector().scan(p, tid, aid),
                ]
            if image := target_model.image:
                calls += [
                    lambda i=image: TrivyCollector().scan(i, "image", tid, aid),
                    lambda i=image: DockleCollector().scan(i, tid, aid),
                ]
            if host := target_model.host:
                calls.append(lambda h=host: NmapPassiveCollector().scan(h, tid, aid))
            if tls := target_model.tls_endpoint:
                calls.append(lambda t=tls: TestSSLCollector().scan(t, tid, aid))
            if target_model.azure:
                calls.append(lambda: ProwlerAzureCollector().scan(tid, aid))
            if target_model.aws_accounts:
                calls.append(
                    lambda ids=list(target_model.aws_accounts): ProwlerAWSCollector().scan(
                        tid, aid, account_ids=ids
                    )
                )
            if target_model.gcp_projects:
                calls.append(
                    lambda ids=list(target_model.gcp_projects): ProwlerGCPCollector().scan(
                        tid, aid, project_ids=ids
                    )
                )

            iac_paths = list(
                dict.fromkeys(
                    target_model.iac_paths
                    + target_model.terraform_plan_paths
                    + target_model.helm_chart_paths
                    + target_model.k8s_manifest_paths
                )
            )
            if iac_paths:
                calls.append(
                    lambda paths=iac_paths: CheckovCollector(
                        binary=settings.tools.checkov_binary,
                        download_external_modules=settings.scanning.external_module_downloads,
                    ).scan(
                        paths,
                        tid,
                        aid,
                        frameworks=("terraform", "terraform_plan", "bicep", "helm", "kubernetes", "kustomize"),
                        module=Module.IAC,
                    )
                )
                calls.append(
                    lambda paths=iac_paths: TrivyConfigCollector(
                        binary=settings.tools.trivy_binary,
                        offline=settings.scanning.offline_mode,
                    ).scan(paths, tid, aid, module=Module.IAC)
                )
            if target_model.api_specs:
                calls.append(
                    lambda paths=target_model.api_specs: CheckovCollector(
                        binary=settings.tools.checkov_binary,
                        download_external_modules=settings.scanning.external_module_downloads,
                    ).scan(paths, tid, aid, frameworks=("openapi",), module=Module.API_SECURITY)
                )

            if target_model.kube_context or target_model.kubeconfig_path:
                if settings.scanning.offline_mode:
                    calls.append(_skip_call("kubescape", Module.KUBERNETES, aid, "offline mode disables cluster access"))
                else:
                    kube_context = target_model.kube_context
                    kubeconfig_path = target_model.kubeconfig_path or (
                        str(settings.kubernetes.kubeconfig_path) if settings.kubernetes.kubeconfig_path else None
                    )
                    calls.append(
                        lambda ctx=kube_context, kp=kubeconfig_path: KubescapeCollector(
                            binary=settings.tools.kubescape_binary,
                            excluded_namespaces=tuple(settings.kubernetes.excluded_namespaces),
                        ).scan(tid, aid, ctx, kp)
                    )
                    inventory = KubernetesInventoryCollector(binary=settings.tools.kubectl_binary)
                    for ref in await inventory.list_workload_images(kube_context, kubeconfig_path):
                        calls.append(lambda ref=ref: _scan_kubernetes_image(ref, tid, aid))

            if target_model.root_domains:
                if settings.scanning.offline_mode:
                    calls.append(_skip_call("subfinder", Module.ASM, aid, "offline mode disables ASM passive discovery"))
                    calls.append(_skip_call("httpx", Module.ASM, aid, "offline mode disables ASM service enrichment"))
                else:
                    hosts = await SubfinderCollector(
                        binary=settings.tools.subfinder_binary,
                        max_results_per_root=settings.asm.max_subdomains_per_root,
                    ).enumerate(target_model.root_domains)
                    if hosts:
                        calls.append(lambda hosts=hosts: HttpxCollector(binary=settings.tools.httpx_binary).scan(hosts, tid, aid))
                        for host in hosts:
                            calls.append(lambda host=host: _scan_asm_tls(host, tid, aid))
                            if settings.asm.allow_nmap_validation:
                                calls.append(lambda host=host: _scan_asm_host(host, tid, aid))

            sbom_paths = list(target_model.sbom_paths)
            if target_model.artifacts:
                syft = SyftCollector(binary=settings.tools.syft_binary)
                for artifact in target_model.artifacts:
                    path = await syft.export_sbom(artifact)
                    temp_sboms.append(path)
                    sbom_paths.append(str(path))
                calls.append(lambda paths=sbom_paths: syft.scan(paths, tid, aid, input_is_sbom=True))
                if settings.supply_chain.verify_signatures:
                    cosign_policy = CosignPolicy(
                        prefer_keyless=settings.supply_chain.prefer_keyless_verify,
                        public_key_path=settings.supply_chain.cosign_public_key_path,
                        identity=settings.supply_chain.cosign_certificate_identity,
                        identity_regexp=settings.supply_chain.cosign_certificate_identity_regexp,
                        issuer=settings.supply_chain.cosign_certificate_oidc_issuer,
                        issuer_regexp=settings.supply_chain.cosign_certificate_oidc_issuer_regexp,
                        attestation_type=settings.supply_chain.require_attestation_type,
                    )
                    calls.append(
                        lambda artifacts=target_model.artifacts, policy=cosign_policy: CosignCollector(
                            binary=settings.tools.cosign_binary,
                            policy=policy,
                        ).scan(artifacts, tid, aid)
                    )
            elif sbom_paths:
                calls.append(lambda paths=sbom_paths: SyftCollector(binary=settings.tools.syft_binary).scan(paths, tid, aid, input_is_sbom=True))

            for sbom_path in sbom_paths:
                calls.append(lambda path=sbom_path: TrivyCollector().scan(path, "sbom", tid, aid))

            if target_model.vex_paths:
                post_processors.append(VEXProcessor.load_many(target_model.vex_paths).apply)

            if target_model.dast_mode != DASTMode.OFF:
                if settings.scanning.offline_mode:
                    calls.append(_skip_call("zap", Module.API_SECURITY, aid, "offline mode disables DAST"))
                    calls.append(_skip_call("nuclei", Module.API_SECURITY, aid, "offline mode disables DAST"))
                else:
                    calls.append(
                        lambda urls=target_model.api_base_urls, specs=target_model.api_specs, mode=target_model.dast_mode: ZAPAutomationCollector(
                            binary=settings.tools.zap_binary,
                            timeout_seconds=settings.api_security.zap_max_minutes * 60,
                        ).scan(tid, aid, urls, specs, mode)
                    )
                    calls.append(
                        lambda urls=target_model.api_base_urls: NucleiCollector(
                            binary=settings.tools.nuclei_binary,
                            severity_floor=settings.api_security.nuclei_severity_floor,
                        ).scan(urls, tid, aid)
                    )

            report = await orch.run(asset, calls, post_processors=post_processors)

            # Phase 3: hand off to AI enrichment asynchronously. The scan
            # result is already persisted; enrichment updates evidence
            # in place and must never delay or fail the scan itself.
            ai_task_id: str | None = None
            if ai_active() and report.findings_after_dedup:
                ai_task = ai_enrich_findings.delay(
                    tenant_id=str(asset.tenant_id),
                    asset_json=asset.model_dump(mode="json"),
                    findings_json=[
                        f.model_dump(mode="json") for f in report.findings_after_dedup
                    ],
                )
                ai_task_id = getattr(ai_task, "id", None)

            return {
                "asset_id": str(asset.asset_id),
                "summary": report.summary,
                "persisted": report.persisted_count,
                "errors": report.errors,
                "ai_enrichment_task": ai_task_id,
            }
        finally:
            for path in temp_sboms:
                path.unlink(missing_ok=True)
            await epss.aclose()

    try:
        return _run_async(_run())
    except Exception as exc:  # noqa: BLE001
        logger.exception("scan_asset failed")
        raise self.retry(exc=exc, countdown=60)


async def _persist_evidence_updates(tenant_id: UUID, findings: list[Finding]) -> int:
    """Write AI-annotated evidence back to rows that gained ai_* keys."""
    from sqlalchemy import update

    count = 0
    async with tenant_session(tenant_id) as session:
        for f in findings:
            raw = f.evidence.raw or {}
            if not any(key.startswith("ai_") for key in raw):
                continue
            await session.execute(
                update(FindingRow)
                .where(FindingRow.finding_id == f.finding_id)
                .values(evidence=f.evidence.model_dump(mode="json"))
            )
            count += 1
        await session.commit()
    return count


@shared_task(name="vulnsuite.workers.tasks.ai_enrich_findings", bind=True, max_retries=1)
def ai_enrich_findings(
    self,
    tenant_id: str,
    asset_json: dict | None,
    findings_json: list[dict],
) -> dict:
    """Phase 3 AI enrichment: triage -> remediation -> attack chains ->
    RBI mapping -> dedup suggestions, then persist evidence updates.

    Every stage degrades to a no-op on failure; the task only retries
    on unexpected infrastructure errors (DB down), never on model errors.
    """
    from ..ai.compliance import map_findings_rbi
    from ..ai.correlate import correlate_findings
    from ..ai.dedup_assist import suggest_merges
    from ..ai.remediate import remediate_findings
    from ..ai.threat_intel import enrich_threat_intel
    from ..ai.triage import (
        apply_triage_batch,
        submit_triage_batches,
        triage_findings,
        wait_for_batch,
    )

    if not ai_active():
        return {"status": "disabled"}

    findings = [Finding(**f) for f in findings_json]
    asset = Asset(**asset_json) if asset_json else None
    if not findings:
        return {"status": "empty"}

    ai_cfg = settings.ai

    # 1) Triage — Batches API (50% price) for full-scan volumes
    if ai_cfg.triage_enabled:
        if ai_cfg.use_batches and len(findings) > ai_cfg.batch_threshold:
            try:
                batch_id = submit_triage_batches(findings, asset)
                if wait_for_batch(batch_id):
                    findings = apply_triage_batch(batch_id, findings)
                else:
                    logger.warning("triage batch %s did not finish in window", batch_id)
            except AIEnrichmentError as exc:
                logger.warning("triage batch path failed: %s", exc)
        else:
            findings = triage_findings(findings, asset)

    # 2-6) remaining stages each degrade independently. Threat intel runs
    # before remediation/correlation so live exploitation status is part
    # of the evidence those stages reason over.
    findings = enrich_threat_intel(findings)
    findings = remediate_findings(findings, asset)
    findings = correlate_findings(findings, asset)
    findings = map_findings_rbi(findings)
    findings = suggest_merges(findings)

    try:
        updated = _run_async(_persist_evidence_updates(UUID(tenant_id), findings))
    except Exception as exc:  # noqa: BLE001 - infra failure: worth a retry
        logger.exception("ai enrichment persist failed")
        raise self.retry(exc=exc, countdown=120)

    return {"status": "ok", "findings": len(findings), "updated": updated}


@shared_task(name="vulnsuite.workers.tasks.discover_assets")
def discover_assets(tenant_id: str) -> int:
    async def _run() -> int:
        from ..collectors.discovery.azure_inventory import AzureInventoryCollector

        assets = await AzureInventoryCollector().discover(UUID(tenant_id))
        return await upsert_assets(UUID(tenant_id), assets)

    return _run_async(_run())


@shared_task(name="vulnsuite.workers.tasks.discover_azure_assets")
def discover_azure_assets(tenant_id: str) -> int:
    return discover_assets(tenant_id)


@shared_task(name="vulnsuite.workers.tasks.discover_aws_assets")
def discover_aws_assets(tenant_id: str, account_ids: list[str]) -> int:
    async def _run() -> int:
        if settings.scanning.offline_mode:
            return 0
        assets = await AWSInventoryCollector(binary=settings.tools.aws_binary, region=settings.aws.region).discover(
            UUID(tenant_id), account_ids
        )
        return await upsert_assets(UUID(tenant_id), assets)

    return _run_async(_run())


@shared_task(name="vulnsuite.workers.tasks.discover_gcp_assets")
def discover_gcp_assets(tenant_id: str, project_ids: list[str]) -> int:
    async def _run() -> int:
        if settings.scanning.offline_mode:
            return 0
        assets = await GCPInventoryCollector(binary=settings.tools.gcloud_binary).discover(
            UUID(tenant_id), project_ids
        )
        return await upsert_assets(UUID(tenant_id), assets)

    return _run_async(_run())


@shared_task(name="vulnsuite.workers.tasks.discover_domains")
def discover_domains(tenant_id: str, root_domains: list[str]) -> int:
    async def _run() -> int:
        if settings.scanning.offline_mode:
            return 0
        assets = await SubfinderCollector(
            binary=settings.tools.subfinder_binary,
            max_results_per_root=settings.asm.max_subdomains_per_root,
        ).discover(UUID(tenant_id), root_domains)
        return await upsert_assets(UUID(tenant_id), assets)

    return _run_async(_run())


@shared_task(name="vulnsuite.workers.tasks.discover_kubernetes_clusters")
def discover_kubernetes_clusters(tenant_id: str, kubeconfig_path: str | None = None) -> int:
    async def _run() -> int:
        if settings.scanning.offline_mode:
            return 0
        assets = await KubernetesInventoryCollector(binary=settings.tools.kubectl_binary).discover_clusters(
            UUID(tenant_id), kubeconfig_path
        )
        return await upsert_assets(UUID(tenant_id), assets)

    return _run_async(_run())


@shared_task(name="vulnsuite.workers.tasks.generate_report")
def generate_report(
    tenant_id: str,
    tenant_name: str,
    operator: str,
    findings_json: list[dict],
    asset_names: dict[str, str],
) -> str:
    from ..ai.narrate import certin_narrative, executive_summary, render_summary_text
    from ..reporting.pdf_report import PDFReportGenerator, ReportMetadata

    findings = [Finding(**finding) for finding in findings_json]

    meta = ReportMetadata(
        tenant_name=tenant_name,
        scan_window_start=datetime.now(timezone.utc),
        scan_window_end=datetime.now(timezone.utc),
        operator=operator,
    )
    out_dir = settings.reporting.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"vulnsuite_{tenant_id}_{datetime.now(timezone.utc):%Y%m%d%H%M%S}.pdf"

    # AI executive briefing (returns None when the AI layer is off/unavailable)
    ai_summary_text: str | None = None
    summary = executive_summary(findings, tenant_name)
    if summary is not None:
        ai_summary_text = render_summary_text(summary)

    PDFReportGenerator().render(findings, asset_names, meta, pdf_path, ai_summary=ai_summary_text)

    incident = build_incident_report(
        findings,
        organization=tenant_name,
        contact_name=operator,
        contact_email=f"{operator}@{tenant_name.lower().replace(' ', '')}.local",
        contact_phone="+91-0000000000",
    )
    if incident:
        narrative = certin_narrative(incident, tenant_id)
        if narrative:
            incident["ai_draft_narrative"] = {
                "text": narrative,
                "model": settings.ai.model,
                "note": "AI-generated draft — human review and sign-off required "
                "before any regulatory submission",
            }
        write_report(incident, out_dir)

    return str(pdf_path)
