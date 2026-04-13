"""VulnSuite - Kubescape collector for Kubernetes posture scanning."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from ...core.schema import Evidence, Finding, Module, ScanResult, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class KubescapeNotInstalled(RuntimeError):
    pass


class KubescapeCollector:
    def __init__(
        self,
        binary: str = "kubescape",
        timeout_seconds: int = 1800,
        excluded_namespaces: tuple[str, ...] = (),
    ) -> None:
        if shutil.which(binary) is None:
            raise KubescapeNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.excluded_namespaces = excluded_namespaces

    async def scan(
        self,
        tenant_id: UUID,
        asset_id: UUID,
        kube_context: str | None = None,
        kubeconfig_path: str | None = None,
    ) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors: list[str] = []
        try:
            raw = await self._run(kube_context, kubeconfig_path)
            findings = self._normalize(raw, tenant_id, asset_id)
        except asyncio.TimeoutError:
            errors.append(f"kubescape timeout after {self.timeout}s")
        except Exception as exc:  # noqa: BLE001
            logger.exception("kubescape failed")
            errors.append(f"kubescape error: {exc}")

        return ScanResult(
            tool="kubescape",
            module=Module.KUBERNETES,
            asset_id=asset_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
            errors=errors,
        )

    async def _run(self, kube_context: str | None, kubeconfig_path: str | None) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_path = Path(tmp.name)

        cmd = [self.binary, "scan", "framework", "nsa,cis", "--format", "json", "--output", str(output_path)]
        if kube_context:
            cmd += ["--context", kube_context]
        if kubeconfig_path:
            cmd += ["--kubeconfig", kubeconfig_path]
        if self.excluded_namespaces:
            cmd += ["--exclude-namespaces", ",".join(self.excluded_namespaces)]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        if proc.returncode not in (0, 1):
            output_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"kubescape exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )
        try:
            return json.loads(output_path.read_text() or "{}")
        finally:
            output_path.unlink(missing_ok=True)

    def _normalize(self, raw: dict, tenant_id: UUID, asset_id: UUID) -> list[Finding]:
        out: list[Finding] = []
        candidates = raw.get("results") or raw.get("matches") or raw.get("controls") or []
        if isinstance(candidates, dict):
            candidates = candidates.get("controls", [])

        for item in candidates:
            status = str(item.get("status") or item.get("result") or "failed").lower()
            if status not in {"failed", "warning"}:
                continue
            severity = _SEVERITY_MAP.get(str(item.get("severity") or "medium").lower(), Severity.MEDIUM)
            control_id = str(item.get("controlID") or item.get("ruleID") or item.get("name") or "kubescape")
            resource = item.get("resourceID") or item.get("resourceName") or item.get("resource") or {}
            if isinstance(resource, dict):
                namespace = str(resource.get("namespace") or item.get("namespace") or "")
                kind = str(resource.get("kind") or item.get("kind") or "")
                name = str(resource.get("name") or item.get("name") or "")
            else:
                namespace = str(item.get("namespace") or "")
                kind = str(item.get("kind") or "")
                name = str(resource)

            out.append(
                Finding(
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    tool="kubescape",
                    module=Module.KUBERNETES,
                    title=f"{control_id}: {item.get('name') or 'Kubernetes posture issue'}",
                    description=str(item.get("description") or item.get("details") or "")[:2000],
                    severity=severity,
                    evidence=Evidence(
                        raw={
                            "control_id": control_id,
                            "cluster": item.get("clusterName"),
                            "namespace": namespace,
                            "kind": kind,
                            "name": name,
                            "resource": resource,
                            "framework": item.get("frameworkName") or item.get("framework"),
                        }
                    ),
                    remediation=str(item.get("remediation") or "Review the Kubescape control guidance and harden the affected workload.")[:1000],
                    references=[str(item.get("link"))] if item.get("link") else [],
                )
            )
        return out
