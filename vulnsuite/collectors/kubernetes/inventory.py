"""VulnSuite - Kubernetes inventory helpers for cluster discovery and image correlation."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import yaml

from ...core.schema import Asset, AssetType, ExposureFactor

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkloadImageRef:
    cluster: str
    namespace: str
    kind: str
    name: str
    image: str


class KubectlNotInstalled(RuntimeError):
    pass


class KubernetesInventoryCollector:
    def __init__(self, binary: str = "kubectl") -> None:
        if shutil.which(binary) is None:
            raise KubectlNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary

    async def discover_clusters(
        self,
        tenant_id: UUID,
        kubeconfig_path: str | None = None,
    ) -> list[Asset]:
        config = self._load_kubeconfig(kubeconfig_path)
        contexts = config.get("contexts", []) or []
        assets: list[Asset] = []
        for context in contexts:
            name = str(context.get("name") or "")
            cluster_name = str((context.get("context") or {}).get("cluster") or name)
            if not cluster_name:
                continue
            assets.append(
                Asset(
                    tenant_id=tenant_id,
                    name=cluster_name,
                    asset_type=AssetType.KUBERNETES_CLUSTER,
                    criticality=4,
                    exposure=ExposureFactor.INTERNAL,
                    tags={
                        "cluster": cluster_name,
                        "context": name,
                        "source": "kubeconfig",
                    },
                )
            )
        return assets

    async def list_workload_images(
        self,
        kube_context: str | None = None,
        kubeconfig_path: str | None = None,
    ) -> list[WorkloadImageRef]:
        cmd = [
            self.binary,
            "get",
            "deploy,statefulset,daemonset,pod",
            "--all-namespaces",
            "-o",
            "json",
        ]
        if kube_context:
            cmd += ["--context", kube_context]
        if kubeconfig_path:
            cmd += ["--kubeconfig", kubeconfig_path]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"kubectl exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )

        payload = json.loads(stdout or "{}")
        items = payload.get("items", []) or []
        cluster = kube_context or "default"
        refs: list[WorkloadImageRef] = []
        for item in items:
            metadata = item.get("metadata", {}) or {}
            spec = item.get("spec", {}) or {}
            template = (spec.get("template") or {}).get("spec") or spec
            containers = template.get("containers", []) or []
            for container in containers:
                image = str(container.get("image") or "").strip()
                if not image:
                    continue
                refs.append(
                    WorkloadImageRef(
                        cluster=cluster,
                        namespace=str(metadata.get("namespace") or "default"),
                        kind=str(item.get("kind") or "Unknown"),
                        name=str(metadata.get("name") or image),
                        image=image,
                    )
                )
        return refs

    @staticmethod
    def _load_kubeconfig(kubeconfig_path: str | None) -> dict:
        path = kubeconfig_path or os.getenv("KUBECONFIG") or str(Path.home() / ".kube" / "config")
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"kubeconfig not found: {path}")
        return yaml.safe_load(p.read_text()) or {}
