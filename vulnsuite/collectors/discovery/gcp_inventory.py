"""VulnSuite - GCP inventory collector using gcloud asset search."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from uuid import UUID

from ...core.schema import Asset, AssetType, ExposureFactor

logger = logging.getLogger(__name__)

_PUBLIC_TYPES = {
    "compute.googleapis.com/ForwardingRule",
    "run.googleapis.com/Service",
    "compute.googleapis.com/Address",
    "apigateway.googleapis.com/Gateway",
}


class GCloudNotInstalled(RuntimeError):
    pass


class GCPInventoryCollector:
    def __init__(self, binary: str = "gcloud") -> None:
        if shutil.which(binary) is None:
            raise GCloudNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary

    async def discover(
        self,
        tenant_id: UUID,
        project_ids: list[str],
        env: dict[str, str] | None = None,
    ) -> list[Asset]:
        """`env` is the tenant-scoped gcloud environment (service-account
        file + project) from core.cloud_accounts; None inherits the worker env."""
        assets: list[Asset] = []
        for project_id in project_ids:
            rows = await self._run_search(project_id, env)
            for row in rows:
                asset_type = str(row.get("assetType") or "")
                name = str(row.get("displayName") or row.get("name") or "gcp-resource")
                assets.append(
                    Asset(
                        tenant_id=tenant_id,
                        name=name,
                        asset_type=AssetType.CLOUD_RESOURCE,
                        criticality=4,
                        exposure=ExposureFactor.INTERNET if asset_type in _PUBLIC_TYPES else ExposureFactor.INTERNAL,
                        tags={
                            "gcp_full_name": str(row.get("name") or ""),
                            "gcp_project": project_id,
                            "gcp_asset_type": asset_type,
                            "location": str(row.get("location") or ""),
                            "source": "gcloud",
                        },
                    )
                )
        return assets

    async def _run_search(
        self, project_id: str, env: dict[str, str] | None = None,
    ) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            "asset",
            "search-all-resources",
            "--scope",
            f"projects/{project_id}",
            "--format=json",
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"gcloud asset search failed: {stderr.decode(errors='ignore')[:500]}"
            )
        payload = json.loads(stdout or "[]")
        return payload if isinstance(payload, list) else []
