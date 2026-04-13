"""VulnSuite - Subfinder wrapper for passive subdomain discovery."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from ...core.schema import Asset, AssetType, ExposureFactor


class SubfinderNotInstalled(RuntimeError):
    pass


class SubfinderCollector:
    def __init__(
        self,
        binary: str = "subfinder",
        timeout_seconds: int = 900,
        max_results_per_root: int = 500,
    ) -> None:
        if shutil.which(binary) is None:
            raise SubfinderNotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.timeout = timeout_seconds
        self.max_results_per_root = max_results_per_root

    async def enumerate(self, root_domains: list[str]) -> list[str]:
        if not root_domains:
            return []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(root_domains))
            input_path = tmp.name

        cmd = [self.binary, "-silent", "-json", "-dL", input_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        finally:
            Path(input_path).unlink(missing_ok=True)

        if proc.returncode != 0:
            raise RuntimeError(
                f"subfinder exit {proc.returncode}: {stderr.decode(errors='ignore')[:500]}"
            )

        hosts: list[str] = []
        seen: set[str] = set()
        per_root: dict[str, int] = {}
        for line in stdout.decode(errors="ignore").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            host = str(item.get("host") or item.get("domain") or "").strip()
            root = str(item.get("input") or "").strip()
            if not host or host in seen:
                continue
            if root and per_root.get(root, 0) >= self.max_results_per_root:
                continue
            seen.add(host)
            hosts.append(host)
            if root:
                per_root[root] = per_root.get(root, 0) + 1
        return hosts

    async def discover(self, tenant_id: UUID, root_domains: list[str]) -> list[Asset]:
        hosts = await self.enumerate(root_domains)
        return [
            Asset(
                tenant_id=tenant_id,
                name=host,
                asset_type=AssetType.DOMAIN,
                criticality=3,
                exposure=ExposureFactor.INTERNET,
                tags={
                    "domain": host,
                    "root_domain": next((root for root in root_domains if host.endswith(root)), host),
                    "source": "subfinder",
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            for host in hosts
        ]
