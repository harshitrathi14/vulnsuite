"""VulnSuite - AWS inventory collector using AWS CLI."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from uuid import UUID

from ...core.schema import Asset, AssetType, ExposureFactor

logger = logging.getLogger(__name__)


class AWSCLINotInstalled(RuntimeError):
    pass


class AWSInventoryCollector:
    def __init__(self, binary: str = "aws", region: str = "ap-south-1") -> None:
        if shutil.which(binary) is None:
            raise AWSCLINotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.region = region

    async def discover(self, tenant_id: UUID, account_ids: list[str]) -> list[Asset]:
        assets: list[Asset] = []
        for lb in await self._run_json("elbv2", "describe-load-balancers"):
            dns_name = str(lb.get("DNSName") or "")
            scheme = str(lb.get("Scheme") or "")
            assets.append(
                Asset(
                    tenant_id=tenant_id,
                    name=str(lb.get("LoadBalancerName") or dns_name or "aws-lb"),
                    asset_type=AssetType.CLOUD_RESOURCE,
                    criticality=4,
                    exposure=ExposureFactor.INTERNET if scheme == "internet-facing" else ExposureFactor.INTERNAL,
                    tags={
                        "aws_arn": str(lb.get("LoadBalancerArn") or ""),
                        "aws_account": ",".join(account_ids),
                        "dns_name": dns_name,
                        "source": "aws-cli",
                    },
                )
            )
        for ip in await self._run_json("ec2", "describe-addresses"):
            public_ip = str(ip.get("PublicIp") or "")
            if not public_ip:
                continue
            assets.append(
                Asset(
                    tenant_id=tenant_id,
                    name=public_ip,
                    asset_type=AssetType.ENDPOINT,
                    criticality=3,
                    exposure=ExposureFactor.INTERNET,
                    tags={
                        "aws_arn": str(ip.get("AllocationId") or ""),
                        "aws_account": ",".join(account_ids),
                        "public_ip": public_ip,
                        "source": "aws-cli",
                    },
                )
            )
        return assets

    async def _run_json(self, *service_args: str) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *service_args,
            "--region",
            self.region,
            "--output",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"aws {' '.join(service_args)} failed: {stderr.decode(errors='ignore')[:500]}"
            )
        payload = json.loads(stdout or "{}")
        for key in ("LoadBalancers", "Addresses", "Items"):
            if key in payload and isinstance(payload[key], list):
                return payload[key]
        return []
