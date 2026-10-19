"""VulnSuite - AWS inventory collector using AWS CLI.

When a tenant role is configured, the worker's base identity is used for
exactly one call — `sts assume-role` — and every inventory call then runs
with the temporary tenant credentials in a scrubbed environment.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from uuid import UUID

from ...core.cloud_accounts import scoped_env
from ...core.schema import Asset, AssetType, ExposureFactor

logger = logging.getLogger(__name__)


class AWSCLINotInstalled(RuntimeError):
    pass


class AWSInventoryCollector:
    def __init__(
        self,
        binary: str = "aws",
        region: str = "ap-south-1",
        role_arn: str | None = None,
        external_id: str | None = None,
        session_name: str = "vulnsuite-discovery",
    ) -> None:
        if shutil.which(binary) is None:
            raise AWSCLINotInstalled(f"{binary!r} not found on PATH")
        self.binary = binary
        self.region = region
        self.role_arn = role_arn
        self.external_id = external_id
        self.session_name = session_name

    async def discover(self, tenant_id: UUID, account_ids: list[str]) -> list[Asset]:
        env = await self._session_env() if self.role_arn else None
        assets: list[Asset] = []
        for lb in await self._run_json("elbv2", "describe-load-balancers", env=env):
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
        for ip in await self._run_json("ec2", "describe-addresses", env=env):
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

    async def _session_env(self) -> dict[str, str]:
        """Assume the tenant role and return a scrubbed env carrying only
        the temporary credentials."""
        cmd = [
            self.binary, "sts", "assume-role",
            "--role-arn", self.role_arn,
            "--role-session-name", self.session_name,
            "--output", "json",
        ]
        if self.external_id:
            cmd += ["--external-id", self.external_id]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"aws sts assume-role {self.role_arn} failed: "
                f"{stderr.decode(errors='ignore')[:500]}"
            )
        creds = (json.loads(stdout or "{}") or {}).get("Credentials") or {}
        try:
            overrides = {
                "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
                "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
                "AWS_SESSION_TOKEN": creds["SessionToken"],
            }
        except KeyError as exc:
            raise RuntimeError("aws sts assume-role returned no credentials") from exc
        return scoped_env("aws", overrides)

    async def _run_json(self, *service_args: str, env: dict[str, str] | None = None) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *service_args,
            "--region",
            self.region,
            "--output",
            "json",
            env=env,
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
