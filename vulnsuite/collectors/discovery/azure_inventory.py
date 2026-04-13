"""VulnSuite - Azure asset discovery via Resource Graph.

Enumerates Azure resources across all accessible subscriptions using
Azure Resource Graph (KQL) and converts them into VulnSuite `Asset`
objects with BFSI-appropriate criticality/exposure defaults.

Auth: DefaultAzureCredential chain (managed identity in prod, env
vars in dev, az CLI as a fallback). Read-only: requires only the
'Reader' role at the subscription or management-group scope.

Requires: azure-identity, azure-mgmt-resourcegraph, azure-mgmt-subscription.
"""
from __future__ import annotations

import asyncio
import logging
from uuid import UUID, uuid4

from azure.identity.aio import DefaultAzureCredential
from azure.mgmt.resourcegraph.aio import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.mgmt.subscription.aio import SubscriptionClient

from ...core.schema import Asset, AssetType, ExposureFactor

logger = logging.getLogger(__name__)

# KQL query — captures all resources with fields we need to infer
# criticality and exposure. Filters out transient/system resources.
_QUERY = """
Resources
| where type !in~ (
    'microsoft.resources/deployments',
    'microsoft.resources/deploymentscripts',
    'microsoft.alertsmanagement/smartdetectoralertrules'
)
| project id, name, type, location, subscriptionId,
          resourceGroup, tags, properties
| order by type asc, name asc
"""

# Public-surface resource types that default to ExposureFactor.INTERNET
_INTERNET_FACING_TYPES = {
    "microsoft.network/publicipaddresses",
    "microsoft.network/applicationgateways",
    "microsoft.network/frontdoors",
    "microsoft.cdn/profiles",
    "microsoft.web/sites",
    "microsoft.apimanagement/service",
    "microsoft.network/loadbalancers",
}

# Heuristic: resources tagged as prod / tier-0 bump criticality to 5
_PROD_TAG_VALUES = {"prod", "production", "tier0", "tier-0", "critical"}


class AzureInventoryCollector:
    def __init__(
        self,
        page_size: int = 1000,
        management_groups: tuple[str, ...] | None = None,
    ) -> None:
        self.page_size = page_size
        self.management_groups = management_groups

    async def discover(self, tenant_id: UUID) -> list[Asset]:
        cred = DefaultAzureCredential()
        try:
            sub_ids = await self._list_subscriptions(cred)
            if not sub_ids:
                logger.warning("no Azure subscriptions accessible")
                return []

            assets: list[Asset] = []
            async with ResourceGraphClient(credential=cred) as rg:
                rows = await self._query_all(rg, sub_ids)
                for row in rows:
                    assets.append(self._to_asset(row, tenant_id))
            logger.info("discovered %d Azure assets", len(assets))
            return assets
        finally:
            await cred.close()

    async def _list_subscriptions(
        self, cred: DefaultAzureCredential,
    ) -> list[str]:
        async with SubscriptionClient(credential=cred) as sub_client:
            subs: list[str] = []
            async for s in sub_client.subscriptions.list():
                if s.subscription_id and s.state == "Enabled":
                    subs.append(s.subscription_id)
            return subs

    async def _query_all(
        self, rg: ResourceGraphClient, sub_ids: list[str],
    ) -> list[dict]:
        """Paginate through Resource Graph results."""
        all_rows: list[dict] = []
        skip_token: str | None = None
        while True:
            opts = QueryRequestOptions(
                top=self.page_size,
                skip_token=skip_token,
            )
            req = QueryRequest(
                subscriptions=sub_ids,
                management_groups=list(self.management_groups or []) or None,
                query=_QUERY,
                options=opts,
            )
            resp = await rg.resources(req)
            data = resp.data or []
            if isinstance(data, list):
                all_rows.extend(data)
            skip_token = getattr(resp, "skip_token", None)
            if not skip_token:
                break
            await asyncio.sleep(0)  # cooperative yield
        return all_rows

    # ---------- mapping ----------

    def _to_asset(self, row: dict, tenant_id: UUID) -> Asset:
        res_type = (row.get("type") or "").lower()
        tags = row.get("tags") or {}
        name = row.get("name") or row.get("id") or "unknown"

        criticality = self._infer_criticality(tags)
        exposure = (
            ExposureFactor.INTERNET
            if res_type in _INTERNET_FACING_TYPES
            else ExposureFactor.INTERNAL
        )
        asset_type = self._map_type(res_type)

        return Asset(
            asset_id=uuid4(),
            tenant_id=tenant_id,
            name=name,
            asset_type=asset_type,
            criticality=criticality,
            exposure=exposure,
            owner=(tags.get("owner") or tags.get("Owner")),
            tags={
                "azure_id": row.get("id", ""),
                "azure_type": res_type,
                "resource_group": row.get("resourceGroup", ""),
                "subscription": row.get("subscriptionId", ""),
                "location": row.get("location", ""),
                **{f"tag.{k}": str(v) for k, v in tags.items()},
            },
        )

    @staticmethod
    def _infer_criticality(tags: dict) -> int:
        env_val = (
            tags.get("environment") or tags.get("Environment")
            or tags.get("env") or ""
        ).lower()
        tier_val = (tags.get("tier") or tags.get("Tier") or "").lower()
        if env_val in _PROD_TAG_VALUES or tier_val in _PROD_TAG_VALUES:
            return 5
        if env_val in ("staging", "uat", "preprod", "pre-prod"):
            return 3
        if env_val in ("dev", "development", "sandbox", "test"):
            return 1
        return 3  # unknown -> medium, defensible default

    @staticmethod
    def _map_type(azure_type: str) -> AssetType:
        if "microsoft.compute/virtualmachines" in azure_type:
            return AssetType.HOST
        if "microsoft.containerregistry" in azure_type:
            return AssetType.IMAGE
        if "microsoft.containerservice" in azure_type:
            return AssetType.HOST
        if any(db in azure_type for db in (
            "microsoft.sql", "microsoft.dbfor", "microsoft.documentdb",
            "microsoft.cache",
        )):
            return AssetType.DATABASE
        return AssetType.CLOUD_RESOURCE
