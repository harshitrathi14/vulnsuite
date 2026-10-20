"""Scheduled Bandit analysis of VulnSuite source only, with persisted findings."""
import asyncio
import json
import os
from pathlib import Path
import time
from uuid import UUID
from vulnsuite.collectors.sast.bandit import BanditCollector
from vulnsuite.core.db import upsert_assets
from vulnsuite.core.schema import Asset, AssetType
from vulnsuite.core.orchestrator import Orchestrator
from vulnsuite.core.risk_engine import RiskEngine

ROOT=Path('/mnt/harshitrathi/vulnsuite')
async def main():
    tenant=UUID('00000000-0000-0000-0000-000000000001')
    asset=Asset(asset_id=UUID('196080ac-18a6-4cfb-9b79-fb408fd5489c'),tenant_id=tenant,name='VulnSuite source (local Bandit SAST)',asset_type=AssetType.REPO,criticality=3)
    await upsert_assets(tenant,[asset])
    result=await BanditCollector().scan(str(ROOT/'vulnsuite'),tenant,asset.asset_id)
    if result.errors:
        raise RuntimeError('; '.join(result.errors))
    async def collected(): return result
    report=await Orchestrator(RiskEngine()).run(asset,[collected])
    if report.errors:
        raise RuntimeError('; '.join(report.errors))
    data={'last_success':time.time(),'tool':'bandit','target':'VulnSuite source only','findings':report.persisted_count,'new':report.new_count,'fixed':report.fixed_count,'schedule':'hourly'}
    tmp=ROOT/'runtime/local-scan.json.tmp';tmp.write_text(json.dumps(data));tmp.replace(ROOT/'runtime/local-scan.json')
    print(json.dumps(data))
if __name__=='__main__': asyncio.run(main())
