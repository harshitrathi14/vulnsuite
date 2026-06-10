"""VulnSuite - Asset auto-criticality from tags.

Discovery collectors import assets with a default criticality, which
makes every risk score downstream a guess. These rules derive honest
criticality and exposure from the tags cloud providers already attach
(environment, data classification, public-facing), so a production
PCI database scores higher than a dev sandbox without an analyst
hand-curating thousands of discovered assets.

Rules only ever *raise* criticality (max), never lower it — an analyst
who set criticality=5 by hand is never overridden down to a tag default.
"""
from __future__ import annotations

import logging

from .schema import Asset, ExposureFactor

logger = logging.getLogger(__name__)


def _tag_universe(asset: Asset) -> set[str]:
    """All tag keys and values, lowercased, for substring/exact matching."""
    out: set[str] = set()
    for key, value in (asset.tags or {}).items():
        out.add(str(key).lower().strip())
        out.add(str(value).lower().strip())
    return out


def _matches(universe: set[str], needles: list[str]) -> bool:
    for token in universe:
        for needle in needles:
            if token == needle or needle in token:
                return True
    return False


def apply_asset_rules(asset: Asset, policy) -> Asset:
    """Return an asset with criticality/exposure adjusted from its tags.

    ``policy`` is a config.AssetPolicySettings. When auto_criticality is
    off, the asset is returned unchanged.
    """
    if not getattr(policy, "auto_criticality", False):
        return asset

    universe = _tag_universe(asset)
    if not universe:
        return asset

    criticality = asset.criticality
    if _matches(universe, policy.prod_tags):
        criticality = max(criticality, 5)
    elif _matches(universe, policy.staging_tags):
        criticality = max(criticality, 3)
    # dev/sandbox tags intentionally do NOT lower an explicit criticality.

    # Sensitive data classification bumps one notch (capped at 5).
    if _matches(universe, policy.sensitive_tags):
        criticality = min(5, criticality + 1)

    exposure = asset.exposure
    if _matches(universe, policy.internet_tags) or asset.tags.get("public_ip"):
        exposure = ExposureFactor.INTERNET

    if criticality == asset.criticality and float(exposure) == float(asset.exposure):
        return asset

    logger.debug(
        "asset rules: %s criticality %d->%d exposure %.1f->%.1f",
        asset.name, asset.criticality, criticality,
        float(asset.exposure), float(exposure),
    )
    return asset.model_copy(update={"criticality": criticality, "exposure": exposure})
