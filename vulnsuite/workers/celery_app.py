"""VulnSuite - Celery app configuration."""
from __future__ import annotations

from celery import Celery

from ..core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vulnsuite",
    broker=settings.redis.url,
    backend=settings.redis.url,
    include=["vulnsuite.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Kolkata",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=7200,
    task_soft_time_limit=6900,
    task_default_queue="vulnsuite.default",
    task_routes={
        "vulnsuite.workers.tasks.scan_asset": {"queue": "vulnsuite.scan"},
        "vulnsuite.workers.tasks.discover_assets": {"queue": "vulnsuite.discovery"},
        "vulnsuite.workers.tasks.discover_azure_assets": {"queue": "vulnsuite.discovery"},
        "vulnsuite.workers.tasks.discover_aws_assets": {"queue": "vulnsuite.discovery"},
        "vulnsuite.workers.tasks.discover_gcp_assets": {"queue": "vulnsuite.discovery"},
        "vulnsuite.workers.tasks.discover_domains": {"queue": "vulnsuite.discovery"},
        "vulnsuite.workers.tasks.discover_kubernetes_clusters": {"queue": "vulnsuite.discovery"},
        "vulnsuite.workers.tasks.generate_report": {"queue": "vulnsuite.report"},
        # AI enrichment is long-running (Batches API polling) and must
        # never compete with scan workers for slots.
        "vulnsuite.workers.tasks.ai_enrich_findings": {"queue": "vulnsuite.ai"},
    },
    beat_schedule={
        "daily-azure-discovery": {
            "task": "vulnsuite.workers.tasks.discover_assets",
            "schedule": 86400.0,   # every 24h
        },
    },
)
