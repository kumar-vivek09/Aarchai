"""Celery app — Redis broker for async stage execution."""
from celery import Celery
from config import REDIS_URL

celery_app = Celery(
    "aarchai",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "stages.stage1_passive",
        "stages.stage2_active",
        "stages.stage3_web",
        "stages.stage4_vulns",
        "stages.stage5_intel",
        "stages.stage6_report",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)
