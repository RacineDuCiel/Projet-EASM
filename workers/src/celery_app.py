import os
from celery import Celery
from celery.signals import worker_ready
from src.core.logging import setup_logging

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000/api/v1")

app = Celery('easm_worker', broker=REDIS_URL, backend=REDIS_URL)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    worker_send_task_events=True,
    task_send_sent_event=True,
    task_track_started=True,
)

@worker_ready.connect
def configure_logging(sender=None, **kwargs):
    setup_logging()

# Imports tasks to register them
import src.tasks.discovery
import src.tasks.scan
import src.tasks.maintenance
import src.tasks.scheduler
from celery.schedules import crontab

app.conf.beat_schedule = {
    'check-scheduled-scans-every-hour': {
        'task': 'src.tasks.trigger_scheduled_scans',
        'schedule': crontab(minute=0), # Every hour
    },
}
