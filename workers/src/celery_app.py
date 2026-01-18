import json
import logging
import os
from datetime import datetime, timezone

from celery import Celery
from celery.signals import worker_ready, task_failure, task_retry
from src.core.logging import setup_logging, get_logger

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000/api/v1")
WORKER_SECRET_TOKEN = os.getenv("WORKER_SECRET_TOKEN", "change-me-in-production-use-secrets-token-hex-32")

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
    # Task result expiration (keep failed results longer for debugging)
    result_expires=86400 * 7,  # 7 days
)


@worker_ready.connect
def configure_logging(sender=None, **kwargs):
    setup_logging()


@task_failure.connect
def handle_task_failure(
    sender=None,
    task_id=None,
    exception=None,
    args=None,
    kwargs=None,
    traceback=None,
    einfo=None,
    **kw
):
    """
    Handle failed tasks by storing them in a Dead Letter Queue.

    Failed tasks are stored in Redis with task details for later inspection
    and potential retry.
    """
    logger = get_logger(__name__, task_id=task_id)
    logger.error(
        f"Task failed: {sender.name if sender else 'unknown'}",
        extra={
            "task_name": sender.name if sender else "unknown",
            "exception": str(exception),
            "args": str(args)[:500],  # Truncate to avoid huge logs
        }
    )

    # Store in Redis DLQ
    try:
        redis_client = app.backend.client
        dlq_key = f"dlq:{task_id}"

        dlq_entry = {
            "task_id": task_id,
            "task_name": sender.name if sender else "unknown",
            "args": json.dumps(args, default=str) if args else "[]",
            "kwargs": json.dumps(kwargs, default=str) if kwargs else "{}",
            "exception": str(exception),
            "traceback": str(traceback) if traceback else "",
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }

        redis_client.hset(dlq_key, mapping=dlq_entry)
        redis_client.expire(dlq_key, 86400 * 30)  # Keep for 30 days

        logger.info(f"Task stored in DLQ: {dlq_key}")

        # Try to notify backend about scan failure
        if args and len(args) > 1:
            scan_id = args[1] if len(args) > 1 else kwargs.get('scan_id')
            if scan_id:
                try:
                    from src.utils import log_event
                    log_event(
                        scan_id,
                        f"Task failed: {str(exception)[:200]}",
                        severity="error"
                    )
                except Exception as notify_error:
                    logger.warning(f"Could not notify backend of failure: {notify_error}")

    except Exception as e:
        logger.error(f"Failed to store task in DLQ: {e}")


@task_retry.connect
def handle_task_retry(
    sender=None,
    request=None,
    reason=None,
    einfo=None,
    **kw
):
    """Log task retries for monitoring."""
    logger = get_logger(__name__)
    logger.warning(
        f"Task retry: {sender.name if sender else 'unknown'}",
        extra={
            "task_name": sender.name if sender else "unknown",
            "task_id": request.id if request else "unknown",
            "reason": str(reason)[:200],
        }
    )

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
