import logging
from src.celery_app import app
from src.utils import post_to_backend, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


@app.task(name='src.tasks.trigger_scheduled_scans')
def trigger_scheduled_scans():
    """
    Periodic task to trigger scheduled scans check on backend.
    """
    logger.info("Checking for scheduled scans...")
    try:
        resp = post_to_backend("/scans/check-schedules", {}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"Scheduled scans check completed. Triggered: {len(data.get('triggered_scans', []))}")
    except Exception as e:
        logger.error(f"Failed to check scheduled scans: {e}", exc_info=True)
