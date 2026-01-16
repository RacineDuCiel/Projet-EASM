"""
Dead Letter Queue management utilities.

Provides functions to inspect, retry, and clear failed tasks.
"""
import json
from typing import Dict, List, Optional

from src.celery_app import app
from src.core.logging import get_logger

logger = get_logger(__name__)


def get_failed_tasks(limit: int = 100) -> List[Dict]:
    """
    Retrieve failed tasks from the Dead Letter Queue.

    Args:
        limit: Maximum number of tasks to retrieve

    Returns:
        List of failed task dictionaries
    """
    try:
        redis_client = app.backend.client
        keys = redis_client.keys("dlq:*")

        tasks = []
        for key in keys[:limit]:
            task_data = redis_client.hgetall(key)
            if task_data:
                # Decode bytes to strings
                decoded = {
                    k.decode() if isinstance(k, bytes) else k:
                    v.decode() if isinstance(v, bytes) else v
                    for k, v in task_data.items()
                }
                decoded['dlq_key'] = key.decode() if isinstance(key, bytes) else key
                tasks.append(decoded)

        # Sort by failed_at descending
        tasks.sort(key=lambda x: x.get('failed_at', ''), reverse=True)
        return tasks

    except Exception as e:
        logger.error(f"Failed to retrieve DLQ tasks: {e}")
        return []


def get_failed_task(task_id: str) -> Optional[Dict]:
    """
    Retrieve a specific failed task from the DLQ.

    Args:
        task_id: The task ID to retrieve

    Returns:
        Task dictionary or None if not found
    """
    try:
        redis_client = app.backend.client
        dlq_key = f"dlq:{task_id}"
        task_data = redis_client.hgetall(dlq_key)

        if not task_data:
            return None

        return {
            k.decode() if isinstance(k, bytes) else k:
            v.decode() if isinstance(v, bytes) else v
            for k, v in task_data.items()
        }

    except Exception as e:
        logger.error(f"Failed to retrieve DLQ task {task_id}: {e}")
        return None


def retry_failed_task(task_id: str) -> bool:
    """
    Retry a specific failed task from the DLQ.

    Args:
        task_id: The task ID to retry

    Returns:
        True if the task was successfully re-queued, False otherwise
    """
    try:
        redis_client = app.backend.client
        dlq_key = f"dlq:{task_id}"

        task_data = redis_client.hgetall(dlq_key)
        if not task_data:
            logger.warning(f"Task {task_id} not found in DLQ")
            return False

        # Decode
        task_name = task_data.get(b'task_name', b'').decode()
        args_str = task_data.get(b'args', b'[]').decode()
        kwargs_str = task_data.get(b'kwargs', b'{}').decode()

        args = json.loads(args_str)
        kwargs = json.loads(kwargs_str)

        # Re-queue the task
        app.send_task(task_name, args=args, kwargs=kwargs)

        # Remove from DLQ
        redis_client.delete(dlq_key)

        logger.info(f"Task {task_id} re-queued and removed from DLQ")
        return True

    except Exception as e:
        logger.error(f"Failed to retry task {task_id}: {e}")
        return False


def delete_failed_task(task_id: str) -> bool:
    """
    Delete a specific failed task from the DLQ without retrying.

    Args:
        task_id: The task ID to delete

    Returns:
        True if deleted, False otherwise
    """
    try:
        redis_client = app.backend.client
        dlq_key = f"dlq:{task_id}"
        result = redis_client.delete(dlq_key)

        if result:
            logger.info(f"Task {task_id} deleted from DLQ")
            return True
        else:
            logger.warning(f"Task {task_id} not found in DLQ")
            return False

    except Exception as e:
        logger.error(f"Failed to delete task {task_id}: {e}")
        return False


def clear_dlq() -> int:
    """
    Clear all failed tasks from the DLQ.

    Returns:
        Number of tasks cleared
    """
    try:
        redis_client = app.backend.client
        keys = redis_client.keys("dlq:*")

        if keys:
            redis_client.delete(*keys)
            logger.info(f"Cleared {len(keys)} tasks from DLQ")
            return len(keys)

        return 0

    except Exception as e:
        logger.error(f"Failed to clear DLQ: {e}")
        return 0


def get_dlq_stats() -> Dict:
    """
    Get statistics about the Dead Letter Queue.

    Returns:
        Dictionary with DLQ statistics
    """
    try:
        redis_client = app.backend.client
        keys = redis_client.keys("dlq:*")

        # Group by task name
        task_counts = {}
        for key in keys:
            task_data = redis_client.hgetall(key)
            if task_data:
                task_name = task_data.get(b'task_name', b'unknown').decode()
                task_counts[task_name] = task_counts.get(task_name, 0) + 1

        return {
            "total_failed": len(keys),
            "by_task": task_counts,
        }

    except Exception as e:
        logger.error(f"Failed to get DLQ stats: {e}")
        return {"total_failed": 0, "by_task": {}}
