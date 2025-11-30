import os
from celery import Celery

def create_celery_app():
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    app = Celery('backend_producer', broker=redis_url, backend=redis_url)
    
    # Optional: Configure Celery options if needed to match workers
    app.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
    )
    return app

celery_app = create_celery_app()
