import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

# Get Redis broker URL from .env or default to localhost
broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')

# 1. Connect to the Redis queue
celery_app = Celery(
    'switchguard_tasks',
    broker=broker_url,
    backend=broker_url
)

# 2. Tell the worker where to find the scan logic
# This connects the worker to your nmap_scanner.py and zap_scanner.py files
celery_app.conf.imports = (
    'scanners.nmap_scanner',
    'scanners.zap_scanner'
)