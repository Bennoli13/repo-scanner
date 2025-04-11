import os
import time
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from functools import partial

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Load env
load_dotenv()
API_BASE = os.getenv("API_BASE", "http://localhost:5001")
scheduler = BackgroundScheduler()

def enqueue_scan_job(source_id, repo_id, scanner_name):
    payload = {
        "source_id": source_id,
        "repo_ids": [repo_id] if repo_id else [],
        "scanners": [scanner_name]
    }
    try:
        res = requests.post(f"{API_BASE}/api/scan", json=payload)
        if res.ok:
            logger.info(f"✅ Triggered scan: {payload}")
        else:
            logger.error(f"❌ Failed to trigger scan: {res.text}")
    except Exception as e:
        logger.exception(f"🔥 API request failed for job {payload}: {e}")

def scheduled_scan_runner(scan):
    try:
        enqueue_scan_job(scan["source_id"], scan["repo_id"], scan["scanner_name"])
        logger.info(f"⏱️ Scan triggered for repo_id={scan['repo_id'] or 'ALL'} using {scan['scanner_name']}")
        # ✅ Update last_run after enqueueing
        requests.patch(f"{API_BASE}/api/schedule/{scan['id']}/mark-run")
    except Exception as e:
        logger.exception(f"🔥 Failed scheduled scan (ID={scan['id']}): {e}")

def register_all_scheduled_jobs():
    try:
        res = requests.get(f"{API_BASE}/api/schedule")
        scans = res.json() if res.ok else []
        db_ids = {f"scan-{scan['id']}" for scan in scans}
        scheduled_ids = {job.id for job in scheduler.get_jobs() if job.id != "auto-sync"}

        for job_id in scheduled_ids - db_ids:
            scheduler.remove_job(job_id)
            logger.info(f"🧹 Removed job no longer in DB: {job_id}")

        for scan in scans:
            job_id = f"scan-{scan['id']}"
            day = scan.get("cron_day", "*")
            hour = scan.get("cron_hour", 0)
            minute = scan.get("cron_minute", 0)

            scheduler.add_job(
                func=partial(scheduled_scan_runner, scan),
                trigger='cron',
                day_of_week=day,
                hour=hour,
                minute=minute,
                id=job_id,
                replace_existing=True
            )
            logger.info(f"📅 Registered job {job_id}: {day} at {hour:02}:{minute:02}")

    except Exception as e:
        logger.exception("🔥 Failed to sync jobs from API")

def auto_sync_job_registry():
    logger.info("🔄 Syncing scheduled jobs from API...")
    register_all_scheduled_jobs()

# Start
register_all_scheduled_jobs()
scheduler.add_job(auto_sync_job_registry, trigger='interval', minutes=5, id="auto-sync")
scheduler.start()
logger.info("🚀 Scheduler started")

try:
    while True:
        time.sleep(60)
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()
    logger.info("👋 Scheduler stopped")
