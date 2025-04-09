import os
import time
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from app import create_app, db
from app.models import ScheduledScan

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Load env and app
load_dotenv()
app = create_app()

API_BASE = os.getenv("API_BASE", "http://localhost:5001")
scheduler = BackgroundScheduler()

# Enqueue the scan job via API
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

# This function is executed by APScheduler
def scheduled_scan_runner(scan_id):
    with app.app_context():
        try:
            scan = ScheduledScan.query.get(scan_id)
            if not scan:
                logger.warning(f"⚠️ ScheduledScan ID {scan_id} not found")
                try:
                    job_id = f"scan-{scan_id}"
                    scheduler.remove_job(job_id)
                    logger.info(f"🧹 Removed stale APScheduler job: {job_id}")
                except Exception as cleanup_error:
                    logger.warning(f"⚠️ Failed to remove job {job_id}: {cleanup_error}")
                return

            enqueue_scan_job(scan.source_id, scan.repo_id, scan.scanner_name)
            scan.last_run = datetime.utcnow()
            db.session.commit()
            logger.info(f"⏱️ Cron-based scan triggered for repo_id={scan.repo_id or 'ALL'} using {scan.scanner_name}")
        except Exception as e:
            logger.exception(f"🔥 Failed to process scheduled scan (ID={scan_id}): {e}")

# Register all jobs from DB and clean up removed ones
def register_all_scheduled_jobs():
    with app.app_context():
        scans = ScheduledScan.query.all()
        db_ids = {f"scan-{scan.id}" for scan in scans}
        scheduled_ids = {job.id for job in scheduler.get_jobs() if job.id != "auto-sync"}

        # Remove orphaned jobs
        for job_id in scheduled_ids - db_ids:
            scheduler.remove_job(job_id)
            logger.info(f"🧹 Removed job no longer in DB: {job_id}")

        # Add or update jobs from DB
        for scan in scans:
            job_id = f"scan-{scan.id}"
            day = scan.cron_day or '*'
            hour = scan.cron_hour or 0
            minute = scan.cron_minute or 0
            try:
                scheduler.add_job(
                    func=lambda sid=scan.id: scheduled_scan_runner(sid),
                    trigger='cron',
                    day_of_week=day,
                    hour=hour,
                    minute=minute,
                    id=job_id,
                    replace_existing=True
                )
                logger.info(f"📅 Registered job {job_id}: {day} at {hour:02}:{minute:02}")
            except Exception as e:
                logger.warning(f"⚠️ Failed to register job {job_id}: {e}")

# Auto-refresh job registration every 5 minutes
def auto_sync_job_registry():
    logger.info("🔄 Syncing scheduled jobs from DB...")
    register_all_scheduled_jobs()

# Bootstrap everything
register_all_scheduled_jobs()
scheduler.add_job(auto_sync_job_registry, trigger='interval', minutes=5, id="auto-sync")
scheduler.start()
logger.info("🚀 Scheduler started and jobs loaded")

# Keep process alive
try:
    while True:
        time.sleep(60)
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()
    logger.info("👋 Scheduler stopped")
except Exception as e:
    logger.exception(f"🔥 Unhandled exception in scheduler loop: {e}")
