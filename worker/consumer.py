import pika
import json
import requests
import time
from datetime import datetime
import os
from cryptography.fernet import Fernet
import logging
from . import scanner_module
from urllib.parse import urlparse

#scanner
from . import trufflehog_proc
from . import trivy_proc
from . import gitleaks_proc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Load from environment — these are set via init_worker.py + .env
API_BASE = os.environ.get("API_BASE")
FERNET_KEY = os.environ.get("FERNET_KEY")
fernet = Fernet(FERNET_KEY)
rabbitmq_user = os.getenv("RABBITMQ_USER", "guest")
rabbitmq_pass = os.getenv("RABBITMQ_PASS", "guest")
rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")

def decrypt_token(token_encrypted):
    return fernet.decrypt(token_encrypted.encode()).decode()

def update_total_branch(job_id, total):
    try:
        res = requests.patch(
            f"{API_BASE}/api/scan/{job_id}/set-total-branches",
            json={"total_branch": total}
        )
        if res.ok:
            logging.info(f"✅ Total branch count set to {total} for job_id={job_id}")
        else:
            logging.warning(f"⚠️ Failed to set total_branch for job_id={job_id}: {res.text}")
    except Exception as e:
        logging.error(f"❌ Error setting total_branch for job_id={job_id}: {e}")

def push_to_branch_queue(branch_data):
    try:
        credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
        params = pika.ConnectionParameters(host=rabbitmq_host, credentials=credentials)
        connection = pika.BlockingConnection(params)
        channel = connection.channel()
        channel.queue_declare(queue="scanner_branch_tasks", durable=True)
        channel.basic_publish(
            exchange="",
            routing_key="scanner_branch_tasks",
            body=json.dumps(branch_data),
            properties=pika.BasicProperties(delivery_mode=2)  # make message persistent
        )
        connection.close()
        logger.info(f"📤 Branch task queued for {branch_data['repo_name']} ({branch_data['branch']})")
    except Exception as e:
        logger.error(f"🔥 Failed to push branch job: {e}")

def process_job(ch, method, properties, body):
    try:
        job = json.loads(body)
        job_id = job["job_id"]
        logger.info(f"\n🚀 [Job {job_id}] Received from queue")

        # 1. Fetch job details via API
        detail_res = requests.get(f"{API_BASE}/api/scan/{job_id}/detail")
        if not detail_res.ok:
            raise Exception(f"Failed to fetch job detail: {detail_res.text}")

        data = detail_res.json()
        repo = data["repo"]
        git_source = data["git_source"]
        dojo = data["defectdojo"]
        scanner = data["scanner_name"]

        # 2. Get branches
        repo_name = repo["name"]
        base_url = git_source["base_url"]
        username = git_source["username"]
        token = decrypt_token(git_source["token"])

        full_url = base_url.rstrip("/") + "/" + repo_name + ".git"
        auth_url = full_url.replace("https://", f"https://{username}:{token}@")

        branches = scanner_module.get_branches(auth_url)
        if not branches:
            logger.info(f"No branches found for {repo_name}. Skipping...")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        logger.info(f"📚 Found {len(branches)} branches for {repo_name}")

        # 4. Push each branch as a separate job
        update_total_branch(job_id, len(branches))
        for branch in branches:
            branch_job = {
                "repo_name": repo_name,
                "job_id": job_id,
                "branch": branch,
                "scanner_name": scanner,
                "git_source": git_source,
                "defectdojo": dojo
            }
            push_to_branch_queue(branch_job)

        # 5. Acknowledge main job
        ch.basic_ack(delivery_tag=method.delivery_tag)
        logger.info(f"✅ Fanned out branch jobs for {repo_name}")

    except Exception as e:
        logger.error(f"❌ [Job Failed] {e}")
        if "job_id" in locals():
            requests.patch(
                f"{API_BASE}/api/scan/{job_id}",
                json={"status": f"failed: {str(e)}"}
            )
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

def process_webhook_job(ch, method, properties, body):
    try:
        job = json.loads(body)
        logger.info(f"\n🚀 [Webhook] New job received for {job.get('repo', {}).get('name')}")

        # Decrypt tokens
        git_token = decrypt_token(job["git_source"]["token"])
        dojo_token = decrypt_token(job["defectdojo"]["token"])
        job["git_source"]["token"] = git_token
        job["defectdojo"]["token"] = dojo_token
        
        # 👇 Inject username + token into the repo URL
        repo_name = job["repo_name"]
        base_url = job["git_source"]["base_url"]
        username = job["git_source"]["username"]
        repo_url = f"{base_url.rstrip('/')}/{repo_name}.git"
        
        parsed = urlparse(repo_url)
        auth_url = f"https://{username}:{git_token}@{parsed.netloc}{parsed.path}"
        job["auth_url"] = auth_url  # pass it to scanner module

        scanner = job["scanner_name"]
        if scanner == "trufflehog":
            trufflehog_proc.main_webhook(job)
        elif scanner == "trivy":
            trivy_proc.main_webhook(job)
        elif scanner == "gitleaks":
            gitleaks_proc.main_webhook(job)
        else:
            raise Exception(f"Unknown scanner: {scanner}")

        logger.info("✅ Webhook scan completed successfully.")
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"❌ [Webhook Job Failed] {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

def connect_with_retry(params, retries=10, delay=3):
    for attempt in range(retries):
        try:
            connection = pika.BlockingConnection(params)
            logger.info("✅ Connected to RabbitMQ")
            return connection
        except pika.exceptions.AMQPConnectionError as e:
            logger.info(f"⏳ Waiting for RabbitMQ... ({attempt+1}/{retries})")
            time.sleep(delay)
    raise Exception("❌ Failed to connect to RabbitMQ after multiple attempts")

def run_consumer():
    while True:
        try:
            credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
            params = pika.ConnectionParameters(
                host=rabbitmq_host,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            connection = connect_with_retry(params)
            channel = connection.channel()
            channel.queue_declare(queue="scanner_jobs", durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue="scanner_jobs", on_message_callback=process_job)

            logger.info("🎧 Worker connected. Waiting for jobs...")
            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError as e:
            logger.warning("💥 Lost connection to RabbitMQ. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            logger.exception("🔥 Unexpected error in consumer loop. Restarting in 5 seconds...")
            time.sleep(5)

def run_webhook_consumer():
    """Consumer loop for webhook-triggered jobs"""
    while True:
        try:
            credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
            params = pika.ConnectionParameters(
                host=rabbitmq_host,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            connection = connect_with_retry(params)
            channel = connection.channel()
            channel.queue_declare(queue="webhook_jobs", durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue="webhook_jobs", on_message_callback=process_webhook_job)

            logger.info("🎧 Webhook Worker connected. Waiting for jobs...")
            channel.start_consuming()

        except pika.exceptions.AMQPConnectionError:
            logger.warning("💥 Lost RabbitMQ connection. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception:
            logger.exception("🔥 Unexpected error in webhook consumer loop. Restarting in 5 seconds...")
            time.sleep(5)
            
def main(webhook=False):
    if webhook:
        run_webhook_consumer()
    else:
        run_consumer()
