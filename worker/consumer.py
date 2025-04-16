import pika
import json
import requests
import time
from datetime import datetime
import os
from cryptography.fernet import Fernet
import logging

#scanner
from . import trufflehog_proc
from . import trivy_proc

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

def process_job(ch, method, properties, body):
    try:
        job = json.loads(body)
        job_id = job["job_id"]
        logger.info(f"\n🚀 [Job {job_id}] Received from queue")

        # 1. Get job details from API
        detail_res = requests.get(f"{API_BASE}/api/scan/{job_id}/detail")
        if not detail_res.ok:
            raise Exception(f"Failed to fetch job detail: {detail_res.text}")

        data = detail_res.json()

        # 2. Decrypt tokens
        git_token = decrypt_token(data["git_source"]["token"])
        dojo_token = decrypt_token(data["defectdojo"]["token"])
        data["git_source"]["token"] = git_token
        data["defectdojo"]["token"] = dojo_token

        logger.info(f"🧠 [Job {job_id}] Scanner: {data['scanner_name']}")
        logger.info(f"🔧 [Job {job_id}] Using Git token and Dojo token securely...")
        logger.info(f"🔄 Starting scan...")

        # 3. Scanning
        if data["scanner_name"] == "trufflehog":
            if data.get("webhook"):
                trufflehog_proc.main_webhook(data)
            else:
                trufflehog_proc.main(data)
        elif data["scanner_name"] == "trivy":
            if data.get("webhook"):
                trivy_proc.main_webhook(data)
            else:
                trivy_proc.main(data)
        else: 
            raise Exception(f"Unknown scanner: {data['scanner_name']}")

        # 4. Report back to API
        update_res = requests.patch(
            f"{API_BASE}/api/scan/{job_id}",
            json={"status": "completed"}
        )

        if update_res.ok:
            logger.info(f"✅ [Job {job_id}] Scan completed and status updated.")
        else:
            raise Exception(f"Failed to update job status: {update_res.text}")

        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.error(f"❌ [Job Failed] {e}")
        update_res = requests.patch(
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

        scanner = job["scanner_name"]
        if scanner == "trufflehog":
            trufflehog_proc.main_webhook(job)
        elif scanner == "trivy":
            trivy_proc.main_webhook(job)
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
