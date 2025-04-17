import os
import time
import json
import pika
import logging
import requests
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor
from . import scanner_module
from . import trivy_proc
from . import trufflehog_proc 
from . import hash_manager
from urllib.parse import urlparse

# Logger setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Load env
API_BASE = os.environ.get("API_BASE")
FERNET_KEY = os.environ.get("FERNET_KEY")
fernet = Fernet(FERNET_KEY)
rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
rabbitmq_user = os.getenv("RABBITMQ_USER", "guest")
rabbitmq_pass = os.getenv("RABBITMQ_PASS", "guest")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 3))  # Default to 3 threads

hash_mgr = hash_manager.HashManager(API_BASE)
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

def decrypt_token(token_encrypted):
    return fernet.decrypt(token_encrypted.encode()).decode()

def mark_branch_scanned(api_base, job_id, branch_name):
    try:
        res = requests.patch(
            f"{api_base}/api/scan/{job_id}",
            json={"scanned_branch": branch_name}
        )
        if res.ok:
            logging.info(f"✅ Marked branch '{branch_name}' as scanned for job_id={job_id}")
        else:
            logging.warning(f"⚠️ Failed to update scanned_branch for job_id={job_id}: {res.text}")
    except Exception as e:
        logging.error(f"❌ Error updating scanned_branch for job_id={job_id}: {e}")

def scan_job_handler(data):
    try:
        repo_name = data["repo_name"]
        job_id = data["job_id"]
        branch = data["branch"]
        scanner_name = data["scanner_name"]
        repo_url = f"{data['git_source']['base_url'].rstrip('/')}/{repo_name}.git"
        label_name = data["git_source"]["label_name"]
        username = data["git_source"]["username"]
        token = decrypt_token(data["git_source"]["token"])
        dojo_url = data["defectdojo"]["url"]
        dojo_token = decrypt_token(data["defectdojo"]["token"])
        skip_dojo = dojo_url == ""

        parsed = urlparse(repo_url)
        auth_url = f"https://{username}:{token}@{parsed.netloc}{parsed.path}"
        engagement_id = scanner_module.defect_dojo_prep(dojo_token, dojo_url, label_name, repo_name)

        if scanner_name == "trivy":
            trivy_proc.scan_and_upload_branch(auth_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo)
        elif scanner_name == "trufflehog":
            trufflehog_proc.scan_and_upload_branch(auth_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo)
        else:
            logger.warning(f"Unknown scanner: {scanner_name}")
        mark_branch_scanned(API_BASE, job_id, branch)
        logger.info(f"✅ Finished branch scan for {repo_name} [{branch}]")

    except Exception as e:
        logger.exception(f"🔥 Error scanning {data.get('repo_name')} [{data.get('branch')}]")

def process_branch_job(ch, method, properties, body):
    try:
        data = json.loads(body)
        logger.info(f"📦 Received job for branch: {data['branch']} from {data['repo_name']}")

        # Submit job to thread pool
        executor.submit(scan_job_handler, data)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        logger.exception("❌ Failed to queue branch job")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

def main():
    credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
    params = pika.ConnectionParameters(
        host=rabbitmq_host,
        credentials=credentials,
        heartbeat=600,
        blocked_connection_timeout=300
    )

    while True:
        try:
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.queue_declare(queue="scanner_branch_tasks", durable=True)
            channel.basic_qos(prefetch_count=MAX_WORKERS)
            channel.basic_consume(queue="scanner_branch_tasks", on_message_callback=process_branch_job)

            logger.info(f"🔂 Branch consumer running with {MAX_WORKERS} thread(s)...")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError:
            logger.warning("💥 Lost connection to RabbitMQ. Retrying...")
            time.sleep(5)
        except Exception as e:
            logger.exception("🔥 Unexpected error in branch consumer")
            time.sleep(5)

if __name__ == "__main__":
    main()
