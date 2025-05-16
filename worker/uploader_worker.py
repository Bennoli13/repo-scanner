import pika
import json
import os
import time
import logging
import sqlite3
from datetime import datetime
from cryptography.fernet import Fernet
from scanner_module import upload_to_defectdojo
from hash_manager import HashManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Config
SQLITE_PATH = os.getenv("SQLITE_PATH", "/app/instance/scanner.db")
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "guest")
FERNET_KEY = os.getenv("FERNET_KEY")
UPLOAD_INTERVAL = 30  # seconds between uploads
API_BASE = os.getenv("API_BASE", "http://web:5000") 

fernet = Fernet(FERNET_KEY)
hash_mgr = HashManager(api_base=API_BASE)

def decrypt_token(token_encrypted: str) -> str:
    return fernet.decrypt(token_encrypted.encode()).decode()

def ensure_upload_history_table():
    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS upload_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            file_hash TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            upload_status TEXT CHECK(upload_status IN ('success', 'fail')) NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def get_last_upload_record(engagement_id):
    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_hash, upload_status FROM upload_history
        WHERE engagement_id = ?
        ORDER BY uploaded_at DESC
        LIMIT 1
    """, (engagement_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else (None, None)

def save_upload_record(engagement_id, file_hash, status):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO upload_history (engagement_id, file_hash, uploaded_at, upload_status)
        VALUES (?, ?, ?, ?)
    """, (engagement_id, file_hash, now, status))
    conn.commit()
    conn.close()

def load_defectdojo_config():
    try:
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT url, token FROM defect_dojo_config LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise Exception("❌ No DefectDojo config found in defect_dojo_config table.")

        dojo_url = row[0]
        dojo_token_encrypted = row[1]
        dojo_token = decrypt_token(dojo_token_encrypted)
        return dojo_url, dojo_token
    except Exception as e:
        logger.error(f"❌ Failed to load or decrypt DefectDojo config: {e}")
        raise

def get_ignore_keywords(scanner, engagement_id):
    """
    Return ignore keywords for both global rules (engagement IS NULL)
    and rules specific to the given engagement_id.
    """
    if engagement_id is None:
        # Can't determine engagement-specific rules
        return []

    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT keyword FROM vulnerability_ignore_rules
        WHERE scanner = ?
          AND (engagement IS NULL OR engagement = ?)
        """,
        (scanner, engagement_id)
    )

    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

def process_vulnerability_ignore_rules_trufflehog(file_path, ignore_keywords):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        filtered_lines = []
        removed = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                detector_name = data.get("DetectorName", "")
                if any(kw.lower() in detector_name.lower() for kw in ignore_keywords):
                    removed += 1
                    continue
                filtered_lines.append(line)
            except Exception:
                continue  # skip malformed lines

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(filtered_lines) + "\n")

        logger.info(f"🧹 TruffleHog: removed {removed} ignored findings")
    except Exception as e:
        logger.error(f"❌ Failed to apply ignore rules: {e}")

def process_upload_job(job):
    try:
        scanner = job["scanner"]
        repo = job["repo"]
        file_path = job["file_path"]
        engagement_id = job.get("engagement_id")
        tags = job.get("tags", [])
        scan_type = job.get("scan_type", "Generic Scan")

        dojo_url, dojo_token = load_defectdojo_config()
        
        #ignore upload if engagement_id is None
        if engagement_id is None:
            logger.info(f"⏩ Skipping upload — engagement_id is None")
            return

        # 🔍 Ignore filtering
        ignore_keywords = get_ignore_keywords(scanner, engagement_id)
        if scanner == "trufflehog":
            process_vulnerability_ignore_rules_trufflehog(file_path, ignore_keywords)
        
        # 🧼 Skip if file is empty
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            logger.info(f"📭 Skipping upload — file is empty: {file_path}")
            return

        # 🧠 Hash check
        file_hash = hash_mgr.compute_file_hash(scanner, file_path)
        if file_hash:
            prev_hash, prev_status = get_last_upload_record(engagement_id)
            if prev_hash == file_hash and prev_status == "success":
                logger.info(f"⏩ Skipping upload — hash unchanged for engagement_id={engagement_id}")
                return

        # 🚀 Upload to DefectDojo
        logger.info(f"⬆️ Uploading: {file_path} for engagement_id={engagement_id}")
        success = upload_to_defectdojo(
            token=dojo_token,
            dojo_url=dojo_url,
            engagement_id=engagement_id,
            file_path=file_path,
            tags=tags,
            scan_type=scan_type
        )

        # 📝 Record hash result
        status = "success" if success else "fail"
        if file_hash:
            save_upload_record(engagement_id, file_hash, status)

        if success:
            logger.info(f"✅ Upload success: {file_path}")
        else:
            logger.warning(f"⚠️ Upload failed: {file_path}")

        time.sleep(UPLOAD_INTERVAL)

    except Exception as e:
        logger.exception(f"❌ Failed to process upload job: {e}")

def connect_with_retry(params, retries=10, delay=3):
    for attempt in range(retries):
        try:
            connection = pika.BlockingConnection(params)
            logger.info("✅ Connected to RabbitMQ (uploader_jobs)")
            return connection
        except pika.exceptions.AMQPConnectionError:
            logger.warning(f"⏳ RabbitMQ unavailable, retrying... ({attempt+1}/{retries})")
            time.sleep(delay)
    raise Exception("❌ Could not connect to RabbitMQ after retries")

def run_uploader():
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        credentials=credentials,
        heartbeat=600,
        blocked_connection_timeout=300
    )
    connection = connect_with_retry(params)
    channel = connection.channel()
    channel.queue_declare(queue="uploader_jobs", durable=True)
    channel.basic_qos(prefetch_count=1)

    def callback(ch, method, properties, body):
        try:
            job = json.loads(body)
            process_upload_job(job)
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            logger.error(f"❌ Failed to handle job: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    channel.basic_consume(queue="uploader_jobs", on_message_callback=callback)
    logger.info("📡 Uploader worker is running... Waiting for jobs.")
    channel.start_consuming()

if __name__ == "__main__":
    ensure_upload_history_table()
    run_uploader()
