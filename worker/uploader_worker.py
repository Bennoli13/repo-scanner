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


####NOTIFICATION####
import json
import sqlite3
import requests

SQLITE_PATH = "/app/db.sqlite3"

class SlackNotifier:
    def __init__(self, scanner, filepath):
        self.scanner = scanner
        self.filepath = filepath
        self.webhooks = self._load_webhooks()
        self.findings = self._load_findings()

    def _load_webhooks(self):
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        query = """
            SELECT name, url FROM slack_webhook
            WHERE is_active = 1 AND ({scanner_field} = 1)
        """.format(scanner_field="notify_trivy" if self.scanner == "trivy" else "notify_trufflehog")
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results

    def _load_findings(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                content = f.read()
            if self.scanner == "trivy":
                return json.loads(content)
            elif self.scanner == "trufflehog":
                return [json.loads(line) for line in content.strip().splitlines()]
            else:
                return []
        except Exception as e:
            print(f"[SlackNotifier] ❌ Failed to read findings: {e}")
            return []

    def _format_message(self, item):
        if self.scanner == "trivy":
            return self._format_trivy(item)
        elif self.scanner == "trufflehog":
            return self._format_trufflehog(item)
        return None

    def _format_trivy(self, data):
        def severity_emoji(sev):
            return {
                "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "UNKNOWN": "⚪"
            }.get(sev.upper(), "⚪")

        def truncate(text, limit=100):
            return text if len(text) <= limit else text[:limit].rstrip() + "..."

        msg_parts = [f"*🔍 Trivy Finding*\nTarget: `{data.get('Target', 'Unknown')}`"]

        for category, icon in [
            ("Vulnerabilities", "🛡️"),
            ("Misconfigurations", "⚠️"),
            ("Secrets", "🔑"),
            ("Licenses", "📄")
        ]:
            if category in data:
                msg_parts.append(f"\n*{icon} {category}:*")
                for item in data[category]:
                    if category == "Vulnerabilities":
                        emoji = severity_emoji(item.get("Severity", "UNKNOWN"))
                        title = truncate(item.get("Title", item.get("VulnerabilityID", "")))
                        msg_parts.append(f"- {emoji} *{item['VulnerabilityID']}* in `{item.get('PkgName', 'unknown')}`: {title}")
                    elif category == "Misconfigurations":
                        emoji = severity_emoji(item.get("Severity", "UNKNOWN"))
                        title = truncate(item.get("Title", item.get("ID", "")))
                        msg_parts.append(f"- {emoji} *{item['ID']}*: {title}")
                    elif category == "Secrets":
                        msg_parts.append(f"- *{item.get('RuleID', 'Unknown')}*: {truncate(item.get('Title', 'Secret found'))}")
                    elif category == "Licenses":
                        msg_parts.append(f"- `{item.get('PkgName', 'unknown')}` uses license: *{item.get('License', 'Unknown')}*")

        return "\n".join(msg_parts) if len(msg_parts) > 1 else None

    def _format_trufflehog(self, data):
        try:
            commit = data["SourceMetadata"]["Data"]["Git"]["commit"]
            repo = data["SourceMetadata"]["Data"]["Git"]["repository"]
            raw = data.get("Raw", "[REDACTED]")
            detector = data.get("DetectorName", "Unknown")
            return f"*🐷 TruffleHog Finding*\nRepo: `{repo}`\nCommit: `{commit}`\nDetector: *{detector}*\nSecret: `{raw[:100]}...`"
        except Exception as e:
            return f"*🐷 TruffleHog Finding*\n(Parsing error: {e})"

    def send_notifications(self):
        if not self.webhooks:
            print("[SlackNotifier] ⚠️ No active webhooks configured.")
            return

        for finding in self.findings:
            msg = self._format_message(finding)
            if not msg:
                continue

            for name, url in self.webhooks:
                try:
                    requests.post(url, json={"text": msg})
                except Exception as e:
                    print(f"[SlackNotifier] ❌ Failed to send to '{name}': {e}")
############

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

def file_contains_trivy_findings(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Trivy JSON format: {"Results": [{...}]}
            for result in data.get("Results", []):
                if result.get("Vulnerabilities"):
                    return True
    except Exception as e:
        logger.warning(f"⚠️ Failed to inspect {file_path}: {e}")
    return False

def file_contains_trufflehog_findings(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if "DetectorName" in data:
                        return True  # At least one finding found
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.warning(f"⚠️ Failed to inspect {file_path}: {e}")
    return False

def file_contains_findings(file_path, scanner):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return False

    if scanner == "trufflehog":
        return file_contains_trufflehog_findings(file_path)
    elif scanner == "trivy":
        return file_contains_trivy_findings(file_path)
    else:
        logger.warning(f"⚠️ Unknown scanner type: {scanner}")
        return False

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
        if not file_contains_findings(file_path, scanner):
            logger.info(f"📭 Skipping upload — no findings for {scanner}: {file_path}")
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
            notifier = SlackNotifier(scanner, file_path)
            notifier.send_notifications()
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
