import pika
import json
import os
import time
import logging
import sqlite3
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from scanner_module import upload_to_defectdojo
from hash_manager import HashManager
import requests
import hashlib

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

def upsert_secret_and_decide_notify(repo: str, raw_secret: str) -> tuple[bool, str]:
    """
    Store (or update) the secret in the shared table and decide if we should notify.

    Returns:
      (should_notify, secret_hash)

    Rules:
      - First time we see a secret_hash -> insert row (repos=[repo]) -> notify
      - If secret_hash exists:
         - If repo NOT in repos -> append repo -> notify
         - Else -> already known for that repo -> do NOT notify
    """
    secret_hash = hashlib.sha256(raw_secret.encode()).hexdigest()

    conn = sqlite3.connect(SQLITE_PATH)
    cursor = conn.cursor()

    # Try insert first (fast path, uses UNIQUE on secret_hash)
    repos_json = json.dumps([repo])
    try:
        cursor.execute(
            """
            INSERT INTO trufflehog_secrets (secret, secret_hash, repos)
            VALUES (?, ?, ?)
            """,
            (raw_secret, secret_hash, repos_json)
        )
        conn.commit()
        conn.close()
        return True, secret_hash  # new secret entirely
    except sqlite3.IntegrityError:
        # Row already exists: update repos if needed
        cursor.execute(
            "SELECT repos FROM trufflehog_secrets WHERE secret_hash = ?",
            (secret_hash,)
        )
        row = cursor.fetchone()
        if not row:
            # rare race: treat as notify
            conn.close()
            return True, secret_hash

        existing_repos = []
        try:
            existing_repos = json.loads(row[0]) if row[0] else []
        except Exception:
            existing_repos = []

        if repo not in existing_repos:
            existing_repos.append(repo)
            cursor.execute(
                """
                UPDATE trufflehog_secrets
                SET repos = ?, updated_at = CURRENT_TIMESTAMP
                WHERE secret_hash = ?
                """,
                (json.dumps(existing_repos), secret_hash)
            )
            conn.commit()
            conn.close()
            return True, secret_hash  # same secret, new repo -> notify

        # Known secret + repo -> no notify
        conn.close()
        return False, secret_hash
    
#### NOTIFICATION (per-commit summaries) ####
class SlackNotifier:
    """
    Sends 1 Slack message per 'execution':
      - Gitleaks: per Commit (data[i]["Commit"])
      - TruffleHog: per Commit (data["SourceMetadata"]["Data"]["Git"]["commit"])
      - Trivy: single summary per scan file (no commit concept)
    """
    def __init__(self, scanner, filepath, repo):
        self.scanner = scanner
        self.filepath = filepath
        self.repo = repo
        self.webhooks = self._load_webhooks()
        self.findings = self._load_findings()

    # ---------- data loading ----------
    def _load_webhooks(self):
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        # Add your 'gitleaks' switch here too
        column = {
            "trivy": "notify_trivy",
            "trufflehog": "notify_trufflehog",
            "gitleaks": "notify_trufflehog",
        }.get(self.scanner, None)

        if not column:
            conn.close()
            return []

        q = f"SELECT name, url FROM slack_webhook WHERE is_active = 1 AND {column} = 1"
        cursor.execute(q)
        rows = cursor.fetchall()
        conn.close()
        return rows

    def _load_findings(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                content = f.read()
            if self.scanner == "trivy":
                return json.loads(content)  # dict with Results
            elif self.scanner == "trufflehog":
                return [json.loads(line) for line in content.strip().splitlines() if line.strip()]
            elif self.scanner == "gitleaks":
                return json.loads(content)  # list of objects
            else:
                return []
        except Exception as e:
            logger.warning(f"[SlackNotifier] Failed to read findings: {e}")
            return []

    # ---------- grouping ----------
    def _group_by_commit(self):
        """Return dict: {commit_hash: [findings]} for gitleaks/trufflehog; {'scan': [...]} for trivy."""
        if self.scanner == "gitleaks":
            groups = {}
            for item in (self.findings or []):
                commit = (item.get("Commit") or "").strip() or "unknown"
                groups.setdefault(commit, []).append(item)
            return groups

        if self.scanner == "trufflehog":
            groups = {}
            for item in (self.findings or []):
                git = (((item.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {})
                commit = (git.get("commit") or "").strip() or "unknown"
                groups.setdefault(commit, []).append(item)
            return groups

        if self.scanner == "trivy":
            # Trivy JSON is one scan result (no commit notion). Use single bucket.
            return {"scan": self.findings}

        return {}

    # ---------- summaries ----------
    def _summarize_gitleaks(self, commit, items, max_examples=5):
        by_rule, by_file = {}, {}
        examples = []

        for it in items:
            # Store/update in shared table by hash
            raw = it.get("Secret", "[REDACTED]") or ""
            should_notify, secret_hash = upsert_secret_and_decide_notify(self.repo, raw)

            rule = it.get("RuleID", "unknown")
            file = it.get("File", "unknown")
            by_rule[rule] = by_rule.get(rule, 0) + 1
            by_file[file] = by_file.get(file, 0) + 1

            if should_notify and len(examples) < max_examples:
                line = it.get("StartLine") or it.get("Line") or "?"
                desc = it.get("Description", "")
                examples.append(f"- `{file}:{line}` • *{rule}* — {desc}\n |__hash: `{secret_hash}`")

        #return None if all secrets are known (no examples)
        if len(examples) == 0:
            return None
        
        top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:5]
        top_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:5]

        commit_short = commit[:8] if commit and commit != "scan" else commit
        header = f"*🔍 Gitleaks Summary*  |  Repo: `{self.repo}`  |  Commit: `{commit}`"
        header_info = f"Author: {items[0].get('Author','?')} | Date: {items[0].get('Date','?')}"
        counts = f"*Findings:* {len(items)}  |  *Rules:* {len(by_rule)}  |  *Files:* {len(by_file)}"

        parts = [header, header_info, counts]
        
        #return None if author is jenkins
        if items[0].get('Author','?').lower() == 'jenkins':
            return None

        if top_rules:
            parts.append("\n*Top Rules:*")
            for r, c in top_rules:
                parts.append(f"• `{r}` — {c}")

        if top_files:
            parts.append("\n*Top Files:*")
            for f, c in top_files:
                parts.append(f"• `{f}` — {c}")

        if examples:
            parts.append("\n*New/Updated in this repo (sample):*")
            parts.extend(examples)

        parts.append("\n🔎 <https://scanner-defectdojo.k8s.uat.sportybet2.com/reveal/trufflehog|Reveal Secret>")
        return "\n".join(parts)

    def _summarize_trufflehog(self, commit, items, max_examples=5):
        # Record secrets and build aggregates
        by_detector, by_file = {}, {}
        examples = []

        for it in items:
            raw = it.get("Raw", "[REDACTED]")
            should_notify, secret_hash = upsert_secret_and_decide_notify(self.repo, raw)
            # If you want to filter out already-known secrets from the summary,
            # skip adding them to examples when should_notify is False.
            # I’ll still count occurrences in totals for visibility.

            det = it.get("DetectorName", "unknown")
            by_detector[det] = by_detector.get(det, 0) + 1
            git = (((it.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {})
            path = git.get("file", "unknown")
            by_file[path] = by_file.get(path, 0) + 1            

            if should_notify and len(examples) < max_examples:
                examples.append(f"- `{path}` • *{det}*\n |__hash: `{secret_hash}`")
        
        #return None if all secrets are known (no examples)
        if len(examples) == 0:
            return None

        top_det = sorted(by_detector.items(), key=lambda x: x[1], reverse=True)[:5]
        top_files = sorted(by_file.items(), key=lambda x: x[1], reverse=True)[:5]

        commit_short = commit[:8] if commit and commit != "scan" else commit
        header = f"*🐷 TruffleHog Summary*  |  Repo: `{self.repo}`  |  Commit: `{commit}`"
        header_info = f"Author Email: {git.get('email','?')} | Date: {git.get('timestamp','?')}"
        counts = f"*Findings:* {len(items)}  |  *Detectors:* {len(by_detector)}  |  *Files:* {len(by_file)}"

        parts = [header, header_info, counts]

        if top_det:
            parts.append("\n*Top Detectors:*")
            for d, c in top_det:
                parts.append(f"• `{d}` — {c}")

        if top_files:
            parts.append("\n*Top Files:*")
            for f, c in top_files:
                parts.append(f"• `{f}` — {c}")

        if examples:
            parts.append("\n*New/Updated in this repo (sample):*")
            parts.extend(examples)

        # Use your reveal tool to show the raw only when needed
        parts.append("\n🔎 <https://scanner-defectdojo.k8s.uat.sportybet2.com/reveal/trufflehog|Reveal Secret>")
        return "\n".join(parts)

    def _summarize_trivy(self, items, max_examples=5):
        # Aggregate from {"Results":[...]}; handle empty safely
        results = (items or {}).get("Results", [])
        vulns = miscfg = secrets = licenses = 0
        sev_counts = {}
        examples = []

        for r in results:
            for v in r.get("Vulnerabilities", []) or []:
                vulns += 1
                sev = (v.get("Severity") or "UNKNOWN").upper()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                if len(examples) < max_examples:
                    examples.append(f"- {sev} `{v.get('VulnerabilityID','')}` in `{v.get('PkgName','?')}`")

            for m in r.get("Misconfigurations", []) or []:
                miscfg += 1
            for s in r.get("Secrets", []) or []:
                secrets += 1
            for l in r.get("Licenses", []) or []:
                licenses += 1

        header = f"*🛡️ Trivy Summary*  |  Target: `{self.repo}`"
        sev_line = ", ".join([f"{k}:{v}" for k, v in sorted(sev_counts.items())]) or "none"
        counts = f"*Vulns:* {vulns} (by severity: {sev_line})  |  *Misconfig:* {miscfg}  |  *Secrets:* {secrets}  |  *Licenses:* {licenses}"

        parts = [header, counts]
        if examples:
            parts.append("\n*Examples:*")
            parts.extend(examples)

        # no specific reveal page here; keep generic or add your own
        return "\n".join(parts)

    # ---------- send ----------
    def send_summary(self, preferred_commit: str | None = None):
        if not self.webhooks:
            logger.info("[SlackNotifier] No active webhooks configured for this scanner.")
            return

        groups = self._group_by_commit()
        if not groups:
            logger.info("[SlackNotifier] No findings to summarize.")
            return

        # If caller knows which commit (e.g., webhook), optionally narrow to that
        if preferred_commit and preferred_commit in groups:
            groups = {preferred_commit: groups[preferred_commit]}

        # Build one message per grouped commit (or one 'scan' for Trivy)
        for commit, items in groups.items():
            if not items:
                continue

            if self.scanner == "gitleaks":
                text = self._summarize_gitleaks(commit, items)
            elif self.scanner == "trufflehog":
                text = self._summarize_trufflehog(commit, items)
            elif self.scanner == "trivy":
                text = self._summarize_trivy(items)
            else:
                continue

            for name, url in self.webhooks:
                try:
                    if text != None:
                        requests.post(url, json={"text": text}, timeout=10)
                    else:
                        logger.warning(f"[SlackNotifier] No text to send for '{name}'")
                except Exception as e:
                    logger.warning(f"[SlackNotifier] Failed to send to '{name}': {e}")
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
        logger.info(f"SQLITE_PATH: {SQLITE_PATH}")
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

def file_contains_gitleaks_findings(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list) and len(data) > 0:
                return True
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
    elif scanner == "gitleaks":
        return file_contains_gitleaks_findings(file_path)
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
            notifier = SlackNotifier(scanner, file_path, repo)
            # If your job payload includes a commit hash, you can pass it to narrow the summary:
            preferred_commit = None
            notifier.send_summary(preferred_commit)
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
