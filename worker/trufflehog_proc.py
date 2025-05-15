import os
import subprocess
import json
import logging
import uuid
import concurrent.futures
from . import scanner_module
from .hash_manager import HashManager
import time
import shutil
import tempfile

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

API_BASE = os.environ.get("API_BASE")
hash_mgr = HashManager(api_base=API_BASE)
RETRY_COUNT = 5 
DELAY_SECONDS = 10

RESULT_DIR = "./results"
os.makedirs(RESULT_DIR, exist_ok=True)

def scan_repo(repo_url, branch, repo_name, output_file):
    logger.info(f"Scanning {repo_name} on branch {branch}...")
    for attempt in range(RETRY_COUNT):
        logger.info(f"Attempt {attempt + 1}/{RETRY_COUNT}...")
        result = subprocess.run(
            ["trufflehog", "git", repo_url, "--branch", branch, "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            break
        logger.warning(f"⚠️ Attempt {attempt + 1}/{RETRY_COUNT} failed: {result.stderr}")
        time.sleep(DELAY_SECONDS)
    
    if result.returncode != 0:
        repo_url_without_cred = repo_url.split("@")[1]
        logger.info(f"❌ [Trufflehog] Error scanning {repo_url_without_cred} ({branch}): {result.stderr}")
        return False, output_file

    output = result.stdout.strip()

    if not output:
        logger.info(f"No credentials found in {repo_name} ({branch}). Skipping file creation.")
        return False, output_file

    with open(output_file, "w", encoding="utf-8") as json_file:
        json_file.write(output)

    logger.info(f"Scan complete: {output_file}")
    return True, output_file

def split_trufflehog_findings(file_path, max_findings=100):
    chunks = []
    current_chunk = []
    count = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            current_chunk.append(line)
            count += 1

            if len(current_chunk) >= max_findings:
                temp_file = f"/tmp/trufflehog_chunk_{uuid.uuid4().hex}.json"
                with open(temp_file, "w", encoding="utf-8") as out:
                    out.write("\n".join(current_chunk))
                chunks.append(temp_file)
                current_chunk = []

    if current_chunk:
        temp_file = f"/tmp/trufflehog_chunk_{uuid.uuid4().hex}.json"
        with open(temp_file, "w", encoding="utf-8") as out:
            out.write("\n".join(current_chunk))
        chunks.append(temp_file)

    return chunks

def scan_and_upload_branch(repo_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo):
    unique_id = uuid.uuid4().hex[:8]
    unique_file = os.path.join(RESULT_DIR, f"{unique_id}.json")

    success, file_path = scan_repo(repo_url, branch, repo_name, unique_file)
    
    # Create a temporary copy of the scan file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        dedup_path = tmp.name
        shutil.copyfile(file_path, dedup_path)

    if success:
        ignore_branch = "ignored"
        already_uploaded = hash_mgr.filter_new_trufflehog_findings("trufflehog", repo_name, ignore_branch, dedup_path)
        #skip deduplication on local runs
        #already_uploaded = False
        logging.info(f"Already uploaded: {already_uploaded}")

        if not skip_dojo and not already_uploaded:
            chunks = split_trufflehog_findings(file_path, max_findings=50)
            uploaded = False
            
            ''' ignore upload to dojo
            if not chunks:
                logger.info("🛑 No findings to upload after minimizing.")
            else:
                for chunk_file in chunks:
                    success = scanner_module.upload_to_defectdojo(
                        dojo_token, dojo_url, engagement_id, chunk_file,
                        tags=[branch, "trufflehog"],
                        scan_type="Trufflehog Scan"
                    )
                    if success:
                        uploaded = True
                    try:
                        os.remove(chunk_file)
                        logger.info(f"🧹 Removed temp file: {chunk_file}")
                    except Exception as e:
                        logger.warning(f"⚠️ Failed to remove temp file {chunk_file}: {e}")
            logger.info(f"Upload status: {uploaded}")
            '''
            uploaded = True #Delete this line to enable upload to dojo
        else:
            logger.info("Skipping upload to DefectDojo (either skipped or already uploaded).")
            uploaded = False
        
        
        if uploaded:
            logger.info(f"✅ Uploaded findings for branch {branch}.")
            hash_mgr.record("trufflehog", repo_name, branch, file_path)
            scanner_module.upload_to_flask_app(file_path, unique_id, "trufflehog", repo_name, API_BASE, engagement_id, tags=[repo_name, branch, "trufflehog"], scan_type="Trufflehog Scan")
        else:
            logger.info(f"❌ Failed to upload findings for branch {branch}.")
    else:
        logger.info(f"==== No findings to upload for branch {branch} ===")


def main(data):
    logger.info(f"🚀 Running TruffleHog scanner for job_id={data['job_id']}")

    repo = data["repo"]
    git_source = data["git_source"]
    dojo = data["defectdojo"]

    repo_name = repo["name"]
    label_name = git_source["label_name"]
    repo_url = f"{git_source['base_url'].rstrip('/')}/{repo_name}.git"
    username = git_source["username"]
    token = git_source["token"]
    dojo_token = dojo["token"]
    dojo_url = dojo["url"]
    skip_dojo = False
    if dojo_url == "": skip_dojo = True

    full_url = repo_url.replace("https://", f"https://{username}:{token}@")
    branches = scanner_module.get_branches(full_url)

    if not branches:
        logger.info(f"No branches found for {repo_url}. Skipping...")
        return

    if not skip_dojo:
        engagement_id = scanner_module.defect_dojo_prep(dojo_token, dojo_url, label_name, repo_name)
    else: 
        engagement_id = None
        logger.info(f"Skipping DefectDojo preparation as skip_dojo is set to True.")
    
    #log the label_name, egangement_id, and repo_name
    logger.info(f"Label Name: {label_name}, Engagement ID: {engagement_id}, Repo Name: {repo_name}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(
            scan_and_upload_branch, full_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo
        ) for branch in branches]

        concurrent.futures.wait(futures)

    logger.info("🏁 [Trufflehog] All branches processed.")


def main_webhook(data):
    logger.info(f"🚀 Running TruffleHog scanner from Webhook")

    repo_name = data["repo_name"]
    branch = data["branch"]
    commit = data.get("commit")  # optional
    repo_url = f"{data['git_source']['base_url'].rstrip('/')}/{repo_name}.git"
    label_name = data["git_source"]["label_name"]
    dojo_token = data["defectdojo"]["token"]
    dojo_url = data["defectdojo"]["url"]
    skip_dojo = dojo_url == ""
    full_url = data.get("auth_url", repo_url)

    engagement_id = scanner_module.defect_dojo_prep(dojo_token, dojo_url, label_name, repo_name)
    
    #log the label_name, egangement_id, and repo_name
    logger.info(f"Label Name: {label_name}, Engagement ID: {engagement_id}, Repo Name: {repo_name}")
    
    # Scan and upload the specific branch only
    scan_and_upload_branch(
        full_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo
    )

    logger.info("🏁 [Trufflehog] Webhook-triggered scan finished.")

