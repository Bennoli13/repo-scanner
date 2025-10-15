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
    logger.info(f"📦 Cloning {repo_name} (branch: {branch}) for Gitleaks scan...")

    # 1. Create temp directory for cloning
    temp_dir = tempfile.mkdtemp()
    repo_path = os.path.join(temp_dir, repo_name)

    # 2. Clone the repo (URL includes credentials)
    clone_cmd = ["git", "clone", "--branch", branch, "--depth", "1", repo_url, repo_path]
    for attempt in range(RETRY_COUNT):
        result = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            break
        logger.warning(f"⚠️ Attempt {attempt + 1}/{RETRY_COUNT} failed to clone {repo_name}: {result.stderr}")
        time.sleep(DELAY_SECONDS)
    
    if result.returncode != 0:
        safe_url = repo_url.split("@")[-1]
        logger.error(f"❌ Failed to clone {safe_url}: {result.stderr}")
        shutil.rmtree(temp_dir)
        return False, output_file

    # 3. Run Gitleaks scan in fs mode
    logger.info(f"🔍 Running Gitleaks scan on {repo_name} (branch: {branch})...")
    scan_cmd = [
        "gitleaks", "detect", "--no-git", repo_path, "--report-path", output_file,
        "--config", "/app/worker/config/gitleaks.toml"
    ]
    scan_result = subprocess.run(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 4. Clean up
    shutil.rmtree(temp_dir)

    if scan_result.returncode != 0:
        logger.error(f"❌ Gitleaks scan failed for {repo_name}: {scan_result.stderr}")
        return False, output_file

    logger.info(f"✅ Gitleaks scan complete: {output_file}")
    return True, output_file

def scan_and_upload_branch(repo_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo):
    unique_id = uuid.uuid4().hex[:8]
    unique_file = os.path.join(RESULT_DIR, f"{unique_id}.json")

    success, file_path = scan_repo(repo_url, branch, repo_name, unique_file)

    if success:
        logger.info(f"✅ Scan found issues, processing upload for branch {branch} ===")
        scanner_module.upload_to_flask_app(file_path, unique_id, "gitleaks", repo_name, API_BASE, engagement_id, tags=[repo_name, branch, "gitleaks"], scan_type="Gitleaks Scan")
    else:
        logger.info(f"==== No findings to upload for branch {branch} ===")

def main(data):
    logger.info(f"🚀 Running Gitleaks scanner for job_id={data['job_id']}")

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

    logger.info("🏁 [Gitleaks] All branches processed.")


def main_webhook(data):
    logger.info(f"🚀 Running Gitleaks scanner from Webhook")

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

    logger.info("🏁 [Gitleaks] Webhook-triggered scan finished.")

