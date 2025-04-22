import os
import subprocess
import shutil
import tempfile
import json
import logging
import uuid
import concurrent.futures
from . import scanner_module
from .hash_manager import HashManager
import time

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
    logger.info(f"📦 Cloning {repo_name} (branch: {branch}) for Trivy scan...")

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

    # 3. Run Trivy scan in fs mode
    logger.info(f"🔍 Running Trivy scan on {repo_name} (branch: {branch})...")
    scan_cmd = [
        "trivy", "fs", "--format", "json", "--output", output_file,
        "--scanners", "vuln,misconfig,license",
        repo_path
    ]
    scan_result = subprocess.run(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 4. Clean up
    shutil.rmtree(temp_dir)

    if scan_result.returncode != 0:
        logger.error(f"❌ Trivy scan failed for {repo_name}: {scan_result.stderr}")
        return False, output_file

    logger.info(f"✅ Trivy scan complete: {output_file}")
    return True, output_file

def split_trivy_findings(file_path, max_findings=100):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("Results", [])
    if not results:
        return []

    chunks = []
    current_chunk = []
    total_count = 0
    base = {
        "SchemaVersion": data.get("SchemaVersion", 2),
        "ArtifactName": data.get("ArtifactName"),
        "ArtifactType": data.get("ArtifactType"),
        "Metadata": data.get("Metadata", {})
    }
    logger.info(f"Total findings in Trivy result: {len(results)}")
    for result in results:
        current_chunk.append(result)
        total_count += 1

        if len(current_chunk) >= max_findings:
            chunk_data = base.copy()
            chunk_data["Results"] = current_chunk

            temp_file = f"/tmp/trivy_chunk_{uuid.uuid4().hex}.json"
            with open(temp_file, "w", encoding="utf-8") as out:
                json.dump(chunk_data, out)
            chunks.append(temp_file)
            current_chunk = []

    # Add remaining
    if current_chunk:
        chunk_data = base.copy()
        chunk_data["Results"] = current_chunk
        temp_file = f"/tmp/trivy_chunk_{uuid.uuid4().hex}.json"
        with open(temp_file, "w", encoding="utf-8") as out:
            json.dump(chunk_data, out)
        chunks.append(temp_file)

    return chunks

def scan_and_upload_branch(repo_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo):
    unique_id = uuid.uuid4().hex[:8]
    unique_file = os.path.join(RESULT_DIR, f"{unique_id}.json")
    success, file_path = scan_repo(repo_url, branch, repo_name, unique_file)

    if not success:
        logger.info(f"==== No findings to upload for branch {branch} ===")
        return

    logger.info(f"Uploading findings file: {file_path}")
    already_uploaded = hash_mgr.filter_new_trivy_findings("trivy", repo_name, branch, file_path)
    logging.info(f"Already uploaded: {already_uploaded}")

    uploaded = False

    if not skip_dojo and not already_uploaded:
        chunks = split_trivy_findings(file_path, max_findings=50)

        if not chunks:
            logger.info("🛑 No findings to upload after minimizing.")
        else:
            for chunk_file in chunks:
                success = scanner_module.upload_to_defectdojo(
                    dojo_token, dojo_url, engagement_id, chunk_file,
                    tags=[branch, "trivy"],
                    scan_type="Trivy Scan"
                )
                if success:
                    uploaded = True
                try:
                    os.remove(chunk_file)
                    logger.info(f"🧹 Removed temp file: {chunk_file}")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to remove temp file {chunk_file}: {e}")
    else:
        logger.info("Skipping upload to DefectDojo (either skipped or already uploaded).")

    if uploaded:
        logger.info(f"✅ Uploaded findings for branch {branch}.")
        hash_mgr.record("trivy", repo_name, branch, file_path)
        scanner_module.upload_to_flask_app(file_path, unique_id, "trivy", repo_name, API_BASE)
    else:
        logger.info(f"❌ Failed to upload findings for branch {branch}.")

def main(data):
    logger.info(f"🚀 Running Trivy scanner for job_id={data['job_id']}")

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

    engagement_id = scanner_module.defect_dojo_prep(dojo_token, dojo_url, label_name, repo_name)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(
            scan_and_upload_branch, full_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo
        ) for branch in branches]

        concurrent.futures.wait(futures)

    logger.info("🏁 [Trivy] All branches processed.")
    
def main_webhook(data):
    logger.info(f"🚀 Running Trivy scanner from Webhook")

    repo_name = data["repo_name"]
    branch = data["branch"]
    commit = data.get("commit")  # optional
    repo_url = f"{data['git_source']['base_url'].rstrip('/')}/{repo_name}.git"
    label_name = data["git_source"]["label_name"]
    dojo_token = data["defectdojo"]["token"]
    dojo_url = data["defectdojo"]["url"]
    skip_dojo = dojo_url == ""
    full_url = data.get("auth_url", repo_url)

    if not skip_dojo:
        engagement_id = scanner_module.defect_dojo_prep(dojo_token, dojo_url, label_name, repo_name)
    else:
        engagement_id = None
        logger.info("Skipping DefectDojo setup (no token/url).")

    # Scan and upload the specific branch only
    scan_and_upload_branch(
        full_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo
    )

    logger.info("🏁 [Trivy] Webhook-triggered scan finished.")
    