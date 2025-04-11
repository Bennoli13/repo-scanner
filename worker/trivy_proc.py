import os
import subprocess
import shutil
import tempfile
import json
import logging
import uuid
import concurrent.futures
from . import scanner_module

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

API_BASE = os.environ.get("API_BASE")

RESULT_DIR = "./results"
os.makedirs(RESULT_DIR, exist_ok=True)

def scan_repo(repo_url, branch, repo_name, output_file):
    logger.info(f"📦 Cloning {repo_name} (branch: {branch}) for Trivy scan...")

    # 1. Create temp directory for cloning
    temp_dir = tempfile.mkdtemp()
    repo_path = os.path.join(temp_dir, repo_name)

    # 2. Clone the repo (URL includes credentials)
    clone_cmd = ["git", "clone", "--branch", branch, "--depth", "1", repo_url, repo_path]
    result = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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

def scan_and_upload_branch(repo_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo):
    unique_id =uuid.uuid4().hex[:8]
    unique_file = os.path.join(RESULT_DIR, f"{unique_id}.json")
    success, file_path = scan_repo(repo_url, branch, repo_name, unique_file)
    if success:
        logger.info(f"Uploading findings file: {file_path}")
        if not skip_dojo:
            uploaded = scanner_module.upload_to_defectdojo(dojo_token, dojo_url, engagement_id, file_path, tags=[branch, "trivy"], scan_type="Trivy Scan")
        else:
            logger.info(f"Skipping upload to DefectDojo as skip_dojo is set to True.")
            uploaded = True
        if uploaded:
            logger.info(f"✅ Uploaded findings for branch {branch}.")
            scanner_module.upload_to_flask_app(file_path,unique_id,"trivy",repo_name,API_BASE)
        else:
            logger.info(f"❌ Failed to upload findings for branch {branch}.")
    else:
        logger.info(f"==== No findings to upload for branch {branch} ===")

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
    
if __name__ == "__main__":
    logger.info("🏁 TruffleHog scan complete.")