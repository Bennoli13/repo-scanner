import os
import subprocess
import json
import logging
import uuid
import concurrent.futures
from . import scanner_module
from .hash_manager import HashManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

API_BASE = os.environ.get("API_BASE")
hash_mgr = HashManager(api_base=API_BASE)

RESULT_DIR = "./results"
os.makedirs(RESULT_DIR, exist_ok=True)

def scan_repo(repo_url, branch, repo_name, output_file):
    logger.info(f"Scanning {repo_name} on branch {branch}...")

    result = subprocess.run(
        ["trufflehog", "git", repo_url, "--branch", branch, "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
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

def scan_and_upload_branch(repo_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo):
    unique_id = uuid.uuid4().hex[:8]
    unique_file = os.path.join(RESULT_DIR, f"{unique_id}.json")

    success, file_path = scan_repo(repo_url, branch, repo_name, unique_file)

    if success:
        already_uploaded = hash_mgr.check_exists("trufflehog", repo_name, branch, file_path)
        logging.info(f"Already uploaded: {already_uploaded}")

        if not skip_dojo and not already_uploaded:
            uploaded = scanner_module.upload_to_defectdojo(
                dojo_token, dojo_url, engagement_id, file_path,
                tags=[branch, "trufflehog"],
                scan_type="Trufflehog Scan"
            )
        else:
            logger.info("Skipping upload to DefectDojo (either skipped or already uploaded).")
            uploaded = False

        if uploaded:
            logger.info(f"✅ Uploaded findings for branch {branch}.")
            hash_mgr.record("trufflehog", repo_name, branch, file_path)
            scanner_module.upload_to_flask_app(file_path, unique_id, "trufflehog", repo_name, API_BASE)
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
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(
            scan_and_upload_branch, full_url, branch, repo_name, dojo_token, dojo_url, engagement_id, skip_dojo
        ) for branch in branches]

        concurrent.futures.wait(futures)

    logger.info("🏁 [Trufflehog] All branches processed.")
