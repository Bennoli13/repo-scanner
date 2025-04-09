import os
import subprocess
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
    logger.info(f"Scanning {repo_name} on branch {branch}...")

    result = subprocess.run(
        ["trivy", "repo", "--format", "json", "--output", output_file, repo_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        repo_url_without_cred = repo_url.split("@")[1]
        logger.info(f"❌  [Trivy] Error scanning {repo_url_without_cred} ({branch}): {result.stderr}")
        return False, output_file

    logger.info(f"Scan complete: {output_file}")
    return True, output_file

def scan_and_upload_branch(repo_url, branch, repo_name, dojo_token, dojo_url, engagement_id):
    unique_id =uuid.uuid4().hex[:8]
    unique_file = os.path.join(RESULT_DIR, f"{unique_id}.json")
    success, file_path = scan_repo(repo_url, branch, repo_name, unique_file)
    if success:
        logger.info(f"Uploading findings file: {file_path}")
        uploaded = scanner_module.upload_to_defectdojo(dojo_token, dojo_url, engagement_id, file_path, tags=[branch, "trivy"], scan_type="Trivy Scan")
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

    full_url = repo_url.replace("https://", f"https://{username}:{token}@")
    branches = scanner_module.get_branches(full_url)

    if not branches:
        logger.info(f"No branches found for {repo_url}. Skipping...")
        return

    product_id = scanner_module.get_or_create_product(dojo_token, dojo_url, label_name)
    engagement_id = scanner_module.get_or_create_engagement(dojo_token, dojo_url, product_id, repo_name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(
            scan_and_upload_branch, full_url, branch, repo_name, dojo_token, dojo_url, engagement_id
        ) for branch in branches]

        concurrent.futures.wait(futures)

    logger.info("🏁 [Trivy] All branches processed.")
    
if __name__ == "__main__":
    # Example data structure for testing
    data = {
        "defectdojo": {
            "token": "REDACTED",
            "url": "***REMOVED***/"
        },
        "git_source": {
            "base_url": "https://gitlab-infra.on.sportydog.net/",
            "id": 2,
            "label_name": "GitLab - OpenNet LTD",
            "platform": "gitlab",
            "token": "REDACTED",
            "username": "ben.abbas"
        },
        "job_id": 85,
        "repo": {
            "id": 85,
            "name": "infra/component/cloudwatch"
        },
        "scanner_name": "trivy"
        }
    main(data)
    logger.info("🏁 TruffleHog scan complete.")