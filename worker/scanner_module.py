import subprocess
import logging
import requests
from datetime import datetime, timedelta
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

def generate_engagement_dates():
    target_start = datetime.utcnow().date()
    target_end = target_start + timedelta(days=180)
    return target_start.isoformat(), target_end.isoformat()

def get_branches(repo_url):
    result = subprocess.run(
        ["git", "ls-remote", "--heads", repo_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        logger.error(f"Error fetching branches for {repo_url}: {result.stderr}")
        return []

    branches = [line.split("\t")[1].replace("refs/heads/", "") for line in result.stdout.splitlines()]
    return branches

def defect_dojo_prep(dojo_token, dojo_url, label_name, repo_name):
    try:
        product_id = get_or_create_product(dojo_token, dojo_url, label_name)
        engagement_id = get_or_create_engagement(dojo_token, dojo_url, product_id, repo_name)
    except Exception as e:
        logger.error(f"Error preparing DefectDojo: {str(e)}")
        return None
    return engagement_id

def get_or_create_product(token, dojo_url, product_name):
    headers = {"Authorization": f"Token {token}"}
    res = requests.get(f"{dojo_url}/api/v2/products/?name={product_name}", headers=headers)
    data = res.json()
    if data["count"] > 0:
        return data["results"][0]["id"]

    res = requests.post(f"{dojo_url}/api/v2/products/", json={"name": product_name}, headers=headers)
    return res.json()["id"]

def get_or_create_engagement(token, dojo_url, product_id, repo_name):
    headers = {"Authorization": f"Token {token}"}
    res = requests.get(f"{dojo_url}/api/v2/engagements/?name={repo_name}&product={product_id}", headers=headers)
    data = res.json()
    if data["count"] > 0:
        return data["results"][0]["id"]

    target_start, target_end = generate_engagement_dates()
    payload = {
        "name": repo_name,
        "product": product_id,
        "status": "In Progress",
        "target_start": target_start,
        "target_end": target_end,
    }
    res = requests.post(f"{dojo_url}/api/v2/engagements/", json=payload, headers=headers)
    return res.json()["id"]

def upload_to_defectdojo(token, dojo_url, engagement_id, file_path, tags, scan_type):
    headers = {"Authorization": f"Token {token}"}
    files = {"file": open(file_path, "rb")}
    data = {
        "scan_type": scan_type,
        "engagement": engagement_id,
        "tags": ",".join(tags),
        "minimum_severity": "Low",
        "active": "true",
        "verified": "false",
        "close_old_findings": "false",
        "skip_duplicates": "true",
    }
    res = requests.post(f"{dojo_url}/api/v2/import-scan/", headers=headers, files=files, data=data)
    logger.info(f"Upload response: {res.status_code}")
    files["file"].close()
    return res.ok

def upload_to_flask_app(file_path, unique_id, scanner_name, repo_name, flask_api_url):
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            data = {
                "scanner_name": scanner_name,
                "repo_name": repo_name,
                "unique_id": unique_id,
            }
            response = requests.post(f"{flask_api_url}/api/upload", files=files, data=data)
        if response.ok:
            logger.info(f"📤 Uploaded scan file to Flask app for {repo_name}")
        else:
            logger.warning(f"⚠️ Failed to upload scan file to Flask app: {response.text}")
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        logger.error(f"❌ Exception during Flask file upload: {str(e)}")
