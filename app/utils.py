import pika
import json
from cryptography.fernet import Fernet
import os
import requests

# Generate this once and save it as a secret (don't regenerate every time!)
FERNET_KEY = os.environ.get("FERNET_KEY", Fernet.generate_key())
fernet = Fernet(FERNET_KEY)

def encrypt_token(token):
    return fernet.encrypt(token.encode()).decode()

def decrypt_token(token_encrypted):
    return fernet.decrypt(token_encrypted.encode()).decode()

def push_scan_job_to_queue(job_data: dict):
    rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
    rabbitmq_user = os.getenv("RABBITMQ_USER", "guest")
    rabbitmq_pass = os.getenv("RABBITMQ_PASS", "guest")

    credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
    params = pika.ConnectionParameters(host=rabbitmq_host, credentials=credentials)

    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue="scanner_jobs", durable=True)

    channel.basic_publish(
        exchange="",
        routing_key="scanner_jobs",
        body=json.dumps(job_data),
        properties=pika.BasicProperties(delivery_mode=2)  # persistent
    )

    connection.close()
    
def push_webhook_job_to_queue(job_data: dict):
    rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
    rabbitmq_user = os.getenv("RABBITMQ_USER", "guest")
    rabbitmq_pass = os.getenv("RABBITMQ_PASS", "guest")

    credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
    params = pika.ConnectionParameters(host=rabbitmq_host, credentials=credentials)

    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue="webhook_jobs", durable=True)

    channel.basic_publish(
        exchange="",
        routing_key="webhook_jobs",
        body=json.dumps(job_data),
        properties=pika.BasicProperties(delivery_mode=2)
    )

    connection.close()
    
def validate_github_token(token: str) -> bool:
    """
    Validates a GitHub personal access token by calling the /user API.
    Returns True if valid, False if unauthorized.
    """
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        res = requests.get("https://api.github.com/user", headers=headers, timeout=5)
        return res.status_code == 200
    except requests.RequestException:
        return False
    
def validate_gitlab_token(token: str, base_url: str) -> bool:
    headers = {
        "PRIVATE-TOKEN": token
    }
    try:
        res = requests.get(f"{base_url.rstrip('/')}/api/v4/user", headers=headers, timeout=5)
        if res.status_code == 200:
            return True
        if res.status_code == 403 and "insufficient_scope" in res.text:
            # Token is valid but doesn't have user-level read scope
            return True
        return False
    except requests.RequestException:
        return False

def is_new_code_push(data):
    # 1. Ignore branch deletion
    if data.get("after") == "0000000000000000000000000000000000000000":
        return False

    # 2. Ignore tag pushes
    if data.get("ref", "").startswith("refs/tags/"):
        return False

    # 3. Extract commit list safely
    commits = data.get("commits", [])

    # 4. Ignore merge commits (GitHub: head_commit.message, GitLab: commits[0].message)
    if len(commits) == 1:
        # Prefer GitHub-style `head_commit` message if available
        head_msg = (
            data.get("head_commit", {}).get("message")
            or next((c.get("message") for c in commits if c.get("message")), "")
        )
        if head_msg.startswith("Merge pull request") or head_msg.startswith("Merge branch"):
            return False

    # 5. Ignore empty commit lists
    if len(commits) == 0:
        return False

    # 6. Ignore commits with no file changes
    if all(len(c.get("added", []) + c.get("modified", []) + c.get("removed", [])) == 0 for c in commits):
        return False

    return True
