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
