import pika
import json
from cryptography.fernet import Fernet
import os

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