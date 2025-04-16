#FOR TESTING 
import requests
import json
import hmac
import hashlib

# Your webhook secret
secret = "helloWorldfromtheotherside"

# The payload that mimics a GitHub push event
payload = {
    "repository": {
        "full_name": "opennetltd/sportybet-yaml-prod",
        "clone_url": "https://github.com/opennetltd/sportybet-yaml-prod.git"
    },
    "ref": "refs/heads/main",
    "head_commit": {
        "id": "abc123",
        "message": "Add new config",
        "timestamp": "2025-04-14T09:30:00Z",
        "author": {
            "name": "Ben Abbas",
            "email": "ben@example.com"
        }
    }
}

# Serialize payload
payload_str = json.dumps(payload)

# Create signature using HMAC with SHA256
signature = 'sha256=' + hmac.new(
    key=secret.encode(),
    msg=payload_str.encode(),
    digestmod=hashlib.sha256
).hexdigest()

# Send POST request to your local Flask app
response = requests.post(
    "http://localhost:5003/webhook/github",
    data=payload_str,
    headers={
        "Content-Type": "application/json",
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": signature
    }
)

# Print the response
print("Status Code:", response.status_code)
print("Response Text:", response.text)
