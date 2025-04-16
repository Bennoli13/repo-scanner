import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Optional: confirm FERNET_KEY loaded
assert os.getenv("FERNET_KEY"), "FERNET_KEY not found in environment"

# Import and run your worker
from worker.consumer import main

if __name__ == "__main__":
    main(webhook=True)
