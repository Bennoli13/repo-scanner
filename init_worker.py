import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Optional: confirm FERNET_KEY loaded
assert os.getenv("FERNET_KEY"), "FERNET_KEY not found in environment"

# Import and run your worker
from worker.consumer import main
from worker.branch_consumer import main as branch_main

WORKER_TYPE = os.getenv("WORKER_TYPE", "master") #master or worker

if __name__ == "__main__":
    if WORKER_TYPE == "master":
        print("Starting master worker...")
        main()
    else:
        print("Starting worker...")
        branch_main()
