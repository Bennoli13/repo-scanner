import requests
import logging
import hashlib
import json

logger = logging.getLogger(__name__)

class HashManager:
    def __init__(self, api_base):
        self.api_base = api_base.rstrip("/")

    def compute_file_hash(self, scanner, file_path):
        """Compute normalized hash depending on the scanner type"""
        try:
            if scanner == "trufflehog":
                lines = []
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        item = json.loads(line.strip())
                        git_data = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
                        if "timestamp" in git_data:
                            del git_data["timestamp"]
                        lines.append(json.dumps(item, sort_keys=True))
                joined = "\n".join(lines)
                return hashlib.sha256(joined.encode("utf-8")).hexdigest()

            elif scanner == "trivy":
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                results = data.get("Results", [])
                return hashlib.sha256(json.dumps(results, sort_keys=True).encode("utf-8")).hexdigest()

            else:
                logger.warning(f"❓ Unknown scanner type: {scanner}")
                return None

        except Exception as e:
            logger.error(f"⚠️ Failed to compute hash for {scanner} on {file_path}: {e}")
            return None

    def check_exists(self, scanner, repo_name, branch, file_path):
        result_hash = self.compute_file_hash(scanner, file_path)
        if not result_hash:
            return False

        res = requests.get(f"{self.api_base}/api/hash/check", params={
            "scanner": scanner,
            "repo_name": repo_name,
            "branch": branch,
            "hash": result_hash
        })
        if res.ok:
            return res.json().get("exists", False)
        return False

    def record(self, scanner, repo_name, branch, file_path):
        result_hash = self.compute_file_hash(scanner, file_path)
        if not result_hash:
            return False

        res = requests.post(f"{self.api_base}/api/hash/add", json={
            "scanner": scanner,
            "repo_name": repo_name,
            "branch": branch,
            "hash": result_hash
        })
        return res.ok