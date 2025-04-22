import requests
import logging
import hashlib
import json
import os

logger = logging.getLogger(__name__)

class HashManager:
    def __init__(self, api_base):
        self.api_base = api_base.rstrip("/")

    def compute_file_hash(self, scanner, file_path):
        try:
            if scanner == "trufflehog":
                lines = []
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        item = json.loads(line.strip())
                        git = item.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
                        raw = item.get("Raw", "")
                        combined = f"{git.get('commit', '')}|{git.get('file', '')}|{raw}"
                        lines.append(combined)
                joined = "\n".join(sorted(lines))
                return hashlib.sha256(joined.encode("utf-8")).hexdigest()

            elif scanner == "trivy":
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                results = data.get("Results", [])
                return hashlib.sha256(json.dumps(results, sort_keys=True).encode("utf-8")).hexdigest()

        except Exception as e:
            logger.error(f"⚠️ Failed to compute hash for {scanner} on {file_path}: {e}")
        return None

    def _request_hash_api(self, method, path, data=None, params=None):
        url = f"{self.api_base}/api/hash/{path}"
        try:
            if method == "GET":
                res = requests.get(url, params=params)
                print(res.text)
                if res.ok:
                    return res.json().get("exists", False)
            elif method == "POST":
                res = requests.post(url, json=data)
                print(res.text)
                return res.ok
        except Exception as e:
            logger.warning(f"Hash API {method} {path} failed: {e}")
        return False

    def check_exists(self, scanner, repo_name, branch, file_path):
        result_hash = self.compute_file_hash(scanner, file_path)
        if not result_hash:
            return False
        return self._request_hash_api("GET", "check", None, params={
            "scanner": scanner,
            "repo_name": repo_name,
            "branch": branch,
            "hash": result_hash
        })

    def record(self, scanner, repo_name, branch, file_path):
        result_hash = self.compute_file_hash(scanner, file_path)
        if not result_hash:
            return False
        return self._request_hash_api("POST", "add", data={
            "scanner": scanner,
            "repo_name": repo_name,
            "branch": branch,
            "hash": result_hash
        }, params=None)
    
    def filter_new_trivy_findings(scanner, repo_name, branch, file_path, api_base):
        def compute_vuln_hash(vuln, target):
            parts = [
                target,
                vuln.get("PkgName", ""),
                vuln.get("InstalledVersion", ""),
                vuln.get("VulnerabilityID", "")
            ]
            base = "|".join(parts)
            return hashlib.sha256(base.encode("utf-8")).hexdigest()

        def compute_misconfig_hash(misconfig, target):
            parts = [
                target,
                misconfig.get("ID", ""),
                misconfig.get("Type", ""),
                misconfig.get("Title", "")
            ]
            base = "|".join(parts)
            return hashlib.sha256(base.encode("utf-8")).hexdigest()

        def compute_license_hash(license_info, target):
            parts = [
                target,
                license_info.get("PkgName", ""),
                license_info.get("Name", ""),
                license_info.get("FilePath", ""),
                license_info.get("LicenseRisk", "")
            ]
            base = "|".join(parts)
            return hashlib.sha256(base.encode("utf-8")).hexdigest()

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = data.get("Results", [])
        if not results:
            return False

        new_results = []
        recorded_hashes = set()

        for result in results:
            target = result.get("Target", "")

            # Filter Vulnerabilities
            new_vulns = []
            for vuln in result.get("Vulnerabilities", []):
                hash_val = compute_vuln_hash(vuln, target)
                try:
                    res = requests.get(f"{api_base}/api/hash/check", params={
                        "scanner": scanner,
                        "repo_name": repo_name,
                        "branch": branch,
                        "hash": hash_val
                    })
                    if res.ok and not res.json().get("exists"):
                        new_vulns.append(vuln)
                        recorded_hashes.add(hash_val)
                except Exception as e:
                    print(f"[WARNING] Trivy vuln hash check failed: {e}")

            # Filter Misconfigurations
            new_misconfigs = []
            for misconfig in result.get("Misconfigurations", []):
                hash_val = compute_misconfig_hash(misconfig, target)
                try:
                    res = requests.get(f"{api_base}/api/hash/check", params={
                        "scanner": scanner,
                        "repo_name": repo_name,
                        "branch": branch,
                        "hash": hash_val
                    })
                    if res.ok and not res.json().get("exists"):
                        new_misconfigs.append(misconfig)
                        recorded_hashes.add(hash_val)
                except Exception as e:
                    print(f"[WARNING] Trivy misconfig hash check failed: {e}")

            # Filter Licenses
            new_licenses = []
            for license_info in result.get("Licenses", []):
                hash_val = compute_license_hash(license_info, target)
                try:
                    res = requests.get(f"{api_base}/api/hash/check", params={
                        "scanner": scanner,
                        "repo_name": repo_name,
                        "branch": branch,
                        "hash": hash_val
                    })
                    if res.ok and not res.json().get("exists"):
                        new_licenses.append(license_info)
                        recorded_hashes.add(hash_val)
                except Exception as e:
                    print(f"[WARNING] Trivy license hash check failed: {e}")

            if new_vulns or new_misconfigs or new_licenses:
                new_result = dict(result)
                if new_vulns:
                    new_result["Vulnerabilities"] = new_vulns
                if new_misconfigs:
                    new_result["Misconfigurations"] = new_misconfigs
                if new_licenses:
                    new_result["Licenses"] = new_licenses
                new_results.append(new_result)

        if new_results:
            data["Results"] = new_results
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            for h in recorded_hashes:
                try:
                    requests.post(f"{api_base}/api/hash/add", json={
                        "scanner": scanner,
                        "repo_name": repo_name,
                        "branch": branch,
                        "hash": h
                    })
                except Exception as e:
                    print(f"[WARNING] Failed to record Trivy hash: {e}")
            return True
        return False


    def filter_new_trufflehog_findings(self, scanner, repo_name, branch, file_path):
        def compute_line_hash(line):
            try:
                data = json.loads(line)
                commit = data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit")
                file = data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file")
                raw = data.get("Raw", "")
                base = f"{(commit or '').strip()}:{(file or '').strip()}:{(raw or '').strip()}"
                hash_val = hashlib.sha256(base.encode("utf-8")).hexdigest()
                return hash_val
            except Exception:
                return None

        new_lines = []
        recorded_hashes = set()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                hash_val = compute_line_hash(line)
                if not hash_val:
                    continue
                exists = self._request_hash_api("GET", "check", data=None, params={
                    "scanner": scanner,
                    "repo_name": repo_name,
                    "branch": branch,
                    "hash": hash_val
                })
                if exists:
                    print(f"✅ Found existing hash: {hash_val}")
                else:
                    print(f"❌ New hash detected: {hash_val}")
                    self._request_hash_api("POST", "add", {
                    "scanner": scanner,
                    "repo_name": repo_name,
                    "branch": branch,
                    "hash": hash_val
                })

            if new_lines:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(new_lines) + "\n")

        except Exception as e:
            logger.error(f"❌ Error filtering TruffleHog findings: {e}")

        return bool(new_lines)
