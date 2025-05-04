# 🛡️ Repo Scanner

A modular Git repository security scanning framework that integrates with [DefectDojo](https://www.defectdojo.org/). This tool lets you easily scan your repositories using tools like **TruffleHog** and **Trivy**, and upload the findings directly to DefectDojo for centralized vulnerability management and tracking.

---

## 📌 Why Repo Scanner?

Security should be automated, repeatable, and visible.

Manually scanning Git repositories is time-consuming and error-prone. This project automates the entire workflow:

- ✅ Central configuration of GitHub/GitLab repos
- ✅ Scheduled or manual scans triggered via UI
- ✅ Scans pushed to RabbitMQ for distributed processing
- ✅ Results uploaded to DefectDojo
- ✅ Status tracking for every scan

Whether you're a security engineer, SRE, or developer responsible for maintaining secure repos, this tool gives you visibility and control with minimal effort.

---

## 🔧 Features
- **GitHub/GitLab Integration**  
  - Support for multiple Git source configurations (URL, token, user)
  - Add repositories manually via UI or API
  - Trigger scans per repository

- **Scanning Framework**
  - Currently supports:
    - [TruffleHog](https://github.com/trufflesecurity/trufflehog)
    - [Trivy](https://github.com/aquasecurity/trivy)
  - Scans all branches per repo in parallel
  - CLI-based worker consumes jobs via RabbitMQ

- **DefectDojo Integration**
  - Auto-create Product & Engagement if not found
  - Upload findings with metadata (branch, commit, scanner)
  - Deduplication supported (both at hash and finding level)

- **Hash Caching & Deduplication**
  - Caches previously uploaded hashes locally and via API
  - Avoids duplicate upload to DefectDojo
  - Export/import hash cache for continuity

- **Scheduling**
  - Cron-style scan scheduling per repo
  - Stored in the DB and processed by worker

- **Git Webhook Support**
  - Webhook listener triggers scans per push or merge
  - Shared scanner logic reused across features

- **UI Features**
  - Bootstrap-based settings dashboard
  - Export/import settings and hash cache via web UI
  - Download `.json` backup and re-import anytime
---

## 🚀 Getting Started
You can run this via docker-compose. In the future we might also provide the helm chart to deploy this service. 

### 1. Clone this repo
```bash
git clone https://github.com/yourusername/repo-scanner.git
cd repo-scanner
```
2. Configure .env
```
FERNET_KEY=your_fernet_key
RABBITMQ_USER=guest
RABBITMQ_PASS=guest
RABBITMQ_HOST=rabbitmq
API_BASE=http://localhost:5001
```
3. Run with Docker-compose
```
docker-compose up --build
#Run the service with 5 workers 
docker-compose up --scale worker=5 --build   
```
4. Access Web UI
Visit: http://localhost:5001

---

## 🧪 How to Use
<img width="1511" alt="Screenshot 2025-04-06 at 3 51 14 PM" src="https://github.com/user-attachments/assets/c8f59f79-7f67-43db-a46f-92766d968a87" />
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/4807b542-442b-40d1-a09e-7943d3ed5912" />
<img width="1511" alt="image" src="https://github.com/user-attachments/assets/311d090d-b804-49b6-bf20-144d1adca57c" />

1. **Settings**  
   - Go to the **Settings** page to configure:
     - GitHub / GitLab base URL, access token, and username
     - DefectDojo API URL and token

2. **Repos**  
   - Navigate to **Repos** to:
     - Add the repositories you want to scan
     - Associate them with the configured Git source

3. **Scan**  
   - Head over to the **Scan** page to:
     - Select repos and the scanner (TruffleHog or Trivy)
     - Click "Scan Now" to trigger scanning
     - The scan job will be queued and processed automatically

4. **Status**  
   - Check scan status updates under the **Repos** list
   - Findings will appear in your DefectDojo dashboard

# 🔧 Architecture Overview
```
```text
+---------+     +-----------+     +--------------+
|  Front  | --> | Flask API | --> |   Database   |
| (Config)|     |  (REST)   |     |   (SQLite)   |
+---------+     +-----------+     +--------------+
                              ↑
         +------------------+ |
         | RabbitMQ (Queue) | |
         +------------------+ |
                              ↓
                        +-----------+
                        |   Worker  |
                        | (scanner) |
                        +-----------+
```
---

# 📁 Project Structure
```
repo-scanner/
├── app/                 # Flask app
├── worker/              # Worker scripts
│   ├── trufflehog_proc.py
│   └── trivy_proc.py
├── Dockerfile
├── docker-compose.yml
└── scan.html            # Frontend config page
```
---

# 🧪 Usage
* Access the dashboard via http://localhost:5000
* Add Git sources and repositories
* Trigger scan or schedule it via UI
* Upload .json export to restore settings/hash cache
* Webhook support available via /webhook

---

# 📁 API Highlights
Method	Endpoint	Description
POST	/api/scan	Trigger a scan job
GET	/export/settings	Export all config data
GET	/export/hash	Export all hash records
POST	/import/settings	Import config data
POST	/import/hash	Import hash records
POST	/webhook	Git push event (scan trigger)

# 🤝 Contributions
PRs and issues are welcome! Please open a discussion if you want to contribute a new scanner or integration.

