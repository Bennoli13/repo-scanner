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

## 💡 Features

- 🖥️ **Web UI (Flask)** to configure Git/GitLab sources, repo lists, and scan parameters  
- 🐇 **RabbitMQ** integration for scalable job queuing  
- ⚙️ **Worker** apps to execute scans concurrently  
- 🔍 Supports:
  - [TruffleHog](https://github.com/trufflesecurity/trufflehog) for secrets scanning  
  - [Trivy](https://github.com/aquasecurity/trivy) for vulnerability scanning in codebases and Dockerfiles  
- 📦 Uploads findings to DefectDojo via API  
- 🔄 Keeps track of completed scans per repository  
- 🔐 Secure token encryption using `Fernet`  

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

# 🔧 Architecture Overview
+------------+        +--------------------+       +---------------+
|  Flask Web | -----> |  RabbitMQ Queue    | --->  |  Worker(s)    |
|  (Frontend)|        |  (scanner_jobs)    |       |  (Scanner +   |
|            |        |                    |       |   Upload)     |
+------------+        +--------------------+       +---------------+
        |                                              |
        +----------------------------------------------+
                      Updates scan status to DB

# 📁 Project Structure
repo-scanner/
├── app/                 # Flask app
├── worker/              # Worker scripts
│   ├── trufflehog_proc.py
│   └── trivy_proc.py
├── Dockerfile
├── docker-compose.yml
└── scan.html            # Frontend config page

# 📖 Roadmap
 [] Add support for more scanners (e.g., Gitleaks, Bandit)
 [] Schedule scans (cron-based)
 [] Alerting via Slack/Email
 [] Scan result visualization in dashboard

# 🤝 Contributions
PRs and issues are welcome! Please open a discussion if you want to contribute a new scanner or integration.

