from flask import Blueprint, render_template, request, jsonify, Flask, send_file, send_from_directory
from . import db
from .models import GitSourceConfig, DefectDojoConfig, Repository, ScannerJob, ScheduledScan, ScanHashRecord, WebhookSecret
from .utils import encrypt_token, decrypt_token, push_scan_job_to_queue, push_webhook_job_to_queue

from sqlalchemy import and_
from datetime import datetime

from werkzeug.utils import secure_filename
import zipfile
import shutil
import os
import hmac
import hashlib

FILE_UPLOAD_BASE= "/app/files"
SCANNERS = ["trufflehog", "trivy"]
main = Blueprint("main", __name__)

# ------------------------------
# HTML Pages
# ------------------------------
@main.route("/")
def index():
    return render_template("index.html")

@main.route("/settings")
def settings():
    dojo = DefectDojoConfig.query.first()
    return render_template("settings.html", dojo=dojo)

@main.route("/repos")
def repos():
    git_sources = GitSourceConfig.query.all()
    return render_template("repos.html", sources=git_sources)

@main.route("/scan")
def scan():
    git_sources = GitSourceConfig.query.all()
    return render_template("scan.html", sources=git_sources)

@main.route("/result/<scanner>")
def view_results(scanner):
    if scanner not in ["trufflehog", "trivy"]:
        return "Invalid scanner", 404

    folder = os.path.join("files", scanner)
    if not os.path.exists(folder):
        return render_template("result.html", scanner=scanner, files=[])

    files = [f for f in os.listdir(folder) if f.endswith(".json")]
    return render_template("result.html", scanner=scanner, files=files)

# ------------------------------
# Files: Download
# ------------------------------
@main.route("/files/<scanner>/<filename>")
def serve_uploaded_file(scanner, filename):
    if scanner not in ["trufflehog", "trivy"]:
        return "Invalid scanner", 404
    folder = os.path.join(FILE_UPLOAD_BASE, scanner)
    return send_from_directory(folder, filename, as_attachment=True)

# ------------------------------
# API: Git Configs
# ------------------------------
@main.route("/api/settings", methods=["GET"])
def get_git_configs():
    configs = GitSourceConfig.query.all()
    return jsonify([
        {
            "id": c.id,
            "label_name": c.label_name,
            "username": c.username,
            "platform": c.platform,
            "base_url": c.base_url,
        } for c in configs
    ])

@main.route("/api/settings", methods=["POST"])
def add_git_config():
    data = request.get_json()
    config = GitSourceConfig(
        label_name=data.get("label_name"),
        username=data.get("username"),
        platform=data["platform"],
        base_url=data["base_url"].rstrip("/"),
        token=encrypt_token(data["token"])
    )
    db.session.add(config)
    db.session.commit()
    return jsonify({"message": "Config added", "id": config.id}), 201

@main.route("/api/settings", methods=["DELETE"])
def delete_git_config():
    config_id = request.args.get("id")
    config = GitSourceConfig.query.get(config_id)
    if not config:
        return jsonify({"error": "Config not found"}), 404
    db.session.delete(config)
    db.session.commit()
    return jsonify({"message": "Config deleted"}), 200

# ------------------------------
# API: DefectDojo Config
# ------------------------------
@main.route("/api/defectdojo", methods=["GET"])
def get_defectdojo():
    dojo = DefectDojoConfig.query.first()
    if not dojo:
        return jsonify({})
    return jsonify({
        "url": dojo.url,
        "token": decrypt_token(dojo.token)
    })
    
@main.route("/api/defectdojo", methods=["POST"])
def update_defectdojo():
    data = request.get_json()
    dojo = DefectDojoConfig.query.first()
    if not dojo:
        dojo = DefectDojoConfig()
        db.session.add(dojo)

    dojo.url = data["url"]
    dojo.token = encrypt_token(data["token"])
    db.session.commit()
    return jsonify({"message": "DefectDojo config saved"}), 200

# ------------------------------
# API: Repos
# ------------------------------
@main.route("/api/repos", methods=["GET"])
def get_repos():
    sources = GitSourceConfig.query.all()
    result = []

    for source in sources:
        repos = Repository.query.filter_by(source_id=source.id).all()
        result.append({
            "source": {
                "id": source.id,
                "platform": source.platform,
                "base_url": source.base_url,
                "username": source.username
            },
            "repos": [
                {
                    "id": r.id,
                    "username": r.username,
                    "scan_status": r.scan_status
                } for r in repos
            ]
        })

    return jsonify(result)

@main.route("/api/repos/source/<int:source_id>", methods=["GET"])
def get_repos_by_source(source_id):
    source = GitSourceConfig.query.get_or_404(source_id)
    repos = Repository.query.filter_by(source_id=source.id).all()
    return jsonify([
        {
            "id": r.id,
            "name": r.name,
        } for r in repos
    ])

@main.route("/api/repos", methods=["POST"])
def add_repos():
    data = request.get_json()
    source_id = data.get("source_id")
    repo_names = data.get("repos", [])

    if not source_id or not repo_names:
        return jsonify({"error": "Missing source_id or repos"}), 400

    for name in repo_names:
        repo = Repository(name=name.strip(), source_id=source_id)
        db.session.add(repo)

    db.session.commit()
    return jsonify({"message": "Repositories added"}), 201

@main.route("/api/repos/<int:repo_id>", methods=["DELETE"])
def delete_repo(repo_id):
    repo = Repository.query.get(repo_id)
    if not repo:
        return jsonify({"error": "Repository not found"}), 404

    db.session.delete(repo)
    db.session.commit()
    return jsonify({"message": "Repository deleted"}), 200

# ------------------------------
# API: Scan
# ------------------------------
@main.route("/api/scan", methods=["POST"])
def trigger_scan_jobs():
    data = request.get_json()
    source_id = data.get("source_id")
    repo_ids = data.get("repo_ids", [])
    scanners = data.get("scanners", [])

    if not source_id or not scanners:
        return jsonify({"error": "Missing source_id or scanners"}), 400

    # If repo_ids is empty, get all repos from this source
    if not repo_ids:
        repo_ids = [r.id for r in Repository.query.filter_by(source_id=source_id).all()]
        if not repo_ids:
            return jsonify({"error": "No repositories found for this source"}), 404

    now = datetime.utcnow()
    message_list = []

    for repo_id in repo_ids:
        for scanner_name in scanners:
            job = ScannerJob.query.filter_by(
                git_source_id=source_id,
                repo_id=repo_id,
                scanner_name=scanner_name
            ).first()

            if job:
                job.created_at = now
            else:
                job = ScannerJob(
                    scanner_name=scanner_name,
                    repo_id=repo_id,
                    git_source_id=source_id,
                    created_at=now
                )
            db.session.add(job)
            db.session.flush()  # get job.id before commit
            message = {
                "job_id": job.id,
                "scanner_name": scanner_name,
                "repo_id": repo_id,
                "source_id": source_id
            }
            message_list.append(message)

    db.session.commit()

    # Push message to RabbitMQ
    for message in message_list:
        push_scan_job_to_queue(message)

    return jsonify({"message": "Scan jobs queued"}), 200

@main.route("/api/scan/status", methods=["GET"])
def scan_status():
    source_id = request.args.get("source_id")
    if not source_id:
        return jsonify([])

    jobs = db.session.query(
        ScannerJob,
        Repository.name.label("repo_name")
    ).join(Repository).filter(
        ScannerJob.git_source_id == source_id
    ).order_by(ScannerJob.updated_at.desc()).all()

    result = []
    for job, repo_name in jobs:
        result.append({
            "repo_name": repo_name,
            "scanner_name": job.scanner_name,
            "scanned_branch": job.scanned_branch,
            "status": job.progress,  # use progress instead of status
            "progress_ratio": job.progress_ratio,
            "updated_at": job.updated_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify(result)

@main.route("/api/scan/<int:job_id>", methods=["PATCH"])
def update_scan_status(job_id):
    job = ScannerJob.query.get_or_404(job_id)
    data = request.get_json()

    scanned_branch = job.scanned_branch or []
    new_branch = data.get("scanned_branch")
    if new_branch and new_branch not in scanned_branch:
        scanned_branch.append(new_branch)
        job.scanned_branch = scanned_branch
        job.updated_at = datetime.utcnow()
        db.session.commit()
    return jsonify({"message": "Branch progress updated"}), 200

@main.route("/api/scan/<int:job_id>/set-total-branches", methods=["PATCH"])
def set_total_branches(job_id):
    job = ScannerJob.query.get_or_404(job_id)
    data = request.get_json()
    total = data.get("total_branch")

    if total is not None and isinstance(total, int) and total >= 0:
        job.total_branch = total
        job.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"message": "Total branch count updated"}), 200

    return jsonify({"error": "Invalid total_branch value"}), 400


@main.route("/api/scan/<int:job_id>/detail", methods=["GET"])
def scan_job_detail(job_id):
    job = ScannerJob.query.get_or_404(job_id)
    repo = Repository.query.get_or_404(job.repo_id)
    source = GitSourceConfig.query.get_or_404(job.git_source_id)
    dojo = DefectDojoConfig.query.first()

    return jsonify({
        "job_id": job.id,
        "scanner_name": job.scanner_name,
        "repo": {
            "id": repo.id,
            "name": repo.name
        },
        "git_source": {
            "id": source.id,
            "label_name": source.label_name,
            "platform": source.platform,
            "base_url": source.base_url,
            "username": source.username,
            "token": source.token
        },
        "defectdojo": {
            "url": dojo.url if dojo else "",
            "token": dojo.token if dojo else ""
        }
    })

# ------------------------------
# API: File Upload
# ------------------------------
@main.route("/api/upload", methods=["POST"])
def handle_file_upload():
    file = request.files.get("file")
    scanner = request.form.get("scanner_name")
    repo = request.form.get("repo_name")
    date_str = datetime.utcnow()
    unique_id = request.form.get("unique_id")

    if not file or not scanner or not repo:
        return jsonify({"error": "Missing required parameters."}), 400

    if scanner not in ["trufflehog", "trivy"]:
        return jsonify({"error": "Unsupported scanner."}), 400

    folder_path = os.path.join(FILE_UPLOAD_BASE, scanner)
    os.makedirs(folder_path, exist_ok=True)

    filename = f"{date_str}_{repo}_{unique_id}.json"
    file_path = os.path.join(folder_path, secure_filename(filename))
    file.save(file_path)

    return jsonify({"message": "File uploaded successfully.", "path": file_path}), 200

@main.route("/api/download/<scanner>", methods=["GET"])
def download_by_scanner(scanner):
    if scanner not in ["trufflehog", "trivy"]:
        return jsonify({"error": "Unsupported scanner."}), 400

    folder_path = os.path.join(FILE_UPLOAD_BASE, scanner)
    if not os.path.exists(folder_path):
        return jsonify({"error": f"No data found for scanner: {scanner}"}), 404

    zip_filename = f"{scanner}_scans.zip"
    zip_path = os.path.join(FILE_UPLOAD_BASE, zip_filename)

    with zipfile.ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".json"):
                    abs_path = os.path.join(root, file)
                    arcname = os.path.relpath(abs_path, FILE_UPLOAD_BASE)
                    zipf.write(abs_path, arcname)

    return send_file(zip_path, as_attachment=True)

@main.route("/api/clear/<scanner>", methods=["DELETE"])
def clear_all(scanner):
    if scanner not in ["trufflehog", "trivy", "all"]:
        return jsonify({"error": "Unsupported scanner."}), 400
    if scanner == "all":
        for scanner in ["trufflehog", "trivy"]:
            folder_path = os.path.join(FILE_UPLOAD_BASE, scanner)
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)
                os.makedirs(folder_path)
    else:
        folder_path = os.path.join(FILE_UPLOAD_BASE, scanner)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)
            os.makedirs(folder_path)
    return jsonify({"message": "All uploaded files cleared."}), 200

# ------------------------------
# API: Scheduler
# ------------------------------
# API route to create a scheduled scan
@main.route("/api/schedule", methods=["POST"])
def create_schedule():
    data = request.get_json()
    source_id = data.get("source_id")
    repo_id = data.get("repo_id")  # May be null for 'all'
    scanner_name = data.get("scanner_name")
    cron_day = data.get("cron_day")
    cron_hour = data.get("cron_hour")
    cron_minute = data.get("cron_minute")

    if source_id is None or scanner_name is None or cron_day is None or cron_hour is None or cron_minute is None:
        return jsonify({"error": "Missing required fields"}), 400

    new_schedule = ScheduledScan(
        source_id=source_id,
        repo_id=repo_id,  # can be None
        scanner_name=scanner_name,
        cron_day=cron_day,
        cron_hour=cron_hour,
        cron_minute=cron_minute,
    )
    db.session.add(new_schedule)
    db.session.commit()
    return jsonify({"message": "Scheduled scan created"}), 201


# API route to list all scheduled scans
@main.route("/api/schedule", methods=["GET"])
def list_schedules():
    schedules = ScheduledScan.query.all()
    result = []
    for s in schedules:
        result.append({
            "id": s.id,
            "source_label": s.source.label_name,
            "source_id": s.source.id,
            "repo_id": s.repo.id if s.repo else None,
            "repo_name": s.repo.name if s.repo else "All Repos",
            "scanner_name": s.scanner_name,
            "cron_day": s.cron_day,
            "cron_hour": s.cron_hour,
            "cron_minute": s.cron_minute,
            "last_run": s.last_run.isoformat() if s.last_run else None
        })
    return jsonify(result)


# API route to delete a schedule
@main.route("/api/schedule/<int:schedule_id>", methods=["DELETE"])
def delete_schedule(schedule_id):
    s = ScheduledScan.query.get_or_404(schedule_id)
    db.session.delete(s)
    db.session.commit()
    return jsonify({"message": "Scheduled scan deleted"})

@main.route("/api/schedule/<int:schedule_id>/mark-run", methods=["PATCH"])
def update_schedule_last_run(schedule_id):
    scan = ScheduledScan.query.get_or_404(schedule_id)
    scan.last_run = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "last_run updated"}), 200


# ------------------------------
# API: Scan Hash
# ------------------------------
@main.route("/api/hash/check", methods=["GET"])
def check_hash():
    scanner = request.args.get("scanner")
    repo_name = request.args.get("repo_name")
    branch = request.args.get("branch")
    hash_value = request.args.get("hash")

    if not all([scanner, repo_name, branch, hash_value]):
        return jsonify({"error": "Missing parameters"}), 400

    exists = ScanHashRecord.query.filter_by(
        scanner=scanner,
        repo_name=repo_name,
        branch=branch,
        result_hash=hash_value
    ).first() is not None

    return jsonify({"exists": exists})

@main.route("/api/hash/add", methods=["POST"])
def add_hash():
    data = request.get_json()
    scanner = data.get("scanner")
    repo_name = data.get("repo_name")
    branch = data.get("branch")
    hash_value = data.get("hash")

    if not all([scanner, repo_name, branch, hash_value]):
        return jsonify({"error": "Missing parameters"}), 400

    existing = ScanHashRecord.query.filter_by(
        scanner=scanner,
        repo_name=repo_name,
        branch=branch
    ).first()

    if existing:
        existing.result_hash = hash_value
        db.session.commit()
        return jsonify({"message": "Hash updated"}), 200

    new_hash = ScanHashRecord(
        scanner=scanner,
        repo_name=repo_name,
        branch=branch,
        result_hash=hash_value
    )
    db.session.add(new_hash)
    db.session.commit()
    return jsonify({"message": "Hash recorded"}), 201

# ------------------------------
# API: Webhook Handler
# ------------------------------
@main.route("/api/webhook-secret", methods=["GET", "POST", "DELETE"])
def webhook_secret():
    if request.method == "GET":
        secrets = WebhookSecret.query.all()
        return jsonify([{
            "platform": s.platform,
            "created_at": s.created_at.isoformat(),
            "secret": s.secret
        } for s in secrets])

    elif request.method == "POST":
        data = request.get_json()
        platform = data.get("platform")
        secret = encrypt_token(data.get("secret"))
        if not platform or not secret:
            return jsonify({"error": "Missing data"}), 400

        existing = WebhookSecret.query.filter_by(platform=platform).first()
        if existing:
            existing.secret = secret
        else:
            new_secret = WebhookSecret(platform=platform, secret=secret)
            db.session.add(new_secret)
        db.session.commit()
        return jsonify({"message": "Saved"}), 201

    elif request.method == "DELETE":
        platform = request.args.get("platform")
        if not platform:
            return jsonify({"error": "Platform required"}), 400
        existing = WebhookSecret.query.filter_by(platform=platform).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()
        return jsonify({"message": "Deleted"}), 200

def verify_github_signature(secret, payload, signature_header):
    expected = 'sha256=' + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header or '')

@main.route("/webhook/<platform>", methods=["POST"])
def handle_webhook(platform):
    raw_body = request.data

    secret_entry = WebhookSecret.query.filter_by(platform=platform).first()
    if not secret_entry:
        return jsonify({"error": "No secret configured"}), 403

    secret = decrypt_token(secret_entry.secret)

    # --- GitHub ---
    if platform == "github":
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not verify_github_signature(secret, raw_body, signature):
            return jsonify({"error": "Invalid signature"}), 403

        payload = request.get_json()
        repo_url = payload["repository"]["clone_url"]
        branch = payload["ref"].split("/")[-1]  # refs/heads/main
        commit_id = payload.get("after")

    # --- GitLab ---
    elif platform == "gitlab":
        token = request.headers.get("X-Gitlab-Token", "")
        if not hmac.compare_digest(token,secret):
            return jsonify({"error": "Invalid token"}), 403

        payload = request.get_json()
        repo_url = payload["project"]["http_url"]
        branch = payload["ref"].split("/")[-1]
        commit_id = payload.get("after")

    else:
        return jsonify({"error": "Unsupported platform"}), 400

    # 🔧 You can add logic here to select which scanner(s) to use
    sources_list = GitSourceConfig.query.all()
    source = None
    repo_name = None

    for s in sources_list:
        prefix = s.base_url.rstrip("/") + "/"
        if repo_url.startswith(prefix):
            source = s
            repo_name = repo_url.replace(prefix, "").replace(".git", "")
            break

    if not source or not repo_name:
        return jsonify({"error": "Git source config not found or repo name parsing failed"}), 404

    repo = Repository.query.filter_by(name=repo_name, source_id=source.id).first()
    dojo = DefectDojoConfig.query.first()
    
    # Push job to webhook queue
    for scanner in SCANNERS:
        push_webhook_job_to_queue({
            "git_source": {
                "id": source.id,
                "label_name": source.label_name,
                "platform": source.platform,
                "base_url": source.base_url,
                "username": source.username,
                "token": source.token
            },
            "defectdojo": {
                "url": dojo.url if dojo else "",
                "token": dojo.token if dojo else ""
            },
            "scanner_name": scanner,  # or "trivy", could be platform/config-based too
            "repo_id": repo.id,
            "repo_name": repo.name,
            "branch": branch,
            "commit_id": commit_id,
            "is_webhook": True
        })
    return jsonify({"message": "Webhook accepted"}), 200