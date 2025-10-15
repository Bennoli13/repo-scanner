from flask import Blueprint, render_template, request, jsonify, Flask, send_file, send_from_directory
from . import db
from .models import GitSourceConfig, DefectDojoConfig, Repository, ScannerJob, ScheduledScan, ScanHashRecord, WebhookSecret, VulnerabilityIgnoreRule, SlackWebhook, TrufflehogSecret
from .utils import encrypt_token, decrypt_token, push_scan_job_to_queue, push_webhook_job_to_queue, push_uploader_job_to_queue, validate_github_token, validate_gitlab_token, is_new_code_push

from sqlalchemy import and_
from datetime import datetime
from dateutil import parser as date_parser

from werkzeug.utils import secure_filename
import zipfile
import shutil
import os
import hmac
import hashlib

FILE_UPLOAD_BASE= "/app/files"
SCANNERS = ["trufflehog", "trivy", "gitleaks"]
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

@main.route("/settings/import-export")
def settings_import_export():
    dojo = DefectDojoConfig.query.first()
    return render_template("settings_import_export.html")

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

@main.route('/reveal/trufflehog')
def reveal_secret_ui():
    return render_template("reveal_secret.html")

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

@main.route("/api/settings/<int:config_id>", methods=["GET", "PUT"])
def git_config_detail(config_id):
    config = GitSourceConfig.query.get_or_404(config_id)

    if request.method == "GET":
        return jsonify({
            "id": config.id,
            "platform": config.platform,
            "label_name": config.label_name,
            "base_url": config.base_url,
            "username": config.username
            # do not return the token
        })

    elif request.method == "PUT":
        data = request.get_json()
        config.username = data.get("username", config.username)
        config.platform = data.get("platform", config.platform)
        config.label_name = data.get("label_name", config.label_name)
        config.base_url = data.get("base_url", config.base_url)
        if data.get("token"):  # only update if new token is provided
            config.token = encrypt_token(data["token"])
        if config.platform == "github":
            if not validate_github_token(decrypt_token(config.token)):
                db.session.rollback()
                return jsonify({"message": "Invalid GitHub token"}), 400
        elif config.platform == "gitlab":
            if not validate_gitlab_token(decrypt_token(config.token), config.base_url):
                db.session.rollback()
                return jsonify({"message": "Invalid GitLab token"}), 400 
        db.session.commit()
        return jsonify({"message": "Config updated"}), 200

@main.route("/api/settings/<int:config_id>/check", methods=["GET"])
def check_token_validity(config_id):
    config = GitSourceConfig.query.get_or_404(config_id)
    token = decrypt_token(config.token)
    if config.platform == "github":
        if validate_github_token(token):
            return jsonify({"message": "Valid", "platform": "github", "username": config.username})
        else:
            return jsonify({"message": "Invalid GitHub token"}), 400
    elif config.platform == "gitlab":
        if validate_gitlab_token(token, config.base_url):
            return jsonify({"message": "Valid", "platform": "gitlab", "username": config.username})
        else:
            return jsonify({"message": "Invalid GitLab token"}), 400
    else:
        return jsonify({"message": "Unsupported platform"}), 400

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
    date_str = datetime.utcnow().isoformat()
    unique_id = request.form.get("unique_id")
    engagement_id = request.form.get("engagement_id")
    tags = request.form.get("tags")
    scan_type = request.form.get("scan_type")

    if not file or not scanner or not repo:
        return jsonify({"error": "Missing required parameters."}), 400

    if scanner not in ["trufflehog", "trivy"]:
        return jsonify({"error": "Unsupported scanner."}), 400

    folder_path = os.path.join(FILE_UPLOAD_BASE, scanner)
    os.makedirs(folder_path, exist_ok=True)

    filename = f"{date_str}_{repo}_{unique_id}.json"
    file_path = os.path.join(folder_path, secure_filename(filename))
    file.save(file_path)

    # 👇 Push job to uploader queue
    job_data = {
        "scanner": scanner,
        "repo": repo,
        "file_path": file_path,
        "engagement_id": engagement_id,
        "tags": tags,
        "scan_type": scan_type,
        "unique_id": unique_id,
        "uploaded_at": date_str
    }
    try:
        push_uploader_job_to_queue(job_data)
    except Exception as e:
        return jsonify({"error": f"File saved, but failed to queue upload: {e}"}), 500

    return jsonify({"message": "File uploaded and job queued successfully.", "path": file_path}), 200


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
# API: Notification
# ------------------------------
@main.route("/api/slackwebhook", methods=["POST"])
def add_slack_webhook():
    data = request.get_json()
    webhook = SlackWebhook(
        name=data["name"],
        url=data["url"],
        is_active=data.get("is_active", True),
        notify_trivy=data.get("notify_trivy", False),
        notify_trufflehog=data.get("notify_trufflehog", False)
    )
    db.session.merge(webhook)
    db.session.commit()
    return jsonify({"message": "Webhook saved."}), 200

@main.route("/api/slackwebhook/all", methods=["GET"])
def list_slack_webhooks():
    rows = db.session.query(SlackWebhook).all()
    return jsonify([
        {
            "id": r.id,
            "name": r.name,
            "url": r.url,
            "is_active": r.is_active,
            "notify_trivy": r.notify_trivy,
            "notify_trufflehog": r.notify_trufflehog
        } for r in rows
    ])

@main.route("/api/slackwebhook/<int:id>/toggle", methods=["POST"])
def toggle_slackwebhook(id):
    row = SlackWebhook.query.get(id)
    if not row:
        return jsonify({"error": "Not found"}), 404
    row.is_active = not row.is_active
    db.session.commit()
    return jsonify({"status": "toggled"})

@main.route("/api/slackwebhook/<int:id>", methods=["DELETE"])
def delete_slackwebhook(id):
    row = SlackWebhook.query.get(id)
    if not row:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(row)
    db.session.commit()
    return jsonify({"status": "deleted"})

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
    #temporary disable deduplication on repo-scanner
    #return jsonify({"exists": False})
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
    #temporary disable deduplication on repo-scanner
    #return jsonify({"message": "Dedup disabled"}), 201
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
        branch=branch,
        result_hash=hash_value
    ).first()

    if existing:
        return jsonify({"message": "Hash already exists"}), 200

    new_hash = ScanHashRecord(
        scanner=scanner,
        repo_name=repo_name,
        branch=branch,
        result_hash=hash_value
    )
    db.session.add(new_hash)
    db.session.commit()
    return jsonify({"message": "Hash recorded"}), 201

@main.route("/api/hash/export", methods=["GET"])
def export_hashes():
    #temporary disable deduplication on repo-scanner
    #return jsonify([]), 200
    from app.models import ScanHashRecord  # adjust import if needed
    records = ScanHashRecord.query.all()
    data = [{
        "scanner": r.scanner,
        "repo_name": r.repo_name,
        "branch": r.branch, #ignore the branch 
        "result_hash": r.result_hash
    } for r in records]
    return jsonify(data), 200

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

@main.route("/webhook/<platform>/<int:git_config_id>", methods=["POST"])
def handle_webhook(platform, git_config_id):
    raw_body = request.data
    json_body = request.get_json()

    secret_entry = WebhookSecret.query.filter_by(platform=platform).first()
    if not secret_entry:
        return jsonify({"error": "No secret configured"}), 403
    
    if not is_new_code_push(json_body):
        return jsonify({"error": "Not a new code push"}), 200

    secret = decrypt_token(secret_entry.secret)

    # --- GitHub ---
    if platform == "github":
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not verify_github_signature(secret, raw_body, signature):
            return jsonify({"error": "Invalid signature"}), 403

        payload = json_body
        repo_url = payload["repository"]["clone_url"]
        branch = payload["ref"].split("/")[-1]  # refs/heads/main
        commit_id = payload.get("after")

    # --- GitLab ---
    elif platform == "gitlab":
        token = request.headers.get("X-Gitlab-Token", "")
        if not hmac.compare_digest(token,secret):
            return jsonify({"error": "Invalid token"}), 403

        payload = json_body
        repo_url = payload["project"]["http_url"]
        branch = payload["ref"].split("/")[-1]
        commit_id = payload.get("after")

    else:
        return jsonify({"error": "Unsupported platform"}), 400

    # 🔧 You can add logic here to select which scanner(s) to use
    source = GitSourceConfig.query.filter_by(id=git_config_id).first()
    if not source:
        return jsonify({"error": "Git source config not found"}), 404
    
    #extract repo name from url
    prefix = source.base_url.rstrip("/") + "/"
    if not repo_url.startswith(prefix):
        return jsonify({"error": "Repo URL doesn't match base_url"}), 400
    repo_name = repo_url.replace(prefix, "").replace(".git", "")
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

# ------------------------------
# Export / Import Setting 
# ------------------------------
@main.route("/export/settings", methods=["GET"])
def export_settings():
    data = {
        "defectdojo": [dojo.to_dict() for dojo in DefectDojoConfig.query.all()],
        "git_sources": [g.to_dict() for g in GitSourceConfig.query.all()],
        "repos": [r.to_dict() for r in Repository.query.all()],
        "scanner_jobs": [j.to_dict() for j in ScannerJob.query.all()],
        "scheduled_scans": [s.to_dict() for s in ScheduledScan.query.all()],
        "webhook_secrets": [w.to_dict() for w in WebhookSecret.query.all()]
    }
    return jsonify(data)

@main.route("/import/settings", methods=["POST"])
def import_settings():
    data = request.get_json()
    try:
        for dojo in data.get("defectdojo", []):
            db.session.merge(DefectDojoConfig(**dojo))
        for g in data.get("git_sources", []):
            db.session.merge(GitSourceConfig(**g))
        for r in data.get("repos", []):
            db.session.merge(Repository(**r))
        for j in data.get("scanner_jobs", []):
            if isinstance(j.get("created_at"), str):
                j["created_at"] = date_parser.parse(j["created_at"])
            if isinstance(j.get("updated_at"), str):
                j["updated_at"] = date_parser.parse(j["updated_at"])
            db.session.merge(ScannerJob(**j))
        for s in data.get("scheduled_scans", []):
            db.session.merge(ScheduledScan(**s))
        for w in data.get("webhook_secrets", []):
            if isinstance(w.get("created_at"), str):
                w["created_at"] = date_parser.parse(w["created_at"])
            db.session.merge(WebhookSecret(**w))
        db.session.commit()
        return jsonify({"message": "Settings imported"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Import failed: {e}"}), 500

@main.route("/export/hash", methods=["GET"])
def export_hashes_html():
    hashes = ScanHashRecord.query.all()
    return jsonify([h.to_dict() for h in hashes])

@main.route("/import/hash", methods=["POST"])
def import_hashes():
    data = request.get_json()
    try:
        for h in data:
            db.session.merge(ScanHashRecord(**h))
        db.session.commit()
        return jsonify({"message": "Hash records imported"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Hash import failed: {e}"}), 500
    
# ------------------------------
# API: Ignore Rules
# ------------------------------
@main.route("/api/ignore-rules", methods=["GET"])
def list_ignore_rules():
    rules = VulnerabilityIgnoreRule.query.all()
    return jsonify([r.to_dict() for r in rules]), 200

@main.route("/api/ignore-rules", methods=["POST"])
def add_ignore_rule():
    data = request.get_json()
    scanner = data.get("scanner")
    keyword = data.get("keyword")
    engagement = data.get("engagement")  # Optional; can be null or int

    if not scanner or not keyword:
        return jsonify({"error": "scanner and keyword are required"}), 400

    # Normalize engagement to None if not provided
    try:
        engagement_id = int(engagement) if engagement is not None else None
    except ValueError:
        return jsonify({"error": "engagement must be an integer or null"}), 400

    rule = VulnerabilityIgnoreRule(
        scanner=scanner,
        keyword=keyword,
        engagement=engagement_id
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify(rule.to_dict()), 201

@main.route("/api/ignore-rules/<int:rule_id>", methods=["DELETE"])
def delete_ignore_rule(rule_id):
    rule = VulnerabilityIgnoreRule.query.get(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    db.session.delete(rule)
    db.session.commit()
    return jsonify({"message": f"Rule {rule_id} deleted"}), 200

# ------------------------------
# Reveal Trufflehog Secrets
# ------------------------------
@main.route("/api/trufflehog/secret/<secret_hash>")
def get_trufflehog_secret(secret_hash):
    secret_entry = TrufflehogSecret.query.filter_by(secret_hash=secret_hash).first()
    if secret_entry:
        return jsonify({"secret": secret_entry.secret})
    else:
        return jsonify({"error": "Secret not found"}), 404