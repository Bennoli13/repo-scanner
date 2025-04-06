from flask import Blueprint, render_template, request, jsonify
from . import db
from .models import GitSourceConfig, DefectDojoConfig, Repository, ScannerJob
from .utils import encrypt_token, decrypt_token, push_scan_job_to_queue

from sqlalchemy import and_
from datetime import datetime

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
        base_url=data["base_url"],
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

    if not source_id or not repo_ids or not scanners:
        return jsonify({"error": "Missing data"}), 400

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
                job.status = "pending"
            else:
                job = ScannerJob(
                    scanner_name=scanner_name,
                    repo_id=repo_id,
                    git_source_id=source_id,
                    status="pending",
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
            "status": job.status,
            "updated_at": job.updated_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify(result)

@main.route("/api/scan/<int:job_id>", methods=["PATCH"])
def update_scan_status(job_id):
    job = ScannerJob.query.get_or_404(job_id)
    data = request.get_json()

    job.status = data.get("status", job.status)
    job.updated_at = datetime.utcnow()

    db.session.commit()
    return jsonify({"message": "Job updated"}), 200

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
