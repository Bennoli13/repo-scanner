from . import db

class DefectDojoConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255))
    token = db.Column(db.String(255))

class GitSourceConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label_name = db.Column(db.String(255)) # name that will be Product name on the Defectdojo
    platform = db.Column(db.String(20))  # 'github' or 'gitlab'
    base_url = db.Column(db.String(255))
    username = db.Column(db.String(255))
    token = db.Column(db.String(255))
    repos = db.relationship("Repository", backref="source_config", cascade="all, delete")
    scanner_jobs = db.relationship("ScannerJob", backref="source_config", cascade="all, delete")

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    source_id = db.Column(db.Integer, db.ForeignKey("git_source_config.id"))
    scanner_jobs = db.relationship("ScannerJob", backref="repository", cascade="all, delete")

class ScannerJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scanner_name = db.Column(db.String(50))
    repo_id = db.Column(db.Integer, db.ForeignKey("repository.id"))
    git_source_id = db.Column(db.Integer, db.ForeignKey("git_source_config.id"))
    status = db.Column(db.String(50), default="pending")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

class ScheduledScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("git_source_config.id"), nullable=False)
    repo_id = db.Column(db.Integer, db.ForeignKey("repository.id"), nullable=True)  # null = all repos
    scanner_name = db.Column(db.String(50), nullable=False)
    cron_day = db.Column(db.String(10))     # e.g. 'mon', '*'
    cron_hour = db.Column(db.Integer)       # 0–23
    cron_minute = db.Column(db.Integer)     # 0–59
    last_run = db.Column(db.DateTime)

    source = db.relationship("GitSourceConfig", backref=db.backref("scheduled_scans", cascade="all, delete"))
    repo = db.relationship("Repository", backref=db.backref("scheduled_scans", cascade="all, delete"))

class ScanHashRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scanner = db.Column(db.String(50), nullable=False)
    repo_name = db.Column(db.String(255), nullable=False)  # ADD THIS
    branch = db.Column(db.String(255), nullable=False)
    result_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint("scanner", "repo_name", "branch", name="unique_scanner_repo_branch"),
    )

class WebhookSecret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(20), nullable=False)  # 'github', 'gitlab'
    secret = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    __table_args__ = (db.UniqueConstraint("platform", name="unique_platform_webhook"),)
