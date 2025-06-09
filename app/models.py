from . import db
from sqlalchemy.ext.mutable import MutableList
from datetime import datetime


class DefectDojoConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255))
    token = db.Column(db.String(255))
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class GitSourceConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label_name = db.Column(db.String(255)) # name that will be Product name on the Defectdojo
    platform = db.Column(db.String(20))  # 'github' or 'gitlab'
    base_url = db.Column(db.String(255))
    username = db.Column(db.String(255))
    token = db.Column(db.String(255))
    repos = db.relationship("Repository", backref="source_config", cascade="all, delete")
    scanner_jobs = db.relationship("ScannerJob", backref="source_config", cascade="all, delete")
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    source_id = db.Column(db.Integer, db.ForeignKey("git_source_config.id"))
    scanner_jobs = db.relationship("ScannerJob", backref="repository", cascade="all, delete")
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class ScannerJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scanner_name = db.Column(db.String(50))
    repo_id = db.Column(db.Integer, db.ForeignKey("repository.id"))
    git_source_id = db.Column(db.Integer, db.ForeignKey("git_source_config.id"))
    total_branch = db.Column(db.Integer, default=0)
    scanned_branch = db.Column(MutableList.as_mutable(db.JSON), default=list)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    @property
    def progress(self):
        scanned_count = len(self.scanned_branch or [])
        if self.total_branch == 0:
            return "pending"
        progress_ratio = scanned_count / self.total_branch
        if progress_ratio >= 0.8:
            return "completed"
        elif scanned_count > 0:
            return "in_progress"
        else:
            return "pending"
    @property
    def progress_ratio(self):
        scanned_count = len(self.scanned_branch or [])
        if self.total_branch == 0:
            return 0.0
        return round(scanned_count / self.total_branch, 2)
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

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
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class ScanHashRecord(db.Model):
    __tablename__ = "scan_hash_record"
    id = db.Column(db.Integer, primary_key=True)
    scanner = db.Column(db.String(50), nullable=False)
    repo_name = db.Column(db.String(255), nullable=False)
    branch = db.Column(db.String(255), nullable=False)
    result_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('scanner', 'repo_name', 'branch', 'result_hash', name='unique_scan_hash'),
    )

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
    
class WebhookSecret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(20), nullable=False)  # 'github', 'gitlab'
    secret = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    __table_args__ = (db.UniqueConstraint("platform", name="unique_platform_webhook"),)
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class UploadHistory(db.Model):
    __tablename__ = "upload_history"

    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(128), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    upload_status = db.Column(
        db.String(10),
        nullable=False,
        default="fail"
    )  # either 'success' or 'fail'

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
    
class VulnerabilityIgnoreRule(db.Model):
    __tablename__ = "vulnerability_ignore_rules"

    id = db.Column(db.Integer, primary_key=True)
    scanner = db.Column(db.String(50), nullable=False)          # e.g., "trufflehog"
    keyword = db.Column(db.String(255), nullable=False)         # e.g., Detector Name
    engagement = db.Column(db.Integer, nullable=True)           # e.g., 1, 2, 3; NULL for "all"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class SlackWebhook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    url = db.Column(db.String(512), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    notify_trufflehog = db.Column(db.Boolean, default=False)
    notify_trivy = db.Column(db.Boolean, default=False)