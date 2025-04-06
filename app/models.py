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