from app import create_app, db
from app.models import GitSourceConfig, DefectDojoConfig, Repository, ScannerJob, ScheduledScan

app = create_app()
with app.app_context():
    # Create the database and tables if they don't exist
    db.create_all()