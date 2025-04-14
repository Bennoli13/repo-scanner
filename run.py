from app import create_app, db
from app.models import GitSourceConfig, DefectDojoConfig, Repository, ScannerJob, ScheduledScan, ScanHashRecord

app = create_app()

with app.app_context():
    # Create the database and tables if they don't exist
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0")
