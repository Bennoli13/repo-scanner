# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///scanner.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    FERNET_KEY = os.getenv("FERNET_KEY")
    if not FERNET_KEY:
        raise RuntimeError("❌ FERNET_KEY is not set in environment or .env file")
