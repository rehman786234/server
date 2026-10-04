import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")
    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = max(2, int(os.getenv("DB_POOL_MAX", "10")))
    POOL_ACQUIRE_TIMEOUT = max(1, int(os.getenv("DB_POOL_ACQUIRE_TIMEOUT", "5")))

    # Never combine wildcard origins with credentials; use explicit browser origins.
    ORIGINS = list(dict.fromkeys([
        origin.strip().rstrip("/")
        for origin in os.getenv("ORIGINS", "").split(",")
        if origin.strip() and origin.strip() != "*"
    ]))
    ORIGINS = list(dict.fromkeys(
        ORIGINS + ["http://localhost:5173", "http://127.0.0.1:5173"]
    ))
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
    RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "").strip()
    SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "").strip()
    SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "0").strip().lower() in {"1", "true", "yes"}

    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL is not set")
