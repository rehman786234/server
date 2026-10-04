import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")
    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = max(2, int(os.getenv("DB_POOL_MAX", "10")))
    POOL_ACQUIRE_TIMEOUT = max(1, int(os.getenv("DB_POOL_ACQUIRE_TIMEOUT", "5")))

    # CORS origins are exact browser origins, without paths or trailing slashes.
    ORIGINS = list(dict.fromkeys([
        origin.strip().rstrip("/")
        for origin in (
            os.getenv("ORIGINS", "*") + ",http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if origin.strip()
    ]))
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
    RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "").strip()

    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL is not set")
