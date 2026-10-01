import os

class Config:
    # ... baaki existing attributes ...
    DATABASE_URL = os.getenv("DATABASE_URL")
    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = 5

    # CORS origins — comma separated env var se lo, ya default
    ORIGINS = os.getenv("ORIGINS", "*").split(",")

    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL is not set")
