import os

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")
    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = 5   # Neon free tier ke liye 5 se zyada mat rakho

    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL is not set")
