import os

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
    
    # CORS origins - Update with your frontend URLs
    ORIGINS = [
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://localhost:5173",
        "*",  # Update with your frontend URL
    ]
    
    # Connection pool settings
    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = 10
    
    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable is required")
        return True
