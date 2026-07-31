import os

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")
    
    # CORS origins
    ORIGINS = [
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://localhost:5173",
        "https://your-frontend-domain.onrender.com",  # Add your frontend URL
    ]
    
    # Pool settings
    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = 10
    
    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable is required")
