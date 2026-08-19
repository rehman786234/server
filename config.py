import os


class Config:
    DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

    ORIGINS = [
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://localhost:5173",
        "https://videoserver.kesug.com",
    ]

    MIN_CONNECTIONS = 1
    MAX_CONNECTIONS = 10

    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError(
                "DATABASE_URL environment variable is missing or empty"
            )

        print("DATABASE_URL detected")
        print(
            "Database host:",
            Config.DATABASE_URL.split("@")[-1].split("/")[0]
        )

        return True
