import os


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return int(default)


class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")

    # Connection pool (per worker process). Workers x MAX_CONNECTIONS must stay
    # under your Postgres plan's connection limit.
    MIN_CONNECTIONS = _int("DB_MIN_CONN", 2)
    MAX_CONNECTIONS = _int("DB_MAX_CONN", 15)
    THREADPOOL_SIZE = _int("THREADPOOL_SIZE", 40)

    # CORS origins: comma separated env var, default "*"
    ORIGINS = [o.strip() for o in os.getenv("ORIGINS", "*").split(",") if o.strip()] or ["*"]

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY")                       # signs login tokens
    STRICT_AUTH = os.getenv("STRICT_AUTH", "0") == "1"         # force token on /apikey/*
    ALLOW_SELF_PREMIUM = os.getenv("ALLOW_SELF_PREMIUM", "0") == "1"
    ENABLE_DOCS = os.getenv("ENABLE_DOCS", "0") == "1"         # /docs, /redoc
    RATE_LIMIT_PER_MIN = _int("RATE_LIMIT_PER_MIN", 600)       # per IP, all endpoints
    AUTH_RATE_LIMIT_PER_MIN = _int("AUTH_RATE_LIMIT_PER_MIN", 20)  # login/register etc.
    MAX_BODY_BYTES = _int("MAX_BODY_BYTES", 5 * 1024 * 1024)
    PROXY_HOPS = _int("PROXY_HOPS", 0)  # 0 = first X-Forwarded-For entry

    # Speed
    CACHE_TTL = _int("CACHE_TTL", 10)          # seconds, public lists
    KEY_CACHE_TTL = _int("KEY_CACHE_TTL", 30)  # seconds, API key lookups

    @classmethod
    def validate(cls):
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL is not set")
        if cls.STRICT_AUTH and not cls.SECRET_KEY:
            raise ValueError("SECRET_KEY must be set when STRICT_AUTH=1")
