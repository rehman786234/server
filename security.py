"""Security + speed helpers: password hashing, login tokens, rate limiter, TTL cache."""
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from typing import Any, Optional, Tuple

from config import Config

# ---------------------------------------------------------------- passwords
PBKDF2_ITERATIONS = 210_000
_dummy = None


def _pbkdf2(password: str, salt_hex: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations
    ).hex()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt}${_pbkdf2(password, salt, PBKDF2_ITERATIONS)}"


def verify_password(password: str, stored: Optional[str]) -> Tuple[bool, bool]:
    """Returns (ok, needs_upgrade). Old unsalted SHA-256 hashes still work and
    are upgraded to PBKDF2 automatically on the next successful login."""
    if not stored or len(password) > 1024:
        return False, False
    try:
        if stored.startswith("pbkdf2$"):
            _, it, salt, dk = stored.split("$")
            it = int(it)
            ok = hmac.compare_digest(_pbkdf2(password, salt, it), dk)
            return ok, ok and it < PBKDF2_ITERATIONS
        ok = hmac.compare_digest(hashlib.sha256(password.encode("utf-8")).hexdigest(), stored)
        return ok, ok
    except Exception:
        return False, False


def dummy_hash() -> str:
    """Used for unknown emails so login takes the same time (no user enumeration)."""
    global _dummy
    if _dummy is None:
        _dummy = hash_password(secrets.token_hex(8))
    return _dummy


# ------------------------------------------------------------------- tokens
_FALLBACK_KEY = secrets.token_hex(32)


def _key() -> bytes:
    return (Config.SECRET_KEY or _FALLBACK_KEY).encode()


def make_token(user_id: int, ttl: int = 7 * 86400) -> str:
    payload = f"{int(user_id)}.{int(time.time()) + ttl}"
    sig = hmac.new(_key(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(token: Optional[str]) -> Optional[int]:
    try:
        uid, exp, sig = (token or "").split(".")
        expected = hmac.new(_key(), f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected) or int(exp) < time.time():
            return None
        return int(uid)
    except Exception:
        return None


# ------------------------------------------------------------- rate limiter
class RateLimiter:
    """In-memory sliding window (per worker process)."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()
        self._last_gc = time.monotonic()

    def allow(self, key: str, limit: int, window: int = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = self._hits[key] = deque()
            while dq and dq[0] <= now - window:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            if now - self._last_gc > 120:
                self._last_gc = now
                for k in [k for k, d in self._hits.items() if not d or d[-1] <= now - 300]:
                    del self._hits[k]
            return True


def client_ip(xff: Optional[str], peer: Optional[str]) -> str:
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            hops = Config.PROXY_HOPS
            return parts[-hops] if 0 < hops <= len(parts) else parts[0]
    return peer or "unknown"


SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"SAMEORIGIN"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
]


# -------------------------------------------------------------------- cache
class TTLCache:
    def __init__(self, max_items: int = 5000):
        self._d = {}
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str) -> Any:
        item = self._d.get(key)
        if item and item[0] > time.monotonic():
            return item[1]
        return None

    def set(self, key: str, value: Any, ttl: float) -> None:
        with self._lock:
            if len(self._d) >= self._max:
                now = time.monotonic()
                self._d = {k: v for k, v in self._d.items() if v[0] > now}
                if len(self._d) >= self._max:
                    self._d.clear()
            self._d[key] = (time.monotonic() + ttl, value)

    def delete(self, key: str) -> None:
        with self._lock:
            self._d.pop(key, None)

    def clear_prefix(self, prefix: str) -> None:
        with self._lock:
            for k in [k for k in self._d if k.startswith(prefix)]:
                del self._d[k]
