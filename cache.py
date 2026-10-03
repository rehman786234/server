# cache.py
"""
Simple in-memory TTL cache.
- Thread-safe
- Per-worker (Render pe 1 worker hai, to perfect)
- API: cache_get / cache_set / cache_del / cache_del_prefix / cache_stats
"""
import time
import threading
from typing import Any, Optional, Dict, Tuple

_cache: Dict[str, Tuple[Any, float]] = {}
_lock = threading.Lock()

# Stats (debugging ke liye)
_hits = 0
_misses = 0
_max_size = 5000


def cache_get(key: str) -> Optional[Any]:
    """Value return karo, ya None agar expire / missing."""
    global _hits, _misses
    with _lock:
        entry = _cache.get(key)
        if entry is None:
            _misses += 1
            return None
        value, expires_at = entry
        if expires_at < time.time():
            _cache.pop(key, None)
            _misses += 1
            return None
        _hits += 1
        return value


def cache_set(key: str, value: Any, ttl: int = 60) -> None:
    """Value store karo TTL seconds ke liye."""
    with _lock:
        # Simple size guard
        if len(_cache) >= _max_size:
            # Purani 500 entries hatao
            now = time.time()
            expired = [k for k, (_, exp) in _cache.items() if exp < now]
            for k in expired:
                _cache.pop(k, None)
            # Agar phir bhi bhara hua, kuch random hatao
            if len(_cache) >= _max_size:
                for k in list(_cache.keys())[:500]:
                    _cache.pop(k, None)
        _cache[key] = (value, time.time() + ttl)


def cache_del(*keys: str) -> None:
    """Ek ya zyada keys delete karo."""
    with _lock:
        for k in keys:
            _cache.pop(k, None)


def cache_del_prefix(prefix: str) -> None:
    """Prefix wali saari keys delete karo."""
    with _lock:
        for k in [k for k in _cache.keys() if k.startswith(prefix)]:
            _cache.pop(k, None)


def cache_clear() -> None:
    """Poora cache clear karo."""
    global _hits, _misses
    with _lock:
        _cache.clear()
        _hits = 0
        _misses = 0


def cache_stats() -> dict:
    """Debug info."""
    with _lock:
        total = _hits + _misses
        return {
            "size": len(_cache),
            "hits": _hits,
            "misses": _misses,
            "hit_rate": round((_hits / total * 100) if total else 0, 1),
        }
