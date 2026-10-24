# cache.py
"""
Thread-safe, bounded in-memory TTL cache.

Entries are local to this server process. Use a shared cache service when
multiple workers or instances need to share cached values.
"""
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from typing import Any, Callable, Dict, Optional, Tuple

_cache: "OrderedDict[str, Tuple[Any, float]]" = OrderedDict()
_lock = threading.Lock()
_inflight: Dict[str, Tuple[Future, int]] = {}
_generation = 0
_hits = 0
_misses = 0
_max_size = 5000


def _read_locked(key: str) -> Tuple[bool, Optional[Any]]:
    global _hits, _misses
    entry = _cache.get(key)
    if entry is None:
        _misses += 1
        return False, None
    value, expires_at = entry
    if expires_at <= time.monotonic():
        _cache.pop(key, None)
        _misses += 1
        return False, None
    _cache.move_to_end(key)
    _hits += 1
    return True, value


def _write_locked(key: str, value: Any, ttl: int) -> None:
    _cache.pop(key, None)
    _cache[key] = (value, time.monotonic() + max(0, ttl))
    while len(_cache) > _max_size:
        _cache.popitem(last=False)


def cache_get(key: str) -> Optional[Any]:
    """Return a fresh value, or None when the key is missing or expired."""
    with _lock:
        _, value = _read_locked(key)
        return value


def cache_set(key: str, value: Any, ttl: int = 60) -> None:
    """Store a value for the requested number of seconds."""
    with _lock:
        _write_locked(key, value, ttl)


def cache_get_or_set(key: str, loader: Callable[[], Any], ttl: int = 60) -> Any:
    """Share one concurrent cache fill for a key and propagate loader failures."""
    with _lock:
        hit, value = _read_locked(key)
        if hit:
            return value
        current = _inflight.get(key)
        if current is None or current[1] != _generation:
            future = Future()
            generation = _generation
            _inflight[key] = (future, generation)
            is_loader = True
        else:
            future = current[0]
            is_loader = False

    if not is_loader:
        return future.result()

    try:
        value = loader()
        with _lock:
            if generation == _generation:
                _write_locked(key, value, ttl)
            future.set_result(value)
        return value
    except BaseException as error:
        future.set_exception(error)
        raise
    finally:
        with _lock:
            current = _inflight.get(key)
            if current is not None and current[0] is future:
                _inflight.pop(key, None)


def cache_del(*keys: str) -> None:
    """Delete keys and prevent concurrent fills from repopulating stale data."""
    global _generation
    if not keys:
        return
    with _lock:
        for key in keys:
            _cache.pop(key, None)
        _generation += 1


def cache_del_prefix(prefix: str) -> None:
    """Delete matching keys and invalidate concurrent cache fills."""
    global _generation
    with _lock:
        matching = [key for key in _cache if key.startswith(prefix)]
        for key in matching:
            _cache.pop(key, None)
        _generation += 1


def cache_clear() -> None:
    global _hits, _misses, _generation
    with _lock:
        _cache.clear()
        _hits = 0
        _misses = 0
        _generation += 1


def cache_stats() -> dict:
    """Return lightweight cache and in-flight request statistics."""
    with _lock:
        total = _hits + _misses
        return {
            "size": len(_cache),
            "hits": _hits,
            "misses": _misses,
            "hit_rate": round((_hits / total * 100) if total else 0, 1),
            "inflight": len(_inflight),
        }
