import logging
import threading
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

from config import Config

logger = logging.getLogger(__name__)

_pool = None
_sem = None
_lock = threading.Lock()


def init_connection_pool():
    """Thread-safe pool (ThreadedConnectionPool) with keepalives + query timeout."""
    global _pool, _sem
    with _lock:
        if _pool is not None:
            return _pool
        Config.validate()
        _pool = pool.ThreadedConnectionPool(
            Config.MIN_CONNECTIONS,
            Config.MAX_CONNECTIONS,
            dsn=Config.DATABASE_URL,
            cursor_factory=RealDictCursor,
            connect_timeout=10,
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=3,
            options="-c statement_timeout=15000",
        )
        # Extra threads WAIT for a free connection instead of failing with PoolError
        _sem = threading.BoundedSemaphore(Config.MAX_CONNECTIONS)
        logger.info("Database connection pool initialized")
        return _pool


@contextmanager
def get_connection() -> Generator:
    if _pool is None:
        init_connection_pool()
    if not _sem.acquire(timeout=10):
        raise RuntimeError("Database busy, try again")
    conn = None
    broken = False
    try:
        conn = _pool.getconn()
        if conn.closed:  # stale connection (DB restarted / idle timeout)
            _pool.putconn(conn, close=True)
            conn = _pool.getconn()
        yield conn
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise
    except Exception:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                broken = True
        raise
    finally:
        if conn is not None:
            try:
                _pool.putconn(conn, close=broken or conn.closed)
            except Exception:
                pass
        _sem.release()


@contextmanager
def get_cursor(connection, cursor_factory=RealDictCursor) -> Generator:
    cursor = connection.cursor(cursor_factory=cursor_factory)
    try:
        yield cursor
    finally:
        cursor.close()


def execute_query(query: str, params: tuple = (), fetch: bool = False) -> Optional[List[Dict]]:
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute(query, params)
                result = cursor.fetchall() if fetch else None
                connection.commit()
                return [dict(row) for row in result] if fetch else None
    except psycopg2.Error as e:
        logger.error(f"Database error: {e}")
        raise


def get_one(query: str, params: tuple = ()) -> Optional[Dict]:
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute(query, params)
                result = cursor.fetchone()
                connection.commit()
                return dict(result) if result else None
    except psycopg2.Error as e:
        logger.error(f"Database error in get_one: {e}")
        raise


def health_check() -> bool:
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute("SELECT 1")
                return True
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False


def close_all_connections():
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None
        logger.info("All database connections closed")
