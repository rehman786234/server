import psycopg2
from psycopg2 import pool
from psycopg2.extensions import TRANSACTION_STATUS_IDLE
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from typing import Generator, Dict, List, Optional
import logging
import threading
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global connection pool
_connection_pool = None
_pool_slots = None
_pool_init_lock = threading.Lock()


def init_connection_pool():
    """Initialize the pool once; concurrent callers wait for a free slot."""
    global _connection_pool, _pool_slots
    
    try:
        with _pool_init_lock:
            if _connection_pool is not None:
                return _connection_pool
            Config.validate()
            logger.info("Initializing database connection pool")
            _connection_pool = pool.ThreadedConnectionPool(
                minconn=Config.MIN_CONNECTIONS,
                maxconn=Config.MAX_CONNECTIONS,
                dsn=Config.DATABASE_URL,
                cursor_factory=RealDictCursor,
                connect_timeout=10,
                options="-c statement_timeout=15000 -c idle_in_transaction_session_timeout=30000",
            )
            _pool_slots = threading.BoundedSemaphore(Config.MAX_CONNECTIONS)
            logger.info(
                "Database connection pool initialized (max=%s)",
                Config.MAX_CONNECTIONS,
            )
            return _connection_pool
        
    except Exception as e:
        logger.error(f"Failed to initialize connection pool: {e}")
        raise


@contextmanager
def get_connection() -> Generator:
    """Context manager for database connections"""
    global _connection_pool, _pool_slots
    
    if _connection_pool is None:
        init_connection_pool()

    if not _pool_slots.acquire(timeout=Config.POOL_ACQUIRE_TIMEOUT):
        raise psycopg2.OperationalError("Timed out waiting for an available database connection")

    connection = None
    try:
        connection = _connection_pool.getconn()
        yield connection
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise
    finally:
        try:
            if connection:
                try:
                    if (not connection.closed
                            and connection.get_transaction_status() != TRANSACTION_STATUS_IDLE):
                        connection.rollback()
                finally:
                    _connection_pool.putconn(connection, close=bool(connection.closed))
        finally:
            _pool_slots.release()


@contextmanager
def get_cursor(connection, cursor_factory=RealDictCursor) -> Generator:
    """Context manager for database cursors"""
    cursor = connection.cursor(cursor_factory=cursor_factory)
    try:
        yield cursor
    finally:
        cursor.close()


def execute_query(query: str, params: tuple = (), fetch: bool = False) -> Optional[List[Dict]]:
    """Execute a query with automatic connection management"""
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute(query, params)
                
                if fetch:
                    result = cursor.fetchall()
                    connection.commit()
                    return [dict(row) for row in result]
                else:
                    connection.commit()
                    return None
                    
    except psycopg2.Error as e:
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


def get_one(query: str, params: tuple = ()) -> Optional[Dict]:
    """Execute a query and return a single row"""
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
    """Check database connectivity"""
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute("SELECT 1")
                return True
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False


def close_all_connections():
    """Close all connections in the pool"""
    global _connection_pool, _pool_slots
    if _connection_pool:
        _connection_pool.closeall()
        _connection_pool = None
        _pool_slots = None
        logger.info("All database connections closed")
