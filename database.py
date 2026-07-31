import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from typing import Generator, Dict, Any, List, Optional
import logging
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global connection pool
_connection_pool = None


def init_connection_pool():
    """Initialize the PostgreSQL connection pool"""
    global _connection_pool
    
    try:
        Config.validate()
        
        # Log connection info (without password)
        db_url = Config.DATABASE_URL
        logger.info(f"Initializing database connection to: {db_url.split('@')[1] if '@' in db_url else 'database'}")
        
        # Create connection pool
        _connection_pool = pool.SimpleConnectionPool(
            minconn=Config.MIN_CONNECTIONS,
            maxconn=Config.MAX_CONNECTIONS,
            dsn=Config.DATABASE_URL,
            cursor_factory=RealDictCursor
        )
        logger.info("Database connection pool initialized successfully")
        return _connection_pool
        
    except Exception as e:
        logger.error(f"Failed to initialize connection pool: {e}")
        raise


@contextmanager
def get_connection() -> Generator:
    """Context manager for database connections"""
    global _connection_pool
    
    if _connection_pool is None:
        init_connection_pool()
    
    connection = None
    try:
        connection = _connection_pool.getconn()
        yield connection
    except Exception as e:
        if connection:
            connection.rollback()
        logger.error(f"Database connection error: {e}")
        raise
    finally:
        if connection:
            _connection_pool.putconn(connection)


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
        connection.rollback() if 'connection' in locals() else None
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
    global _connection_pool
    if _connection_pool:
        _connection_pool.closeall()
        logger.info("All database connections closed")
