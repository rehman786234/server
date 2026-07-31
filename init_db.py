import logging
import secrets
from database import get_connection, get_cursor

logger = logging.getLogger(__name__)


def init_database():
    """Initialize database tables safely (idempotent migration)"""
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                
                # Create mydata table
                logger.info("Checking/migrating mydata table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS mydata (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Check if table exists and has data
                cursor.execute("SELECT COUNT(*) as count FROM mydata")
                count = cursor.fetchone()['count']
                logger.info(f"mydata table has {count} records")
                
                # Create apikeys table
                logger.info("Checking/migrating apikeys table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS apikeys (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES mydata(id) ON DELETE CASCADE
                    )
                """)
                
                # Check if table exists and has data
                cursor.execute("SELECT COUNT(*) as count FROM apikeys")
                count = cursor.fetchone()['count']
                logger.info(f"apikeys table has {count} records")
                
                # Create videos table
                logger.info("Checking/migrating videos table...")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS videos (
                        id SERIAL PRIMARY KEY,
                        title TEXT NOT NULL,
                        stream_link TEXT NOT NULL,
                        viewkey TEXT UNIQUE NOT NULL,
                        thumbnail TEXT,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Check if table exists and has data
                cursor.execute("SELECT COUNT(*) as count FROM videos")
                count = cursor.fetchone()['count']
                logger.info(f"videos table has {count} records")
                
                # Create indexes for performance
                logger.info("Creating indexes...")
                
                # Index for mydata email
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mydata_email 
                    ON mydata(email)
                """)
                
                # Index for apikeys
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_apikeys_user_id 
                    ON apikeys(user_id)
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_apikeys_api_key 
                    ON apikeys(api_key)
                """)
                
                # Index for videos
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_videos_viewkey 
                    ON videos(viewkey)
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_videos_uploaded_at 
                    ON videos(uploaded_at DESC)
                """)
                
                connection.commit()
                logger.info("Database migration completed successfully!")
                
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise
