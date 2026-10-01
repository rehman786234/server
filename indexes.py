"""Extra performance indexes. Safe to run on every start (IF NOT EXISTS).
Each statement is isolated, so a missing table/column never blocks startup."""
import logging

from database import get_connection, get_cursor

logger = logging.getLogger(__name__)

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_videos_list ON videos (is_premium, visibility, uploaded_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_videos_user ON videos (user_id, uploaded_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_api_usage_user_time ON api_usage (user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_api_usage_key ON api_usage (api_key_id)",
    "CREATE INDEX IF NOT EXISTS idx_vop_playlist ON videos_of_playlist (playlist_id, video_id)",
    "CREATE INDEX IF NOT EXISTS idx_playlist_created ON playlist (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_video_views_video ON video_views (video_id)",
    "CREATE INDEX IF NOT EXISTS idx_ads_type ON ads_table (ad_type)",
]


def ensure_indexes():
    try:
        with get_connection() as conn:
            for stmt in INDEXES:
                try:
                    with get_cursor(conn) as cur:
                        cur.execute(stmt)
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    logger.warning(f"Index skipped: {e}".strip())
    except Exception:
        logger.exception("ensure_indexes failed")
