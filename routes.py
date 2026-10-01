import secrets
from fastapi import APIRouter, HTTPException, status, Header
from fastapi.responses import HTMLResponse
from typing import Optional
from pydantic import BaseModel
import logging
from datetime import datetime, timedelta
import os
import hashlib

from database import execute_query, get_one
from models import User, UserCreate, UserLogin, APIKeyRequest, Video

logger = logging.getLogger(__name__)
router = APIRouter()


# Helper function to hash passwords
def hash_password(password: str) -> str:
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


# Helper function to validate API key
def validate_api_key(api_key: str):
    """Validate API key and return user data if valid"""
    try:
        query = """
            SELECT a.*, u.id as user_id, u.name, u.email, u.is_premium
            FROM apikeys a
            JOIN mydata u ON a.user_id = u.id
            WHERE a.api_key = %s 
            AND a.expiry_date > NOW()
        """
        result = get_one(query, (api_key,))
        return result
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        return None


# Function to read HTML file
def get_home_html():
    """Read the home.html file and return its content"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        html_path = os.path.join(current_dir, "home.html")

        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading home.html: {e}")
        return "<h1>Error loading page</h1>"


@router.get("/", response_class=HTMLResponse)
async def home():
    """Root endpoint - returns HTML page"""
    return get_home_html()


# ============ AUTHENTICATION ENDPOINTS ============

@router.post("/login")
async def login(user: UserLogin):
    """Login endpoint for frontend"""
    try:
        query = "SELECT * FROM mydata WHERE email = %s"
        db_user = get_one(query, (user.email,))

        if not db_user:
            return {"success": False, "message": "Invalid email or password"}

        hashed_input = hash_password(user.password)
        if db_user['password'] != hashed_input:
            return {"success": False, "message": "Invalid email or password"}

        db_user.pop('password', None)

        return {
            "success": True,
            "message": "Login successful",
            "user": {
                "id": db_user['id'],
                "name": db_user['name'],
                "email": db_user['email'],
                "is_premium": db_user['is_premium'],
                "created_at": db_user['created_at']
            }
        }

    except Exception as e:
        logger.error(f"Error in login: {e}")
        return {"success": False, "message": f"Login error: {str(e)}"}


@router.post("/register")
async def register(user: UserCreate):
    """Register endpoint for frontend"""
    try:
        check_query = "SELECT id FROM mydata WHERE email = %s"
        existing_user = get_one(check_query, (user.email,))

        if existing_user:
            return {"success": False, "message": "User with this email already exists"}

        hashed_password = hash_password(user.password)

        query = """
            INSERT INTO mydata (name, email, password, is_premium, created_at) 
            VALUES (%s, %s, %s, %s, %s) 
            RETURNING id, name, email, is_premium, created_at
        """
        result = get_one(
            query,
            (user.name, user.email, hashed_password, user.is_premium or False, datetime.now())
        )

        if result:
            return {"success": True, "message": "User registered successfully", "user": result}
        else:
            return {"success": False, "message": "Failed to register user"}

    except Exception as e:
        logger.error(f"Error in register: {e}")
        return {"success": False, "message": f"Registration error: {str(e)}"}


# ============ API KEY MANAGEMENT ENDPOINTS ============

@router.post("/apikey/gen")
async def generate_api_key(request: APIKeyRequest):
    """Generate a new API key for a user"""
    try:
        user_query = "SELECT * FROM mydata WHERE id = %s"
        user_exists = get_one(user_query, (request.user_id,))

        if not user_exists:
            return {"success": False, "message": "User not found"}

        api_key = secrets.token_hex(16)
        expiry_date = datetime.now() + timedelta(days=30)

        query = """
            INSERT INTO apikeys (user_id, api_key, created_at, expiry_date) 
            VALUES (%s, %s, %s, %s) 
            RETURNING id, user_id, api_key, created_at, expiry_date
        """
        result = get_one(query, (request.user_id, api_key, datetime.now(), expiry_date))

        if result:
            return {"success": True, "message": "API Key generated successfully", "api_key": result}
        else:
            return {"success": False, "message": "Failed to create API key"}

    except Exception as e:
        logger.error(f"Error in generate_api_key: {e}")
        return {"success": False, "message": f"Database error: {str(e)}"}


@router.get("/apikey/list")
async def list_user_apikeys(user_id: int):
    """Get all API keys for a specific user"""
    try:
        query = """
            SELECT id, user_id, api_key, created_at, expiry_date 
            FROM apikeys 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """
        results = execute_query(query, (user_id,), fetch=True)
        return {
            "success": True,
            "total": len(results) if results else 0,
            "api_keys": results if results else []
        }

    except Exception as e:
        logger.error(f"Error in list_user_apikeys: {e}")
        return {"success": False, "message": f"Database error: {str(e)}"}


@router.delete("/apikey/del")
async def delete_apikey(api_key: str):
    """Delete/Revoke an API key"""
    try:
        check_query = "SELECT id FROM apikeys WHERE api_key = %s"
        existing_key = get_one(check_query, (api_key,))

        if not existing_key:
            return {"success": False, "message": "API key not found"}

        query = "DELETE FROM apikeys WHERE api_key = %s RETURNING id"
        result = get_one(query, (api_key,))

        if result:
            return {"success": True, "message": "API key deleted successfully"}
        else:
            return {"success": False, "message": "Failed to delete API key"}

    except Exception as e:
        logger.error(f"Error in delete_apikey: {e}")
        return {"success": False, "message": f"Database error: {str(e)}"}


# ============ VIDEOS ENDPOINTS ============

@router.get("/videos")
async def get_videos():
    """
    Get all free PUBLIC videos (is_premium = false)
    - No API key required
    - Returns direct array (old format)
    """
    try:
        # CHANGED: added visibility = 'public'
        query = """
            SELECT * FROM videos 
            WHERE is_premium = false AND visibility = 'public'
            ORDER BY uploaded_at DESC
        """
        results = execute_query(query, fetch=True)
        return results if results else []

    except Exception as e:
        logger.error(f"Error in get_videos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.get("/premium_videos")
async def get_premium_videos(api_key: str = Header(...)):
    """Get all premium PUBLIC videos - requires API key"""
    user_data = validate_api_key(api_key)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )

    try:
        # CHANGED: added visibility = 'public'
        query = """
            SELECT * FROM videos 
            WHERE is_premium = true AND visibility = 'public'
            ORDER BY uploaded_at DESC
        """
        results = execute_query(query, fetch=True)

        return {
            "success": True,
            "message": "Premium videos retrieved successfully",
            "total": len(results) if results else 0,
            "videos": results if results else [],
            "user": {
                "id": user_data['user_id'],
                "name": user_data['name'],
                "email": user_data['email'],
                "is_premium": user_data['is_premium']
            }
        }

    except Exception as e:
        logger.error(f"Error in get_premium_videos: {e}")
        return {"success": False, "message": f"Database error: {str(e)}"}


@router.post("/upload_videos")
async def upload_video(video: Video, api_key: str = Header(...)):
    """Upload a new video (old endpoint, still works) - requires API key"""
    user_data = validate_api_key(api_key)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )

    viewkey = secrets.token_hex(6)

    try:
        # CHANGED: now also saves user_id (uploader)
        query = """
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium, user_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s) 
            RETURNING id, title, stream_link, viewkey, thumbnail, category, is_premium, uploaded_at
        """
        result = get_one(
            query,
            (video.title, video.stream_link, viewkey, video.thumbnail,
             video.category, video.is_premium, user_data.get('user_id'))
        )

        if result:
            return {
                "success": True,
                "message": "Video uploaded successfully",
                "viewkey": viewkey,
                "video": result,
                "uploaded_by": user_data.get('name', 'Unknown'),
                "user_id": user_data.get('user_id')
            }
        else:
            return {"success": False, "message": "Failed to upload video"}

    except Exception as e:
        logger.error(f"Error in upload_video: {e}")
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            return {"success": False, "message": "Video with this viewkey already exists"}
        return {"success": False, "message": f"Database error: {str(e)}"}


@router.get("/videos/{viewkey}")
async def get_video_by_key(viewkey: str):
    """Get a video by its viewkey"""
    try:
        query = "SELECT * FROM videos WHERE viewkey = %s AND visibility <> 'private'"  # CHANGED
        result = get_one(query, (viewkey,))

        if result:
            return {"success": True, "video": result}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Video not found"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_video_by_key: {e}")
        return {"success": False, "message": f"Database error: {str(e)}"}


# ============ PLAYLIST ENDPOINTS ============

@router.get("/playlists")
async def get_playlists():
    """Get all playlists with their playlist videos. No API key required."""
    try:
        query = """
            SELECT
                p.playlist_id,
                p.playlist_name,
                p.playlist_type,
                p.total_videos,
                p.playlist_thumbnail,
                p.created_at,

                COALESCE(
                    json_agg(
                        json_build_object(
                            'video_id', v.video_id,
                            'viewkey', v.viewkey,
                            'stream_url', v.stream_url,
                            'video_title', v.video_title,
                            'video_thumbnail', v.video_thumbnail,
                            'video_duration', v.video_duration,
                            'video_quality', v.video_quality
                        )
                        ORDER BY v.video_id ASC
                    ) FILTER (WHERE v.video_id IS NOT NULL),
                    '[]'::json
                ) AS videos

            FROM playlist AS p

            LEFT JOIN videos_of_playlist AS v
                ON v.playlist_id = p.playlist_id

            GROUP BY
                p.playlist_id,
                p.playlist_name,
                p.playlist_type,
                p.total_videos,
                p.playlist_thumbnail,
                p.created_at

            ORDER BY p.created_at DESC
        """

        results = execute_query(query, fetch=True)

        return {
            "success": True,
            "total": len(results) if results else 0,
            "playlists": results or []
        }

    except Exception as e:
        logger.exception("Error while retrieving playlists")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve playlists"
        )


@router.get("/playlists/{playlist_id}")
async def get_playlist(playlist_id: int):
    """Get one playlist with all of its videos. No API key required."""
    if playlist_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid playlist ID"
        )

    try:
        query = """
            SELECT
                p.playlist_id,
                p.playlist_name,
                p.playlist_type,
                p.total_videos,
                p.playlist_thumbnail,
                p.created_at,

                COALESCE(
                    json_agg(
                        json_build_object(
                            'video_id', v.video_id,
                            'viewkey', v.viewkey,
                            'stream_url', v.stream_url,
                            'video_title', v.video_title,
                            'video_thumbnail', v.video_thumbnail,
                            'video_duration', v.video_duration,
                            'video_quality', v.video_quality
                        )
                        ORDER BY v.video_id ASC
                    ) FILTER (WHERE v.video_id IS NOT NULL),
                    '[]'::json
                ) AS videos

            FROM playlist AS p

            LEFT JOIN videos_of_playlist AS v
                ON v.playlist_id = p.playlist_id

            WHERE p.playlist_id = %s

            GROUP BY
                p.playlist_id,
                p.playlist_name,
                p.playlist_type,
                p.total_videos,
                p.playlist_thumbnail,
                p.created_at
        """

        result = get_one(query, (playlist_id,))

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Playlist not found"
            )

        return {"success": True, "playlist": result}

    except HTTPException:
        raise

    except Exception:
        logger.exception("Error while retrieving playlist %s", playlist_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve playlist"
        )


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    from database import health_check
    is_healthy = health_check()
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "database": "connected" if is_healthy else "disconnected",
        "timestamp": datetime.now().isoformat()
    }


@router.get("/ads")
async def get_ads():
    """Get random ads: 2 image ads + 1 video ad. No API key required."""
    try:
        image_query = """
            SELECT id, ad_name, promotion_link, ad_type,link
            FROM ads_table
            WHERE ad_type = 'image'
            ORDER BY RANDOM()
            LIMIT 2
        """
        image_ads = execute_query(image_query, fetch=True) or []

        video_query = """
            SELECT id, ad_name, promotion_link, ad_type, link
            FROM ads_table
            WHERE ad_type = 'video'
            ORDER BY RANDOM()
            LIMIT 1
        """
        video_ads = execute_query(video_query, fetch=True) or []

        return {
            "success": True,
            "total": len(image_ads) + len(video_ads),
            "image_ads": image_ads,
            "video_ads": video_ads
        }

    except Exception as e:
        logger.exception("Error while retrieving ads")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ads"
        )


# =====================================================================
# ============ NEW: CREATOR STUDIO ENDPOINTS ==========================
# =====================================================================

class StudioVideoIn(BaseModel):
    title: str
    stream_link: str
    thumbnail: Optional[str] = ""
    category: Optional[str] = "Uncategorized"
    description: Optional[str] = ""
    visibility: Optional[str] = "public"
    is_premium: bool = False
    duration: Optional[int] = 0
    file_size: Optional[int] = 0


class StudioVideoEdit(BaseModel):
    title: Optional[str] = None
    thumbnail: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    visibility: Optional[str] = None
    is_premium: Optional[bool] = None


class ChannelIn(BaseModel):
    channel_name: str
    handle: Optional[str] = None
    avatar_url: Optional[str] = None
    description: Optional[str] = ""


def current_user(api_key: str):
    u = validate_api_key(api_key)
    if not u:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    return u


@router.get("/studio/my_videos")
async def studio_my_videos(api_key: str = Header(...)):
    u = current_user(api_key)
    rows = execute_query(
        "SELECT * FROM videos WHERE user_id=%s ORDER BY uploaded_at DESC",
        (u["user_id"],), fetch=True) or []
    return {"success": True, "total": len(rows), "videos": rows}


@router.post("/studio/videos")
async def studio_create_video(v: StudioVideoIn, api_key: str = Header(...)):
    u = current_user(api_key)
    if v.visibility not in ("public", "unlisted", "private"):
        raise HTTPException(400, "Invalid visibility")
    viewkey = secrets.token_hex(6)
    try:
        row = get_one("""
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium,
                                user_id, description, visibility, duration, file_size)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (v.title.strip(), v.stream_link, viewkey, v.thumbnail, v.category, v.is_premium,
             u["user_id"], v.description, v.visibility, v.duration, v.file_size))
        return {"success": True, "viewkey": viewkey, "video": row}
    except Exception:
        logger.exception("studio_create_video")
        return {"success": False, "message": "Could not save video"}


@router.put("/studio/videos/{video_id}")
async def studio_edit_video(video_id: int, v: StudioVideoEdit, api_key: str = Header(...)):
    u = current_user(api_key)
    fields = {k: val for k, val in v.dict().items() if val is not None}
    if not fields:
        return {"success": False, "message": "Nothing to update"}
    sets = ", ".join(f"{k}=%s" for k in fields) + ", updated_at=NOW()"
    row = get_one(f"UPDATE videos SET {sets} WHERE id=%s AND user_id=%s RETURNING *",
                  (*fields.values(), video_id, u["user_id"]))
    if not row:
        raise HTTPException(404, "Video not found")
    return {"success": True, "video": row}


@router.delete("/studio/videos/{video_id}")
async def studio_delete_video(video_id: int, api_key: str = Header(...)):
    u = current_user(api_key)
    row = get_one("DELETE FROM videos WHERE id=%s AND user_id=%s RETURNING id",
                  (video_id, u["user_id"]))
    if not row:
        raise HTTPException(404, "Video not found")
    return {"success": True}


@router.get("/studio/stats")
async def studio_stats(api_key: str = Header(...)):
    u = current_user(api_key)
    s = get_one("""
        SELECT COUNT(*) AS videos,
               COALESCE(SUM(views),0) AS views,
               COUNT(*) FILTER (WHERE is_premium) AS premium
        FROM videos WHERE user_id=%s""", (u["user_id"],))
    return {"success": True, "stats": s}


@router.get("/studio/channel")
async def studio_get_channel(api_key: str = Header(...)):
    u = current_user(api_key)
    return {"success": True,
            "channel": get_one("SELECT * FROM channels WHERE user_id=%s", (u["user_id"],))}


@router.put("/studio/channel")
async def studio_save_channel(c: ChannelIn, api_key: str = Header(...)):
    u = current_user(api_key)
    row = get_one("""
        INSERT INTO channels (user_id, channel_name, handle, avatar_url, description)
        VALUES (%s,%s,%s,%s,%s)
        ON CONFLICT (user_id) DO UPDATE SET channel_name=EXCLUDED.channel_name,
            handle=EXCLUDED.handle, avatar_url=EXCLUDED.avatar_url,
            description=EXCLUDED.description RETURNING *""",
        (u["user_id"], c.channel_name, c.handle, c.avatar_url, c.description))
    return {"success": True, "channel": row}


@router.post("/studio/view/{viewkey}")
async def studio_count_view(viewkey: str):
    """Viewer page se call karo - view count barhata hai"""
    row = get_one("UPDATE videos SET views=views+1 WHERE viewkey=%s RETURNING id", (viewkey,))
    if row:
        get_one("INSERT INTO video_views (video_id) VALUES (%s) RETURNING id", (row["id"],))
    return {"success": bool(row)}
