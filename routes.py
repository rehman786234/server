import logging
import os
import queue
import secrets
import threading
from collections import Counter
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from config import Config
from database import execute_query, get_connection, get_cursor, get_one
from models import APIKeyRequest, User, UserCreate, UserLogin, Video  # noqa: F401
from security import (TTLCache, client_ip, dummy_hash, hash_password, make_token,
                      verify_password, verify_token)

logger = logging.getLogger(__name__)
router = APIRouter()

# NOTE: every handler that touches the database is a plain `def` (not `async def`).
# FastAPI runs those in a thread pool, so one slow query no longer freezes the
# whole server (psycopg2 is blocking).

cache = TTLCache()


# ------------------------------------------------------------------ helpers
def cached_json(key: str, producer, ttl: Optional[int] = None) -> Response:
    """Cache the already-serialised JSON body (byte-identical to normal output)."""
    body = cache.get(key)
    if body is None:
        body = JSONResponse(jsonable_encoder(producer())).body
        cache.set(key, body, ttl or Config.CACHE_TTL)
    return Response(content=body, media_type="application/json")


def _page(limit: Optional[int], offset: int):
    """Optional pagination. No `limit` = old behaviour (everything)."""
    if limit is None:
        return "", ()
    return " LIMIT %s OFFSET %s", (max(1, min(int(limit), 500)), max(0, int(offset or 0)))


def check_owner(user_id: int, authorization: Optional[str]):
    """If a valid login token is sent it must belong to user_id.
    With STRICT_AUTH=1 a token is mandatory."""
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    uid = verify_token(token) if token else None
    if uid is not None:
        if uid != user_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden")
        return
    if Config.STRICT_AUTH:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Login required")


# ------------------------------------------------- API key check + analytics
_usage_q: "queue.Queue" = queue.Queue(maxsize=5000)
_worker_started = False
_worker_lock = threading.Lock()


def _usage_worker():
    """Writes analytics in batches in the background (never slows a request)."""
    while True:
        batch = [_usage_q.get()]
        try:
            while len(batch) < 200:
                batch.append(_usage_q.get_nowait())
        except queue.Empty:
            pass
        try:
            with get_connection() as conn:
                with get_cursor(conn) as cur:
                    cur.executemany(
                        "INSERT INTO api_usage (api_key_id, user_id, endpoint, method) "
                        "VALUES (%s,%s,%s,%s)", batch)
                    for key_id, n in Counter(b[0] for b in batch).items():
                        cur.execute("UPDATE apikeys SET request_count = request_count + %s, "
                                    "last_used_at = NOW() WHERE id=%s", (n, key_id))
                conn.commit()
        except Exception:
            logger.exception("Usage tracking error")


def track_usage(key_row, endpoint: str, method: str = "GET"):
    global _worker_started
    if not _worker_started:
        with _worker_lock:
            if not _worker_started:
                threading.Thread(target=_usage_worker, daemon=True).start()
                _worker_started = True
    try:
        _usage_q.put_nowait((key_row["key_id"], key_row["user_id"], endpoint, method))
    except queue.Full:
        pass  # analytics must never break the main request


def validate_api_key(api_key: str, endpoint: str = None, method: str = "GET"):
    """Validate API key, return user data (cached briefly). Logs the call if endpoint given."""
    try:
        ck = "k:" + api_key
        result = cache.get(ck)
        if result is None:
            result = get_one("""
                SELECT a.*, a.id as key_id, u.id as user_id, u.name, u.email, u.is_premium
                FROM apikeys a
                JOIN mydata u ON a.user_id = u.id
                WHERE a.api_key = %s
                AND a.expiry_date > NOW()
            """, (api_key,))
            if result:
                cache.set(ck, result, Config.KEY_CACHE_TTL)
        if result and endpoint:
            track_usage(result, endpoint, method)
        return result
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        return None


def current_user(api_key: str, endpoint: str = None, method: str = "GET"):
    u = validate_api_key(api_key, endpoint, method)
    if not u:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    return u


# --------------------------------------------------------------------- home
_home_html = None


def get_home_html():
    global _home_html
    if _home_html is None:
        try:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "home.html")
            with open(path, "r", encoding="utf-8") as f:
                _home_html = f.read()
        except Exception as e:
            logger.error(f"Error reading home.html: {e}")
            return "<h1>Error loading page</h1>"
    return _home_html


@router.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(get_home_html(), headers={"Cache-Control": "public, max-age=60"})


# ================= AUTHENTICATION =================
@router.post("/login")
def login(user: UserLogin):
    try:
        db_user = get_one("SELECT * FROM mydata WHERE email = %s", (user.email,))
        if not db_user:
            verify_password(user.password, dummy_hash())  # same timing as a real check
            return {"success": False, "message": "Invalid email or password"}

        ok, upgrade = verify_password(user.password, db_user["password"])
        if not ok:
            return {"success": False, "message": "Invalid email or password"}

        if upgrade:  # silently move old SHA-256 hash to salted PBKDF2
            try:
                get_one("UPDATE mydata SET password=%s WHERE id=%s RETURNING id",
                        (hash_password(user.password), db_user["id"]))
            except Exception:
                logger.exception("password upgrade failed")

        return {
            "success": True,
            "message": "Login successful",
            "token": make_token(db_user["id"]),  # NEW (extra field, old clients ignore it)
            "user": {
                "id": db_user["id"],
                "name": db_user["name"],
                "email": db_user["email"],
                "is_premium": db_user["is_premium"],
                "phone": db_user.get("phone"),
                "bio": db_user.get("bio"),
                "avatar_url": db_user.get("avatar_url"),
                "created_at": db_user["created_at"],
            },
        }
    except Exception:
        logger.exception("Error in login")
        return {"success": False, "message": "Login failed, please try again"}


@router.post("/register")
def register(user: UserCreate):
    try:
        if len(user.password) > 1024:
            return {"success": False, "message": "Password too long"}
        if get_one("SELECT id FROM mydata WHERE email = %s", (user.email,)):
            return {"success": False, "message": "User with this email already exists"}

        # Anyone could previously register as premium. Now only if you allow it.
        is_premium = bool(user.is_premium) if Config.ALLOW_SELF_PREMIUM else False

        result = get_one("""
            INSERT INTO mydata (name, email, password, is_premium, created_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, name, email, is_premium, created_at
        """, (user.name, user.email, hash_password(user.password), is_premium, datetime.now()))

        if result:
            return {"success": True, "message": "User registered successfully", "user": result}
        return {"success": False, "message": "Failed to register user"}
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate key" in str(e).lower():
            return {"success": False, "message": "User with this email already exists"}
        logger.exception("Error in register")
        return {"success": False, "message": "Registration failed, please try again"}


# ================= API KEY MANAGEMENT =================
@router.post("/apikey/gen")
def generate_api_key(request: APIKeyRequest, authorization: Optional[str] = Header(None)):
    check_owner(request.user_id, authorization)
    try:
        user_exists = get_one("SELECT * FROM mydata WHERE id = %s", (request.user_id,))
        if not user_exists:
            return {"success": False, "message": "User not found"}
        if not user_exists.get("is_premium"):
            return {"success": False, "message": "Premium subscription required to generate API keys"}

        count = get_one("SELECT COUNT(*) AS c FROM apikeys WHERE user_id = %s", (request.user_id,))
        if count and count["c"] >= 2:
            return {"success": False, "message": "Maximum 2 API keys allowed per user"}

        api_key = secrets.token_hex(16)
        result = get_one("""
            INSERT INTO apikeys (user_id, api_key, created_at, expiry_date)
            VALUES (%s, %s, %s, %s)
            RETURNING id, user_id, api_key, created_at, expiry_date
        """, (request.user_id, api_key, datetime.now(), datetime.now() + timedelta(days=30)))

        if result:
            return {"success": True, "message": "API Key generated successfully", "api_key": result}
        return {"success": False, "message": "Failed to create API key"}
    except Exception:
        logger.exception("Error in generate_api_key")
        return {"success": False, "message": "Database error"}


@router.get("/apikey/list")
def list_user_apikeys(user_id: int, authorization: Optional[str] = Header(None)):
    check_owner(user_id, authorization)
    try:
        results = execute_query("""
            SELECT id, user_id, api_key, created_at, expiry_date
            FROM apikeys WHERE user_id = %s ORDER BY created_at DESC
        """, (user_id,), fetch=True)
        return {"success": True, "total": len(results) if results else 0,
                "api_keys": results if results else []}
    except Exception:
        logger.exception("Error in list_user_apikeys")
        return {"success": False, "message": "Database error"}


@router.delete("/apikey/del")
def delete_apikey(api_key: str, authorization: Optional[str] = Header(None)):
    try:
        existing = get_one("SELECT id, user_id FROM apikeys WHERE api_key = %s", (api_key,))
        if not existing:
            return {"success": False, "message": "API key not found"}
        check_owner(existing["user_id"], authorization)

        result = get_one("DELETE FROM apikeys WHERE api_key = %s RETURNING id", (api_key,))
        cache.delete("k:" + api_key)
        if result:
            return {"success": True, "message": "API key deleted successfully"}
        return {"success": False, "message": "Failed to delete API key"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Error in delete_apikey")
        return {"success": False, "message": "Database error"}


# ================= VIDEOS =================
@router.get("/videos")
def get_videos(limit: Optional[int] = None, offset: int = 0):
    """All free PUBLIC videos. No API key. Optional ?limit=&offset= for paging."""
    try:
        suffix, params = _page(limit, offset)
        return cached_json(
            f"videos:free:{limit}:{offset}",
            lambda: execute_query(
                "SELECT * FROM videos WHERE is_premium = false AND visibility = 'public' "
                "ORDER BY uploaded_at DESC" + suffix, params, fetch=True) or [])
    except Exception:
        logger.exception("Error in get_videos")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")


@router.get("/premium_videos")
def get_premium_videos(limit: Optional[int] = None, offset: int = 0, api_key: str = Header(...)):
    user_data = validate_api_key(api_key, "/premium_videos")
    if not user_data:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key")
    try:
        ck = f"videos:premium:{limit}:{offset}"
        results = cache.get(ck)
        if results is None:
            suffix, params = _page(limit, offset)
            results = execute_query(
                "SELECT * FROM videos WHERE is_premium = true AND visibility = 'public' "
                "ORDER BY uploaded_at DESC" + suffix, params, fetch=True) or []
            cache.set(ck, results, Config.CACHE_TTL)
        return {
            "success": True,
            "message": "Premium videos retrieved successfully",
            "total": len(results),
            "videos": results,
            "user": {
                "id": user_data["user_id"],
                "name": user_data["name"],
                "email": user_data["email"],
                "is_premium": user_data["is_premium"],
            },
        }
    except Exception:
        logger.exception("Error in get_premium_videos")
        return {"success": False, "message": "Database error"}


@router.post("/upload_videos")
def upload_video(video: Video, api_key: str = Header(...)):
    user_data = validate_api_key(api_key, "/upload_videos", "POST")
    if not user_data:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key")

    viewkey = secrets.token_hex(6)
    try:
        result = get_one("""
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium, user_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, title, stream_link, viewkey, thumbnail, category, is_premium, uploaded_at
        """, (video.title, video.stream_link, viewkey, video.thumbnail,
              video.category, video.is_premium, user_data.get("user_id")))
        if result:
            cache.clear_prefix("videos:")
            return {"success": True, "message": "Video uploaded successfully", "viewkey": viewkey,
                    "video": result, "uploaded_by": user_data.get("name", "Unknown"),
                    "user_id": user_data.get("user_id")}
        return {"success": False, "message": "Failed to upload video"}
    except Exception as e:
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            return {"success": False, "message": "Video with this viewkey already exists"}
        logger.exception("Error in upload_video")
        return {"success": False, "message": "Database error"}


@router.get("/videos/{viewkey}")
def get_video_by_key(viewkey: str):
    try:
        result = get_one("SELECT * FROM videos WHERE viewkey = %s AND visibility <> 'private'",
                         (viewkey,))
        if result:
            return {"success": True, "video": result}
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Video not found")
    except HTTPException:
        raise
    except Exception:
        logger.exception("Error in get_video_by_key")
        return {"success": False, "message": "Database error"}


# ================= PLAYLISTS =================
_PLAYLIST_SELECT = """
    SELECT p.playlist_id, p.playlist_name, p.playlist_type, p.total_videos,
           p.playlist_thumbnail, p.created_at,
           COALESCE(
               json_agg(
                   json_build_object(
                       'video_id', v.video_id, 'viewkey', v.viewkey, 'stream_url', v.stream_url,
                       'video_title', v.video_title, 'video_thumbnail', v.video_thumbnail,
                       'video_duration', v.video_duration, 'video_quality', v.video_quality
                   ) ORDER BY v.video_id ASC
               ) FILTER (WHERE v.video_id IS NOT NULL),
               '[]'::json
           ) AS videos
    FROM playlist AS p
    LEFT JOIN videos_of_playlist AS v ON v.playlist_id = p.playlist_id
"""
_PLAYLIST_GROUP = """
    GROUP BY p.playlist_id, p.playlist_name, p.playlist_type, p.total_videos,
             p.playlist_thumbnail, p.created_at
"""


@router.get("/playlists")
def get_playlists(limit: Optional[int] = None, offset: int = 0):
    """All playlists with their videos. No API key. Optional ?limit=&offset=."""
    try:
        suffix, params = _page(limit, offset)

        def produce():
            results = execute_query(_PLAYLIST_SELECT + _PLAYLIST_GROUP +
                                    " ORDER BY p.created_at DESC" + suffix, params, fetch=True)
            return {"success": True, "total": len(results) if results else 0,
                    "playlists": results or []}

        return cached_json(f"playlists:{limit}:{offset}", produce)
    except Exception:
        logger.exception("Error while retrieving playlists")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to retrieve playlists")


@router.get("/playlists/{playlist_id}")
def get_playlist(playlist_id: int):
    if playlist_id <= 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid playlist ID")
    try:
        result = get_one(_PLAYLIST_SELECT + " WHERE p.playlist_id = %s" + _PLAYLIST_GROUP,
                         (playlist_id,))
        if not result:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Playlist not found")
        return {"success": True, "playlist": result}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Error while retrieving playlist %s", playlist_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to retrieve playlist")


@router.get("/health")
def health_check():
    from database import health_check as db_health
    healthy = db_health()
    return {"status": "healthy" if healthy else "unhealthy",
            "database": "connected" if healthy else "disconnected",
            "timestamp": datetime.now().isoformat()}


@router.get("/ads")
def get_ads():
    """2 random image ads + 1 random video ad. No API key. (Not cached: stays random.)"""
    try:
        image_ads = execute_query("""
            SELECT id, ad_name, promotion_link, ad_type, link FROM ads_table
            WHERE ad_type = 'image' ORDER BY RANDOM() LIMIT 2""", fetch=True) or []
        video_ads = execute_query("""
            SELECT id, ad_name, promotion_link, ad_type, link FROM ads_table
            WHERE ad_type = 'video' ORDER BY RANDOM() LIMIT 1""", fetch=True) or []
        return {"success": True, "total": len(image_ads) + len(video_ads),
                "image_ads": image_ads, "video_ads": video_ads}
    except Exception:
        logger.exception("Error while retrieving ads")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve ads")


# ================= CREATOR STUDIO =================
VISIBILITIES = ("public", "unlisted", "private")


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


@router.get("/studio/my_videos")
def studio_my_videos(api_key: str = Header(...)):
    u = current_user(api_key, "/studio/my_videos")
    rows = execute_query("SELECT * FROM videos WHERE user_id=%s ORDER BY uploaded_at DESC",
                         (u["user_id"],), fetch=True) or []
    return {"success": True, "total": len(rows), "videos": rows}


@router.post("/studio/videos")
def studio_create_video(v: StudioVideoIn, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/create_video")
    if v.visibility not in VISIBILITIES:
        raise HTTPException(400, "Invalid visibility")
    if not v.title.strip() or len(v.title) > 300 or len(v.stream_link) > 2048:
        raise HTTPException(400, "Invalid title or link")
    viewkey = secrets.token_hex(6)
    try:
        row = get_one("""
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium,
                                user_id, description, visibility, duration, file_size)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (v.title.strip(), v.stream_link, viewkey, v.thumbnail, v.category, v.is_premium,
             u["user_id"], v.description, v.visibility, v.duration, v.file_size))
        cache.clear_prefix("videos:")
        return {"success": True, "viewkey": viewkey, "video": row}
    except Exception:
        logger.exception("studio_create_video")
        return {"success": False, "message": "Could not save video"}


@router.put("/studio/videos/{video_id}")
def studio_edit_video(video_id: int, v: StudioVideoEdit, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/edit_video")
    fields = {k: val for k, val in v.dict().items() if val is not None}
    if not fields:
        return {"success": False, "message": "Nothing to update"}
    if "visibility" in fields and fields["visibility"] not in VISIBILITIES:
        raise HTTPException(400, "Invalid visibility")
    sets = ", ".join(f"{k}=%s" for k in fields) + ", updated_at=NOW()"  # keys come from the model
    row = get_one(f"UPDATE videos SET {sets} WHERE id=%s AND user_id=%s RETURNING *",
                  (*fields.values(), video_id, u["user_id"]))
    if not row:
        raise HTTPException(404, "Video not found")
    cache.clear_prefix("videos:")
    return {"success": True, "video": row}


@router.delete("/studio/videos/{video_id}")
def studio_delete_video(video_id: int, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/delete_video")
    row = get_one("DELETE FROM videos WHERE id=%s AND user_id=%s RETURNING id",
                  (video_id, u["user_id"]))
    if not row:
        raise HTTPException(404, "Video not found")
    cache.clear_prefix("videos:")
    return {"success": True}


@router.get("/studio/stats")
def studio_stats(api_key: str = Header(...)):
    u = current_user(api_key, "/studio/stats")
    s = get_one("""
        SELECT COUNT(*) AS videos,
               COALESCE(SUM(views),0) AS views,
               COUNT(*) FILTER (WHERE is_premium) AS premium
        FROM videos WHERE user_id=%s""", (u["user_id"],))
    return {"success": True, "stats": s}


@router.get("/studio/channel")
def studio_get_channel(api_key: str = Header(...)):
    u = current_user(api_key, "/studio/get_channel")
    return {"success": True,
            "channel": get_one("SELECT * FROM channels WHERE user_id=%s", (u["user_id"],))}


@router.put("/studio/channel")
def studio_save_channel(c: ChannelIn, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/save_channel")
    row = get_one("""
        INSERT INTO channels (user_id, channel_name, handle, avatar_url, description)
        VALUES (%s,%s,%s,%s,%s)
        ON CONFLICT (user_id) DO UPDATE SET channel_name=EXCLUDED.channel_name,
            handle=EXCLUDED.handle, avatar_url=EXCLUDED.avatar_url,
            description=EXCLUDED.description RETURNING *""",
        (u["user_id"], c.channel_name, c.handle, c.avatar_url, c.description))
    return {"success": True, "channel": row}


@router.post("/studio/view/{viewkey}")
def studio_count_view(viewkey: str, request: Request):
    """Viewer page se call karo - view count barhata hai (same IP: max 1 view / 30 min)."""
    ip = client_ip(request.headers.get("x-forwarded-for"),
                   request.client.host if request.client else None)
    dedupe = f"view:{ip}:{viewkey}"
    if cache.get(dedupe):
        return {"success": True}
    row = get_one("UPDATE videos SET views=views+1 WHERE viewkey=%s RETURNING id", (viewkey,))
    if row:
        cache.set(dedupe, 1, 1800)
        get_one("INSERT INTO video_views (video_id) VALUES (%s) RETURNING id", (row["id"],))
    return {"success": bool(row)}


# ================= ANALYTICS + PROFILE =================
@router.get("/analytics")
def analytics(api_key: str = Header(...)):
    """API usage analytics for the owner of the given key (key call itself is not counted)."""
    u = current_user(api_key)
    uid = u["user_id"]
    try:
        totals = get_one("""
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS last_30_days,
                   COUNT(*) FILTER (WHERE created_at::date = CURRENT_DATE) AS today
            FROM api_usage WHERE user_id = %s""", (uid,))
        daily = execute_query("""
            SELECT to_char(d, 'Dy DD') AS day, COUNT(a.id) AS requests
            FROM generate_series(CURRENT_DATE - 6, CURRENT_DATE, '1 day') AS d
            LEFT JOIN api_usage a ON a.user_id = %s AND a.created_at::date = d::date
            GROUP BY d ORDER BY d""", (uid,), fetch=True) or []
        endpoints = execute_query("""
            SELECT endpoint, COUNT(*) AS requests FROM api_usage
            WHERE user_id = %s GROUP BY endpoint ORDER BY requests DESC LIMIT 5""",
            (uid,), fetch=True) or []
        keys = execute_query("""
            SELECT id, left(api_key, 8) || '...' || right(api_key, 4) AS key_preview,
                   request_count, last_used_at, created_at, expiry_date
            FROM apikeys WHERE user_id = %s ORDER BY created_at DESC""", (uid,), fetch=True) or []
        return {"success": True, "totals": totals, "daily": daily, "endpoints": endpoints,
                "keys": keys}
    except Exception:
        logger.exception("analytics")
        return {"success": False, "message": "Could not load analytics"}


class ProfileUpdate(BaseModel):
    user_id: int
    current_password: str
    name: str
    email: str
    phone: Optional[str] = ""
    bio: Optional[str] = ""
    avatar_url: Optional[str] = None


class PasswordChange(BaseModel):
    user_id: int
    current_password: str
    new_password: str


def _verified_user(user_id: int, password: str):
    row = get_one("SELECT * FROM mydata WHERE id = %s", (user_id,))
    if not row:
        verify_password(password, dummy_hash())
        return None
    ok, _ = verify_password(password, row["password"])
    return row if ok else None


@router.put("/profile/update")
def update_profile(p: ProfileUpdate, authorization: Optional[str] = Header(None)):
    """Update name / email / phone / bio / avatar. Needs current password."""
    check_owner(p.user_id, authorization)
    try:
        if not _verified_user(p.user_id, p.current_password):
            return {"success": False, "message": "Current password is incorrect"}
        if not p.name.strip() or "@" not in p.email:
            return {"success": False, "message": "Enter a valid name and email"}
        if get_one("SELECT id FROM mydata WHERE email = %s AND id <> %s", (p.email, p.user_id)):
            return {"success": False, "message": "This email is already used by another account"}
        row = get_one("""
            UPDATE mydata SET name=%s, email=%s, phone=%s, bio=%s,
                   avatar_url=COALESCE(%s, avatar_url), updated_at=NOW()
            WHERE id=%s
            RETURNING id, name, email, is_premium, phone, bio, avatar_url, created_at""",
            (p.name.strip(), p.email.strip(), p.phone, p.bio, p.avatar_url, p.user_id))
        return {"success": True, "message": "Profile updated", "user": row}
    except Exception:
        logger.exception("update_profile")
        return {"success": False, "message": "Could not update profile"}


@router.put("/profile/password")
def change_password(p: PasswordChange, authorization: Optional[str] = Header(None)):
    check_owner(p.user_id, authorization)
    try:
        if not _verified_user(p.user_id, p.current_password):
            return {"success": False, "message": "Current password is incorrect"}
        if len(p.new_password) < 8 or len(p.new_password) > 1024:
            return {"success": False, "message": "New password must be at least 8 characters"}
        get_one("UPDATE mydata SET password=%s, updated_at=NOW() WHERE id=%s RETURNING id",
                (hash_password(p.new_password), p.user_id))
        return {"success": True, "message": "Password changed"}
    except Exception:
        logger.exception("change_password")
        return {"success": False, "message": "Could not change password"}
