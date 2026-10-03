import secrets
import hmac
import base64
import json
import hashlib
import logging
import os
import re
import time
from collections import defaultdict, deque
from threading import Lock
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import (APIRouter, HTTPException, status, Header, Request, Depends,
                     WebSocket, WebSocketDisconnect)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from database import execute_query, get_one
from models import (
    User, UserCreate, UserLogin, APIKeyRequest, Video,
    TagOut, TagsForVideoIn,
    PlaylistCreateIn, PlaylistUpdateIn, PlaylistAddVideoIn, PlaylistReorderIn,
    PaymentSubmitIn, PaymentReviewIn,
    SupportThreadCreateIn, SupportMessageIn, SupportStatusIn,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# =====================================================================
#  CONFIG
# =====================================================================
AUTH_SECRET = os.getenv("AUTH_SECRET") or secrets.token_hex(32)
if not os.getenv("AUTH_SECRET"):
    logger.warning("AUTH_SECRET is not set. Tokens will be invalid after every restart. Set it in Render > Environment.")

ALLOW_LEGACY_USER_ID = os.getenv("ALLOW_LEGACY_USER_ID", "1") == "1"

ADMIN_USER_IDS = {int(x) for x in os.getenv("ADMIN_USER_IDS", "").split(",") if x.strip().isdigit()}

CLD2_CLOUD = os.getenv("CLOUDINARY2_CLOUD_NAME", "")
CLD2_KEY = os.getenv("CLOUDINARY2_API_KEY", "")
CLD2_SECRET = os.getenv("CLOUDINARY2_API_SECRET", "")

SHOW_LOCKED_PREMIUM = False


# =====================================================================
#  RATE LIMITING (in-memory, thread-safe)
# =====================================================================
_rate_buckets: dict = defaultdict(deque)
_rate_lock = Lock()


def rate_limit(key: str, max_calls: int, window_sec: int) -> bool:
    """True = allowed. False = blocked. Per-worker in-memory."""
    now = time.time()
    cutoff = now - window_sec
    with _rate_lock:
        bucket = _rate_buckets[key]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= max_calls:
            return False
        bucket.append(now)
        if len(_rate_buckets) > 10000:
            for k in list(_rate_buckets.keys())[:1000]:
                _rate_buckets.pop(k, None)
    return True


def _ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


# =====================================================================
#  AUTH HELPERS
# =====================================================================
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user_id: int, days: int = 30) -> str:
    payload = _b64(json.dumps({"uid": int(user_id), "exp": int(time.time()) + days * 86400},
                              separators=(",", ":")).encode())
    sig = _b64(hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def read_token(token: Optional[str]) -> Optional[int]:
    try:
        payload, sig = (token or "").split(".")
        good = _b64(hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(_unb64(payload))
        if data["exp"] < time.time():
            return None
        return int(data["uid"])
    except Exception:
        return None


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def validate_api_key(api_key: str, endpoint: str = None, method: str = "GET"):
    try:
        query = """
            SELECT a.*, a.id as key_id, u.id as user_id, u.name, u.email, u.is_premium
            FROM apikeys a
            JOIN mydata u ON a.user_id = u.id
            WHERE a.api_key = %s 
            AND a.expiry_date > NOW()
        """
        result = get_one(query, (api_key,))
        if result and endpoint:
            track_usage(result, endpoint, method)
        return result
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        return None


def track_usage(key_row, endpoint: str, method: str = "GET"):
    try:
        get_one("INSERT INTO api_usage (api_key_id, user_id, endpoint, method) VALUES (%s,%s,%s,%s) RETURNING id",
                (key_row["key_id"], key_row["user_id"], endpoint, method))
        get_one("UPDATE apikeys SET request_count = request_count + 1, last_used_at = NOW() WHERE id=%s RETURNING id",
                (key_row["key_id"],))
    except Exception as e:
        logger.error(f"Usage tracking error: {e}")


def _clean_visitor(v: Optional[str]) -> Optional[str]:
    v = (v or "").strip()
    return v if re.fullmatch(r"[A-Za-z0-9_-]{8,64}", v) else None


def resolve_actor(authorization=None, api_key=None, x_user_id=None, x_visitor_id=None) -> dict:
    actor = {"user_id": None, "visitor_id": _clean_visitor(x_visitor_id),
             "verified": False, "is_premium": False, "name": "", "via": "anon"}
    uid = None
    if authorization and authorization.lower().startswith("bearer "):
        uid = read_token(authorization[7:].strip())
        if uid:
            actor["verified"], actor["via"] = True, "token"
    if not uid and api_key:
        k = validate_api_key(api_key)
        if k:
            uid = k["user_id"]
            actor["verified"], actor["via"] = True, "apikey"
    if not uid and ALLOW_LEGACY_USER_ID and x_user_id and str(x_user_id).isdigit():
        uid = int(x_user_id)
        actor["via"] = "legacy"
    if uid:
        u = get_one("SELECT id, name, is_premium FROM mydata WHERE id=%s", (uid,))
        if u:
            actor["user_id"] = u["id"]
            actor["name"] = u["name"] or ""
            actor["is_premium"] = bool(u["is_premium"]) and actor["verified"]
        else:
            actor["verified"], actor["via"] = False, "anon"
    return actor


async def get_actor(authorization: Optional[str] = Header(None),
                    api_key: Optional[str] = Header(None),
                    x_user_id: Optional[str] = Header(None),
                    x_visitor_id: Optional[str] = Header(None)) -> dict:
    return resolve_actor(authorization, api_key, x_user_id, x_visitor_id)


def need_login(actor: dict):
    if not actor["user_id"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Please sign in")


def need_verified(actor: dict):
    if not (actor["user_id"] and actor["verified"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Please sign in again")


def _is_owner(actor: dict, owner_id) -> bool:
    return bool(actor["user_id"] and actor["verified"] and owner_id and actor["user_id"] == owner_id)


def _can_view_video(v: dict, actor: dict) -> bool:
    owner = _is_owner(actor, v.get("user_id"))
    if v.get("visibility") == "private" and not owner:
        return False
    if v.get("is_premium") and not (actor["is_premium"] or owner):
        return False
    return True


def _check_url(u: Optional[str], what: str = "link"):
    if u and not re.match(r"^https?://\S+$", u.strip(), re.I):
        raise HTTPException(400, f"Invalid {what}")


# Login brute-force guard (in-memory)
_login_fails = {}


def _login_blocked(key: str) -> bool:
    now = time.time()
    fails = [t for t in _login_fails.get(key, []) if now - t < 600]
    _login_fails[key] = fails
    return len(fails) >= 5


def _login_fail(key: str):
    _login_fails.setdefault(key, []).append(time.time())
    if len(_login_fails) > 5000:
        _login_fails.clear()


# =====================================================================
#  HOME
# =====================================================================
def get_home_html():
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(current_dir, "home.html"), "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading home.html: {e}")
        return "<h1>Error loading page</h1>"


@router.get("/", response_class=HTMLResponse)
async def home():
    return get_home_html()


# =====================================================================
#  AUTHENTICATION
# =====================================================================
@router.post("/login")
async def login(user: UserLogin, request: Request):
    try:
        ip = _ip(request)
        if not rate_limit(f"login:{ip}", 10, 60):
            return {"success": False, "message": "Too many attempts. Try again in a minute."}

        throttle_key = f"{ip}|{(user.email or '').lower()}"
        if _login_blocked(throttle_key):
            return {"success": False, "message": "Too many attempts. Please try again in a few minutes."}

        db_user = get_one("SELECT * FROM mydata WHERE email = %s", (user.email,))
        if not db_user or db_user['password'] != hash_password(user.password):
            _login_fail(throttle_key)
            return {"success": False, "message": "Invalid email or password"}

        _login_fails.pop(throttle_key, None)
        db_user.pop('password', None)
        return {
            "success": True,
            "message": "Login successful",
            "token": make_token(db_user['id']),
            "user": {
                "id": db_user['id'],
                "name": db_user['name'],
                "email": db_user['email'],
                "is_premium": db_user['is_premium'],
                "phone": db_user.get('phone'),
                "bio": db_user.get('bio'),
                "avatar_url": db_user.get('avatar_url'),
                "created_at": db_user['created_at']
            }
        }
    except Exception as e:
        logger.error(f"Error in login: {e}")
        return {"success": False, "message": "Login error. Please try again."}


@router.post("/register")
async def register(user: UserCreate, request: Request):
    try:
        ip = _ip(request)
        if not rate_limit(f"register:{ip}", 5, 3600):
            return {"success": False, "message": "Too many registrations. Try again later."}

        if get_one("SELECT id FROM mydata WHERE email = %s", (user.email,)):
            return {"success": False, "message": "User with this email already exists"}

        result = get_one("""
            INSERT INTO mydata (name, email, password, is_premium, created_at) 
            VALUES (%s, %s, %s, %s, %s) 
            RETURNING id, name, email, is_premium, created_at
        """, (user.name, user.email, hash_password(user.password), False, datetime.now()))

        if result:
            return {"success": True, "message": "User registered successfully",
                    "token": make_token(result["id"]), "user": result}
        return {"success": False, "message": "Failed to register user"}
    except Exception as e:
        logger.error(f"Error in register: {e}")
        return {"success": False, "message": "Registration error. Please try again."}


@router.get("/me")
async def me(actor: dict = Depends(get_actor)):
    need_verified(actor)
    u = get_one("SELECT * FROM mydata WHERE id=%s", (actor["user_id"],))
    u.pop("password", None)
    return {"success": True, "user": u}


class ProfileIn(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None


@router.put("/me/profile")
async def update_profile(p: ProfileIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    fields = {k: v for k, v in p.dict().items() if v is not None}
    if "name" in fields:
        fields["name"] = fields["name"].strip()
        if len(fields["name"]) < 2:
            return {"success": False, "message": "Name must be at least 2 characters"}
    if "avatar_url" in fields and fields["avatar_url"] and not fields["avatar_url"].startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Profile picture must be uploaded through the app"}
    if not fields:
        return {"success": False, "message": "Nothing to update"}
    sets = ", ".join(f"{k}=%s" for k in fields)
    row = get_one(f"UPDATE mydata SET {sets} WHERE id=%s RETURNING id, name, email, is_premium, phone, bio, avatar_url",
                  (*fields.values(), actor["user_id"]))
    return {"success": True, "user": row}


class ProfileUpdateIn(BaseModel):
    user_id: int
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    current_password: str


class PasswordChangeIn(BaseModel):
    user_id: int
    current_password: str
    new_password: str


def _verify_password(user_id: int, password: str, request: Request):
    ip = _ip(request)
    key = f"pw|{ip}|{user_id}"
    if _login_blocked(key):
        raise HTTPException(429, "Too many attempts. Please try again in a few minutes.")
    u = get_one("SELECT * FROM mydata WHERE id=%s", (user_id,))
    if not u or u["password"] != hash_password(password or ""):
        _login_fail(key)
        return None
    _login_fails.pop(key, None)
    return u


_PROFILE_COLS = "id, name, email, is_premium, phone, bio, avatar_url, created_at"


@router.put("/profile/update")
async def profile_update(p: ProfileUpdateIn, request: Request, actor: dict = Depends(get_actor)):
    _authorize_user_id(actor, p.user_id)
    if not _verify_password(p.user_id, p.current_password, request):
        return {"success": False, "message": "Current password is incorrect"}

    fields = {}
    if p.name is not None:
        name = p.name.strip()
        if len(name) < 2:
            return {"success": False, "message": "Name must be at least 2 characters"}
        fields["name"] = name[:100]

    if p.email is not None:
        email = p.email.strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return {"success": False, "message": "Enter a valid email address"}
        if get_one("SELECT id FROM mydata WHERE LOWER(email)=LOWER(%s) AND id<>%s", (email, p.user_id)):
            return {"success": False, "message": "This email is already used by another account"}
        fields["email"] = email

    if p.phone is not None:
        fields["phone"] = p.phone.strip()[:30]
    if p.bio is not None:
        fields["bio"] = p.bio.strip()[:300]
    if p.avatar_url is not None:
        av = p.avatar_url.strip()
        if av and not av.startswith("https://res.cloudinary.com/"):
            return {"success": False, "message": "Profile picture must be uploaded through the app"}
        fields["avatar_url"] = av

    if not fields:
        return {"success": False, "message": "Nothing to update"}
    try:
        sets = ", ".join(f"{k}=%s" for k in fields)
        row = get_one(f"UPDATE mydata SET {sets} WHERE id=%s RETURNING {_PROFILE_COLS}",
                      (*fields.values(), p.user_id))
    except Exception:
        logger.exception("profile_update")
        return {"success": False, "message": "Could not update profile"}
    return {"success": True, "message": "Profile updated", "user": row}


@router.put("/profile/password")
async def profile_password(p: PasswordChangeIn, request: Request, actor: dict = Depends(get_actor)):
    _authorize_user_id(actor, p.user_id)
    if len(p.new_password or "") < 8:
        return {"success": False, "message": "New password must be at least 8 characters"}
    if not _verify_password(p.user_id, p.current_password, request):
        return {"success": False, "message": "Current password is incorrect"}
    if p.new_password == p.current_password:
        return {"success": False, "message": "New password must be different from the current one"}
    get_one("UPDATE mydata SET password=%s WHERE id=%s RETURNING id",
            (hash_password(p.new_password), p.user_id))
    return {"success": True, "message": "Password changed"}


# =====================================================================
#  CLOUDINARY (2nd account) — signed upload
# =====================================================================
UPLOAD_PURPOSES = {
    "avatar":   {"folder": "profiles", "type": "image", "formats": "jpg,jpeg,png,webp", "admin": False},
    "channel":  {"folder": "channels", "type": "image", "formats": "jpg,jpeg,png,webp", "admin": False},
    "banner":   {"folder": "banners",  "type": "image", "formats": "jpg,jpeg,png,webp", "admin": False},
    "ad_image": {"folder": "ads",      "type": "image", "formats": "jpg,jpeg,png,webp,gif", "admin": True},
    "ad_video": {"folder": "ads",      "type": "video", "formats": "mp4,webm,mov", "admin": True},
    "ad_creative_image": {"folder": "ads/creatives", "type": "image", "formats": "jpg,jpeg,png,webp,gif", "admin": False},
    "ad_creative_video": {"folder": "ads/creatives", "type": "video", "formats": "mp4,webm,mov", "admin": False},
}


class SignIn(BaseModel):
    purpose: str


@router.post("/uploads/sign")
async def sign_upload(body: SignIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    cfg = UPLOAD_PURPOSES.get(body.purpose)
    if not cfg:
        raise HTTPException(400, "Unknown upload purpose")
    if cfg["admin"] and actor["user_id"] not in ADMIN_USER_IDS:
        raise HTTPException(403, "Only admins can upload ads")
    if not (CLD2_CLOUD and CLD2_KEY and CLD2_SECRET):
        return {"success": False, "message": "Cloudinary is not configured on the server"}

    params = {"allowed_formats": cfg["formats"], "folder": cfg["folder"], "timestamp": int(time.time())}
    to_sign = "&".join(f"{k}={params[k]}" for k in sorted(params)) + CLD2_SECRET
    signature = hashlib.sha1(to_sign.encode()).hexdigest()
    return {
        "success": True,
        "cloud_name": CLD2_CLOUD,
        "api_key": CLD2_KEY,
        "resource_type": cfg["type"],
        "upload_url": f"https://api.cloudinary.com/v1_1/{CLD2_CLOUD}/{cfg['type']}/upload",
        "signature": signature,
        **params,
    }


# =====================================================================
#  ADMIN: LEGACY ADS (ads_table)
# =====================================================================
class AdIn(BaseModel):
    ad_name: str
    ad_type: str
    link: str
    promotion_link: Optional[str] = ""


def need_admin(actor: dict):
    need_verified(actor)
    if actor["user_id"] not in ADMIN_USER_IDS:
        raise HTTPException(403, "Admins only")


@router.get("/admin/ads")
async def admin_list_ads(actor: dict = Depends(get_actor)):
    need_admin(actor)
    rows = execute_query("SELECT * FROM ads_table ORDER BY id DESC", fetch=True) or []
    return {"success": True, "ads": rows}


@router.post("/admin/ads")
async def admin_create_ad(ad: AdIn, actor: dict = Depends(get_actor)):
    need_admin(actor)
    if ad.ad_type not in ("image", "video"):
        raise HTTPException(400, "ad_type must be image or video")
    _check_url(ad.link, "ad link")
    _check_url(ad.promotion_link, "promotion link")
    row = get_one("""INSERT INTO ads_table (ad_name, promotion_link, ad_type, link)
                     VALUES (%s,%s,%s,%s) RETURNING *""",
                  (ad.ad_name.strip(), ad.promotion_link or "", ad.ad_type, ad.link.strip()))
    return {"success": True, "ad": row}


@router.delete("/admin/ads/{ad_id}")
async def admin_delete_ad(ad_id: int, actor: dict = Depends(get_actor)):
    need_admin(actor)
    row = get_one("DELETE FROM ads_table WHERE id=%s RETURNING id", (ad_id,))
    if not row:
        raise HTTPException(404, "Ad not found")
    return {"success": True}


# =====================================================================
#  API KEYS
# =====================================================================
def _authorize_user_id(actor: dict, user_id: int):
    if actor["user_id"] and actor["verified"]:
        if actor["user_id"] != user_id:
            raise HTTPException(403, "Not allowed")
        return
    if ALLOW_LEGACY_USER_ID:
        return
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Please sign in again")


@router.post("/apikey/gen")
async def generate_api_key(request: APIKeyRequest, actor: dict = Depends(get_actor)):
    try:
        _authorize_user_id(actor, request.user_id)
        if not rate_limit(f"apikeygen:{request.user_id}", 5, 3600):
            return {"success": False, "message": "Too many API key requests. Try again later."}
        user_exists = get_one("SELECT * FROM mydata WHERE id = %s", (request.user_id,))
        if not user_exists:
            return {"success": False, "message": "User not found"}
        if not user_exists.get('is_premium'):
            return {"success": False, "message": "Premium subscription required to generate API keys"}
        count = get_one("SELECT COUNT(*) AS c FROM apikeys WHERE user_id = %s", (request.user_id,))
        if count and count['c'] >= 2:
            return {"success": False, "message": "Maximum 2 API keys allowed per user"}

        api_key = secrets.token_hex(16)
        expiry_date = datetime.now() + timedelta(days=30)
        result = get_one("""
            INSERT INTO apikeys (user_id, api_key, created_at, expiry_date) 
            VALUES (%s, %s, %s, %s) 
            RETURNING id, user_id, api_key, created_at, expiry_date
        """, (request.user_id, api_key, datetime.now(), expiry_date))
        if result:
            return {"success": True, "message": "API Key generated successfully", "api_key": result}
        return {"success": False, "message": "Failed to create API key"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in generate_api_key: {e}")
        return {"success": False, "message": "Database error"}


@router.get("/apikey/list")
async def list_user_apikeys(user_id: int, actor: dict = Depends(get_actor)):
    try:
        _authorize_user_id(actor, user_id)
        results = execute_query("""
            SELECT id, user_id, api_key, created_at, expiry_date,
                   COALESCE(request_count, 0) AS request_count, last_used_at
            FROM apikeys WHERE user_id = %s ORDER BY created_at DESC
        """, (user_id,), fetch=True)
        return {"success": True, "total": len(results) if results else 0, "api_keys": results or []}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in list_user_apikeys: {e}")
        return {"success": False, "message": "Database error"}


@router.delete("/apikey/del")
async def delete_apikey(api_key: str, actor: dict = Depends(get_actor)):
    try:
        existing = get_one("SELECT id, user_id FROM apikeys WHERE api_key = %s", (api_key,))
        if not existing:
            return {"success": False, "message": "API key not found"}
        _authorize_user_id(actor, existing["user_id"])
        result = get_one("DELETE FROM apikeys WHERE api_key = %s RETURNING id", (api_key,))
        if result:
            return {"success": True, "message": "API key deleted successfully"}
        return {"success": False, "message": "Failed to delete API key"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in delete_apikey: {e}")
        return {"success": False, "message": "Database error"}


@router.get("/analytics")
async def api_analytics(api_key: str = Header(...)):
    k = validate_api_key(api_key)
    if not k:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    uid = k["user_id"]
    try:
        totals = get_one("""
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS last_30_days,
                   COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)               AS today
            FROM api_usage WHERE user_id = %s""", (uid,)) or {}

        daily = execute_query("""
            SELECT to_char(d, 'Mon DD') AS day, COALESCE(x.n, 0) AS requests
            FROM generate_series(CURRENT_DATE - 6, CURRENT_DATE, interval '1 day') d
            LEFT JOIN (SELECT created_at::date AS dd, COUNT(*) AS n
                       FROM api_usage
                       WHERE user_id = %s AND created_at >= CURRENT_DATE - 6
                       GROUP BY 1) x ON x.dd = d::date
            ORDER BY d""", (uid,), fetch=True) or []

        endpoints = execute_query("""
            SELECT endpoint, COUNT(*) AS requests
            FROM api_usage WHERE user_id = %s
            GROUP BY endpoint ORDER BY requests DESC LIMIT 8""", (uid,), fetch=True) or []

        keys = execute_query("""
            SELECT id, api_key, COALESCE(request_count, 0) AS request_count, last_used_at
            FROM apikeys WHERE user_id = %s ORDER BY created_at DESC""", (uid,), fetch=True) or []
        for r in keys:
            full = r.pop("api_key", "") or ""
            r["key_preview"] = f"{full[:8]}••••{full[-4:]}" if len(full) > 12 else full

        return {"success": True,
                "totals": {"total": totals.get("total", 0),
                           "last_30_days": totals.get("last_30_days", 0),
                           "today": totals.get("today", 0)},
                "daily": daily, "endpoints": endpoints, "keys": keys}
    except Exception:
        logger.exception("api_analytics")
        return {"success": False, "message": "Could not load analytics"}


# =====================================================================
#  VIDEOS
# =====================================================================
@router.get("/videos")
async def get_videos():
    """Free PUBLIC videos. No login needed."""
    try:
        results = execute_query("""
            SELECT v.*,
                   COALESCE(c.channel_name, u.name)     AS channel_name,
                   c.handle                             AS channel_handle,
                   COALESCE(c.avatar_url, u.avatar_url) AS channel_avatar
            FROM videos v
            LEFT JOIN channels c ON c.user_id = v.user_id
            LEFT JOIN mydata u   ON u.id = v.user_id
            WHERE v.is_premium = false AND v.visibility = 'public'
            ORDER BY v.uploaded_at DESC
        """, fetch=True)
        return results if results else []
    except Exception as e:
        logger.error(f"Error in get_videos: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@router.get("/premium_videos")
async def get_premium_videos(api_key: str = Header(...)):
    user_data = validate_api_key(api_key, "/premium_videos")
    if not user_data:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    if not user_data.get("is_premium"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Premium subscription required")
    try:
        results = execute_query("""
            SELECT v.*,
                   COALESCE(c.channel_name, u.name)     AS channel_name,
                   c.handle                             AS channel_handle,
                   COALESCE(c.avatar_url, u.avatar_url) AS channel_avatar
            FROM videos v
            LEFT JOIN channels c ON c.user_id = v.user_id
            LEFT JOIN mydata u   ON u.id = v.user_id
            WHERE v.is_premium = true AND v.visibility = 'public'
            ORDER BY v.uploaded_at DESC
        """, fetch=True)
        return {
            "success": True,
            "message": "Premium videos retrieved successfully",
            "total": len(results) if results else 0,
            "videos": results or [],
            "user": {"id": user_data['user_id'], "name": user_data['name'],
                     "email": user_data['email'], "is_premium": user_data['is_premium']}
        }
    except Exception as e:
        logger.error(f"Error in get_premium_videos: {e}")
        return {"success": False, "message": "Database error"}


@router.post("/upload_videos")
async def upload_video(video: Video, api_key: str = Header(...)):
    user_data = validate_api_key(api_key, "/upload_videos", "POST")
    if not user_data:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    viewkey = secrets.token_hex(6)
    try:
        result = get_one("""
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium, user_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s) 
            RETURNING id, title, stream_link, viewkey, thumbnail, category, is_premium, uploaded_at
        """, (video.title, video.stream_link, viewkey, video.thumbnail,
              video.category, video.is_premium, user_data.get('user_id')))
        if result:
            return {"success": True, "message": "Video uploaded successfully", "viewkey": viewkey,
                    "video": result, "uploaded_by": user_data.get('name', 'Unknown'),
                    "user_id": user_data.get('user_id')}
        return {"success": False, "message": "Failed to upload video"}
    except Exception as e:
        logger.error(f"Error in upload_video: {e}")
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            return {"success": False, "message": "Video with this viewkey already exists"}
        return {"success": False, "message": "Database error"}


@router.get("/videos/{viewkey}")
async def get_video_by_key(viewkey: str, actor: dict = Depends(get_actor)):
    try:
        row = get_one("""
            SELECT v.*,
                   COALESCE(c.channel_name, u.name) AS creator_name,
                   c.handle AS creator_handle,
                   COALESCE(c.avatar_url, u.avatar_url) AS creator_avatar,
                   (SELECT COUNT(*) FROM video_likes vl WHERE vl.video_id = v.id) AS like_count,
                   EXISTS(SELECT 1 FROM video_likes vl2 WHERE vl2.video_id = v.id AND vl2.user_id = %s::int) AS liked,
                   (SELECT COUNT(*) FROM subscriptions s WHERE s.channel_user_id = v.user_id) AS subscriber_count,
                   EXISTS(SELECT 1 FROM subscriptions s2
                          WHERE s2.channel_user_id = v.user_id AND s2.subscriber_id = %s::int) AS is_subscribed
            FROM videos v
            LEFT JOIN mydata u ON u.id = v.user_id
            LEFT JOIN channels c ON c.user_id = v.user_id
            WHERE v.viewkey = %s
        """, (actor["user_id"], actor["user_id"], viewkey))

        if not row or (row["visibility"] == "private" and not _is_owner(actor, row.get("user_id"))):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Video not found")

        if not _can_view_video(row, actor):
            row["stream_link"] = ""
            row.pop("stream_url", None)
            row["locked"] = True
        else:
            row["locked"] = False

        row["is_own_channel"] = bool(actor["user_id"] and actor["user_id"] == row.get("user_id"))

        return {"success": True, "video": row}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_video_by_key: {e}")
        return {"success": False, "message": "Database error"}


@router.post("/videos/{viewkey}/like")
async def toggle_video_like(viewkey: str, actor: dict = Depends(get_actor)):
    need_login(actor)
    if not rate_limit(f"like:{actor['user_id']}", 30, 60):
        raise HTTPException(429, "Too many likes. Slow down.")
    v = get_one("SELECT id, user_id, is_premium, visibility FROM videos WHERE viewkey=%s", (viewkey,))
    if not v or not _can_view_video(v, actor):
        raise HTTPException(404, "Video not found")
    uid = actor["user_id"]
    ins = get_one("INSERT INTO video_likes (video_id, user_id) VALUES (%s,%s) ON CONFLICT DO NOTHING RETURNING video_id",
                  (v["id"], uid))
    liked = bool(ins)
    if liked:
        await notify(v["user_id"], "video_like", uid, video_id=v["id"])
    else:
        get_one("DELETE FROM video_likes WHERE video_id=%s AND user_id=%s RETURNING video_id", (v["id"], uid))
        _drop_notification(v["user_id"], "video_like", uid, video_id=v["id"])
    cnt = get_one("SELECT COUNT(*) AS n FROM video_likes WHERE video_id=%s", (v["id"],))
    return {"success": True, "liked": liked, "likes": cnt["n"] if cnt else 0}


# =====================================================================
#  PLAYLISTS (LEGACY — videos_of_playlist based)
# =====================================================================
PLAYLIST_SELECT = """
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
PLAYLIST_GROUP = """
    GROUP BY p.playlist_id, p.playlist_name, p.playlist_type, p.total_videos,
             p.playlist_thumbnail, p.created_at
"""


def _lock_playlist(p: dict, actor: dict) -> dict:
    if p.get("playlist_type") == "premium" and not actor["is_premium"]:
        p["videos"] = [{**v, "stream_url": ""} for v in (p.get("videos") or [])]
        p["locked"] = True
    else:
        p["locked"] = False
    return p


@router.get("/playlists")
async def get_playlists(actor: dict = Depends(get_actor)):
    try:
        results = execute_query(PLAYLIST_SELECT + PLAYLIST_GROUP + " ORDER BY p.created_at DESC", fetch=True) or []
        results = [_lock_playlist(p, actor) for p in results]
        return {"success": True, "total": len(results), "playlists": results}
    except Exception:
        logger.exception("Error while retrieving playlists")
        raise HTTPException(500, "Failed to retrieve playlists")


# IMPORTANT: specific routes PEHLE, phir dynamic route
# Ye line FastAPI ke route-matching order ko preserve karti hai


@router.get("/playlists/{playlist_id}")
async def get_playlist(playlist_id: str, actor: dict = Depends(get_actor)):
    # Safety: non-numeric IDs (jaise "my") ko gracefully handle karo
    if not playlist_id.isdigit():
        raise HTTPException(404, "Playlist not found")
    playlist_id = int(playlist_id)
    if playlist_id <= 0:
        raise HTTPException(400, "Invalid playlist ID")
    try:
        result = get_one(PLAYLIST_SELECT + " WHERE p.playlist_id = %s " + PLAYLIST_GROUP, (playlist_id,))
        if not result:
            raise HTTPException(404, "Playlist not found")
        return {"success": True, "playlist": _lock_playlist(result, actor)}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Error while retrieving playlist %s", playlist_id)
        raise HTTPException(500, "Failed to retrieve playlist")


@router.get("/health")
async def health_check():
    from database import health_check
    is_healthy = health_check()
    return {"status": "healthy" if is_healthy else "unhealthy",
            "database": "connected" if is_healthy else "disconnected",
            "timestamp": datetime.now().isoformat()}


@router.get("/ads")
async def get_ads():
    """Legacy random ads: 2 image + 1 video."""
    try:
        image_ads = execute_query("""
            SELECT id, ad_name, promotion_link, ad_type, link
            FROM ads_table WHERE ad_type = 'image' ORDER BY RANDOM() LIMIT 2
        """, fetch=True) or []
        video_ads = execute_query("""
            SELECT id, ad_name, promotion_link, ad_type, link
            FROM ads_table WHERE ad_type = 'video' ORDER BY RANDOM() LIMIT 1
        """, fetch=True) or []
        return {"success": True, "total": len(image_ads) + len(video_ads),
                "image_ads": image_ads, "video_ads": video_ads}
    except Exception:
        logger.exception("Error while retrieving ads")
        raise HTTPException(500, "Failed to retrieve ads")
# =====================================================================
#  CREATOR STUDIO
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
    banner_url: Optional[str] = None
    description: Optional[str] = ""


def current_user(api_key: str, endpoint: str = None, method: str = "GET"):
    u = validate_api_key(api_key, endpoint, method)
    if not u:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    return u


@router.get("/studio/my_videos")
async def studio_my_videos(api_key: str = Header(...)):
    u = current_user(api_key, "/studio/my_videos")
    rows = execute_query("SELECT * FROM videos WHERE user_id=%s ORDER BY uploaded_at DESC",
                         (u["user_id"],), fetch=True) or []
    return {"success": True, "total": len(rows), "videos": rows}


@router.post("/studio/videos")
async def studio_create_video(v: StudioVideoIn, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/create_video")
    if not get_one("SELECT id FROM channels WHERE user_id=%s", (u["user_id"],)):
        return {"success": False, "message": "Create your channel before uploading videos"}
    if v.visibility not in ("public", "unlisted", "private"):
        raise HTTPException(400, "Invalid visibility")
    _check_url(v.stream_link, "video link")
    _check_url(v.thumbnail, "thumbnail link")
    viewkey = secrets.token_hex(6)
    try:
        row = get_one("""
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium,
                                user_id, description, visibility, duration, file_size)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (v.title.strip(), v.stream_link.strip(), viewkey, v.thumbnail, v.category, v.is_premium,
             u["user_id"], v.description, v.visibility, v.duration, v.file_size))
    except Exception:
        logger.exception("studio_create_video")
        return {"success": False, "message": "Could not save video"}
    if v.visibility == "public":
        await _notify_new_upload(u["user_id"], row["id"], v.is_premium)
    return {"success": True, "viewkey": viewkey, "video": row}


@router.put("/studio/videos/{video_id}")
async def studio_edit_video(video_id: int, v: StudioVideoEdit, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/edit_video")
    if v.visibility is not None and v.visibility not in ("public", "unlisted", "private"):
        raise HTTPException(400, "Invalid visibility")
    _check_url(v.thumbnail, "thumbnail link")
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
    u = current_user(api_key, "/studio/delete_video")
    row = get_one("DELETE FROM videos WHERE id=%s AND user_id=%s RETURNING id", (video_id, u["user_id"]))
    if not row:
        raise HTTPException(404, "Video not found")
    return {"success": True}


@router.get("/studio/stats")
async def studio_stats(api_key: str = Header(...)):
    u = current_user(api_key, "/studio/stats")
    uid = u["user_id"]
    s = get_one("""
        SELECT COUNT(*) AS videos,
               COALESCE(SUM(views),0) AS views,
               COUNT(*) FILTER (WHERE is_premium) AS premium,
               (SELECT COUNT(*) FROM subscriptions WHERE channel_user_id=%s) AS subscribers,
               (SELECT COUNT(*) FROM video_likes vl JOIN videos x ON x.id=vl.video_id WHERE x.user_id=%s) AS likes,
               (SELECT COUNT(*) FROM comments cm JOIN videos y ON y.id=cm.video_id WHERE y.user_id=%s) AS comments
        FROM videos WHERE user_id=%s""", (uid, uid, uid, uid))
    return {"success": True, "stats": s}


@router.get("/studio/channel")
async def studio_get_channel(api_key: str = Header(...)):
    u = current_user(api_key, "/studio/get_channel")
    return {"success": True, "channel": get_one("SELECT * FROM channels WHERE user_id=%s", (u["user_id"],))}


@router.put("/studio/channel")
async def studio_save_channel(c: ChannelIn, api_key: str = Header(...)):
    u = current_user(api_key, "/studio/save_channel")
    name = (c.channel_name or "").strip()
    handle = (c.handle or "").strip().lower()
    if len(name) < 2:
        return {"success": False, "message": "Channel name must be at least 2 characters"}
    if not re.fullmatch(r"[a-z0-9_]{3,30}", handle):
        return {"success": False, "message": "Handle must be 3-30 characters: lowercase letters, numbers or underscore"}
    if get_one("SELECT id FROM channels WHERE handle=%s AND user_id<>%s", (handle, u["user_id"])):
        return {"success": False, "message": "This handle is already taken"}
    row = get_one("""
        INSERT INTO channels (user_id, channel_name, handle, avatar_url, banner_url, description)
        VALUES (%s,%s,%s,%s,%s,%s)
        ON CONFLICT (user_id) DO UPDATE SET channel_name=EXCLUDED.channel_name,
            handle=EXCLUDED.handle, avatar_url=EXCLUDED.avatar_url,
            banner_url=COALESCE(EXCLUDED.banner_url, channels.banner_url),
            description=EXCLUDED.description RETURNING *""",
        (u["user_id"], name, handle, c.avatar_url, c.banner_url, c.description))
    return {"success": True, "channel": row}


_recent_views = {}


@router.post("/studio/view/{viewkey}")
async def studio_count_view(viewkey: str, request: Request):
    """Viewer page 5 second playback ke baad call karta hai. Same IP + video 30 min me ek dafa count hota hai."""
    ip = _ip(request)
    now = time.time()
    k = (ip, viewkey)
    if now - _recent_views.get(k, 0) < 1800:
        return {"success": True, "counted": False}
    row = get_one("UPDATE videos SET views=views+1 WHERE viewkey=%s RETURNING id, views", (viewkey,))
    if not row:
        return {"success": False, "counted": False}
    _recent_views[k] = now
    if len(_recent_views) > 5000:
        for old in [x for x, t in _recent_views.items() if now - t > 1800]:
            _recent_views.pop(old, None)
    get_one("INSERT INTO video_views (video_id) VALUES (%s) RETURNING id", (row["id"],))
    return {"success": True, "counted": True, "views": row["views"]}


def _analytics_for(uid: int):
    """28 din ka analytics dict, ya error par None."""
    try:
        views_daily = execute_query("""
            SELECT to_char(d, 'Mon DD') AS day, COALESCE(x.n, 0) AS n
            FROM generate_series(CURRENT_DATE - 27, CURRENT_DATE, interval '1 day') d
            LEFT JOIN (SELECT vv.created_at::date AS dd, COUNT(*) AS n
                       FROM video_views vv JOIN videos v ON v.id = vv.video_id
                       WHERE v.user_id = %s AND vv.created_at >= CURRENT_DATE - 27
                       GROUP BY 1) x ON x.dd = d::date
            ORDER BY d""", (uid,), fetch=True) or []

        subs_daily = execute_query("""
            SELECT to_char(d, 'Mon DD') AS day, COALESCE(x.n, 0) AS n
            FROM generate_series(CURRENT_DATE - 27, CURRENT_DATE, interval '1 day') d
            LEFT JOIN (SELECT created_at::date AS dd, COUNT(*) AS n
                       FROM subscriptions
                       WHERE channel_user_id = %s AND created_at >= CURRENT_DATE - 27
                       GROUP BY 1) x ON x.dd = d::date
            ORDER BY d""", (uid,), fetch=True) or []

        top_videos = execute_query("""
            SELECT v.id, v.title, v.viewkey, v.thumbnail, v.views, v.is_premium,
                   (SELECT COUNT(*) FROM video_likes l WHERE l.video_id = v.id) AS likes,
                   (SELECT COUNT(*) FROM comments c WHERE c.video_id = v.id)    AS comments
            FROM videos v WHERE v.user_id = %s
            ORDER BY v.views DESC NULLS LAST, v.uploaded_at DESC LIMIT 5""", (uid,), fetch=True) or []

        recent_comments = execute_query("""
            SELECT cm.id, LEFT(cm.content, 140) AS content, cm.created_at,
                   COALESCE(ch.channel_name, mu.name) AS name,
                   COALESCE(ch.avatar_url, mu.avatar_url) AS avatar,
                   v.title AS video_title, v.viewkey, v.is_premium
            FROM comments cm
            JOIN videos v  ON v.id = cm.video_id
            JOIN mydata mu ON mu.id = cm.user_id
            LEFT JOIN channels ch ON ch.user_id = cm.user_id
            WHERE v.user_id = %s AND cm.user_id <> %s
            ORDER BY cm.created_at DESC LIMIT 5""", (uid, uid), fetch=True) or []

        recent_subscribers = execute_query("""
            SELECT s.created_at, COALESCE(c.channel_name, mu.name) AS name, c.handle,
                   COALESCE(c.avatar_url, mu.avatar_url) AS avatar
            FROM subscriptions s
            JOIN mydata mu ON mu.id = s.subscriber_id
            LEFT JOIN channels c ON c.user_id = mu.id
            WHERE s.channel_user_id = %s
            ORDER BY s.created_at DESC LIMIT 5""", (uid,), fetch=True) or []

        return {
            "views_daily": views_daily,
            "subs_daily": subs_daily,
            "views_28d": sum(int(r["n"]) for r in views_daily),
            "subs_28d": sum(int(r["n"]) for r in subs_daily),
            "top_videos": top_videos,
            "recent_comments": recent_comments,
            "recent_subscribers": recent_subscribers,
        }
    except Exception:
        logger.exception("studio_analytics")
        return None


@router.get("/studio/analytics")
async def studio_analytics(api_key: str = Header(...)):
    u = current_user(api_key)
    a = _analytics_for(u["user_id"])
    if a:
        return {"success": True, "analytics": a}
    return {"success": False, "message": "Could not load analytics"}


@router.get("/studio/init")
async def studio_init(api_key: str = Header(...)):
    u = current_user(api_key)
    uid = u["user_id"]
    channel = get_one("SELECT * FROM channels WHERE user_id=%s", (uid,))
    stats = get_one("""
        SELECT COUNT(*) AS videos,
               COALESCE(SUM(views),0) AS views,
               COUNT(*) FILTER (WHERE is_premium) AS premium,
               (SELECT COUNT(*) FROM subscriptions WHERE channel_user_id=%s) AS subscribers,
               (SELECT COUNT(*) FROM video_likes vl JOIN videos x ON x.id=vl.video_id WHERE x.user_id=%s) AS likes,
               (SELECT COUNT(*) FROM comments cm JOIN videos y ON y.id=cm.video_id WHERE y.user_id=%s) AS comments
        FROM videos WHERE user_id=%s""", (uid, uid, uid, uid))
    videos = execute_query("""
        SELECT id, title, viewkey, thumbnail, category, description, visibility, is_premium,
               views, duration, uploaded_at
        FROM videos WHERE user_id=%s ORDER BY uploaded_at DESC LIMIT 100""", (uid,), fetch=True) or []
    analytics = _analytics_for(uid) if channel else None
    return {"success": True, "channel": channel, "stats": stats, "videos": videos, "analytics": analytics}


# =====================================================================
#  CHANNELS + SUBSCRIPTIONS
# =====================================================================
@router.get("/channels")
async def list_channels(q: str = "", sort: str = "popular", limit: int = 24, offset: int = 0,
                        actor: dict = Depends(get_actor)):
    """Channels discover page: search + popular/newest."""
    limit = max(1, min(limit, 50))
    like = f"%{q.strip()}%" if q.strip() else None
    order = "c.id DESC" if sort == "new" else "subscriber_count DESC, video_count DESC, c.id DESC"
    rows = execute_query(f"""
        SELECT c.user_id, c.channel_name, c.handle, c.avatar_url, c.description,
               (SELECT COUNT(*) FROM subscriptions s WHERE s.channel_user_id = c.user_id) AS subscriber_count,
               (SELECT COUNT(*) FROM videos v WHERE v.user_id = c.user_id AND v.visibility = 'public'
                       AND (%s::boolean OR v.is_premium = false)) AS video_count,
               EXISTS(SELECT 1 FROM subscriptions s2
                      WHERE s2.channel_user_id = c.user_id AND s2.subscriber_id = %s::int) AS is_subscribed
        FROM channels c
        WHERE c.handle IS NOT NULL AND (%s::text IS NULL OR c.channel_name ILIKE %s OR c.handle ILIKE %s)
        ORDER BY {order} LIMIT %s OFFSET %s
    """, (actor["is_premium"] or False, actor["user_id"], like, like, like, limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "channels": rows[:limit]}


@router.get("/channels/{handle}")
async def get_channel(handle: str, actor: dict = Depends(get_actor)):
    row = get_one("""
        SELECT c.*,
               (SELECT COUNT(*) FROM subscriptions s WHERE s.channel_user_id = c.user_id) AS subscriber_count,
               (SELECT COUNT(*) FROM videos v WHERE v.user_id = c.user_id AND v.visibility = 'public'
                       AND (%s::boolean OR v.is_premium = false)) AS video_count,
               COALESCE((SELECT SUM(v.views) FROM videos v
                         WHERE v.user_id = c.user_id AND v.visibility = 'public'), 0) AS total_views,
               EXISTS(SELECT 1 FROM subscriptions s2
                      WHERE s2.channel_user_id = c.user_id AND s2.subscriber_id = %s::int) AS is_subscribed
        FROM channels c WHERE c.handle = %s
    """, (actor["is_premium"] or False, actor["user_id"], handle.lower()))
    if not row:
        raise HTTPException(404, "Channel not found")
    row["is_owner"] = _is_owner(actor, row["user_id"])
    row["is_own"] = bool(actor["user_id"] and actor["user_id"] == row["user_id"])
    return {"success": True, "channel": row}


@router.get("/channels/{handle}/videos")
async def get_channel_videos(handle: str, sort: str = "latest", limit: int = 20, offset: int = 0,
                             actor: dict = Depends(get_actor)):
    ch = get_one("SELECT user_id FROM channels WHERE handle=%s", (handle.lower(),))
    if not ch:
        raise HTTPException(404, "Channel not found")
    can_premium = actor["is_premium"] or _is_owner(actor, ch["user_id"])
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    where = "v.user_id = %s AND v.visibility = 'public'"
    if not can_premium and not SHOW_LOCKED_PREMIUM:
        where += " AND v.is_premium = false"
    order = "v.views DESC, v.uploaded_at DESC" if sort == "popular" else "v.uploaded_at DESC"
    rows = execute_query(f"""
        SELECT v.id, v.title, v.viewkey, v.thumbnail, v.category, v.description,
               v.is_premium, v.views, v.duration, v.uploaded_at
        FROM videos v WHERE {where} ORDER BY {order} LIMIT %s OFFSET %s
    """, (ch["user_id"], limit + 1, offset), fetch=True) or []
    for r in rows:
        r["locked"] = bool(r["is_premium"] and not can_premium)
    return {"success": True, "has_more": len(rows) > limit, "videos": rows[:limit]}


@router.post("/channels/{handle}/subscribe")
async def subscribe(handle: str, actor: dict = Depends(get_actor)):
    need_login(actor)
    ch = get_one("SELECT user_id FROM channels WHERE handle=%s", (handle.lower(),))
    if not ch:
        raise HTTPException(404, "Channel not found")
    if ch["user_id"] == actor["user_id"]:
        return {"success": False, "message": "You can't subscribe to your own channel"}
    ins = get_one("""INSERT INTO subscriptions (subscriber_id, channel_user_id) VALUES (%s,%s)
                     ON CONFLICT DO NOTHING RETURNING subscriber_id""", (actor["user_id"], ch["user_id"]))
    if ins:
        await notify(ch["user_id"], "new_subscriber", actor["user_id"])
    cnt = get_one("SELECT COUNT(*) AS n FROM subscriptions WHERE channel_user_id=%s", (ch["user_id"],))
    return {"success": True, "subscribed": True, "subscriber_count": cnt["n"] if cnt else 0}


@router.delete("/channels/{handle}/subscribe")
async def unsubscribe(handle: str, actor: dict = Depends(get_actor)):
    need_login(actor)
    ch = get_one("SELECT user_id FROM channels WHERE handle=%s", (handle.lower(),))
    if not ch:
        raise HTTPException(404, "Channel not found")
    get_one("DELETE FROM subscriptions WHERE subscriber_id=%s AND channel_user_id=%s RETURNING subscriber_id",
            (actor["user_id"], ch["user_id"]))
    cnt = get_one("SELECT COUNT(*) AS n FROM subscriptions WHERE channel_user_id=%s", (ch["user_id"],))
    return {"success": True, "subscribed": False, "subscriber_count": cnt["n"] if cnt else 0}


@router.get("/channels/{handle}/subscribers")
async def channel_subscribers(handle: str, limit: int = 50, offset: int = 0, actor: dict = Depends(get_actor)):
    need_verified(actor)
    ch = get_one("SELECT user_id FROM channels WHERE handle=%s", (handle.lower(),))
    if not ch:
        raise HTTPException(404, "Channel not found")
    if ch["user_id"] != actor["user_id"]:
        raise HTTPException(403, "Only the channel owner can see subscribers")
    limit = max(1, min(limit, 100))
    rows = execute_query("""
        SELECT s.created_at AS subscribed_at, u.id AS user_id,
               COALESCE(c.channel_name, u.name) AS name, c.handle, COALESCE(c.avatar_url, u.avatar_url) AS avatar
        FROM subscriptions s
        JOIN mydata u ON u.id = s.subscriber_id
        LEFT JOIN channels c ON c.user_id = u.id
        WHERE s.channel_user_id = %s ORDER BY s.created_at DESC LIMIT %s OFFSET %s
    """, (ch["user_id"], limit + 1, max(0, offset)), fetch=True) or []
    total = get_one("SELECT COUNT(*) AS n FROM subscriptions WHERE channel_user_id=%s", (ch["user_id"],))
    return {"success": True, "total": total["n"] if total else 0,
            "has_more": len(rows) > limit, "subscribers": rows[:limit]}


@router.get("/me/subscriptions")
async def my_subscriptions(actor: dict = Depends(get_actor)):
    need_login(actor)
    rows = execute_query("""
        SELECT c.handle, c.channel_name, c.avatar_url,
               (SELECT COUNT(*) FROM subscriptions s2 WHERE s2.channel_user_id = c.user_id) AS subscriber_count
        FROM subscriptions s JOIN channels c ON c.user_id = s.channel_user_id
        WHERE s.subscriber_id = %s ORDER BY s.created_at DESC
    """, (actor["user_id"],), fetch=True) or []
    return {"success": True, "total": len(rows), "channels": rows}


@router.get("/me/subscriptions/feed")
async def my_subscription_feed(limit: int = 20, offset: int = 0, actor: dict = Depends(get_actor)):
    need_login(actor)
    limit = max(1, min(limit, 50))
    rows = execute_query("""
        SELECT v.id, v.title, v.viewkey, v.thumbnail, v.category, v.is_premium, v.views, v.duration, v.uploaded_at,
               c.channel_name, c.handle, c.avatar_url
        FROM subscriptions s
        JOIN videos v   ON v.user_id = s.channel_user_id
        JOIN channels c ON c.user_id = s.channel_user_id
        WHERE s.subscriber_id = %s AND v.visibility = 'public' AND (%s::boolean OR v.is_premium = false)
        ORDER BY v.uploaded_at DESC LIMIT %s OFFSET %s
    """, (actor["user_id"], actor["is_premium"] or False, limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "videos": rows[:limit]}


# =====================================================================
#  NOTIFICATIONS
# =====================================================================
class WSManager:
    def __init__(self):
        self.conns = {}

    async def connect(self, uid: int, ws: WebSocket):
        await ws.accept()
        self.conns.setdefault(uid, set()).add(ws)

    def disconnect(self, uid: int, ws: WebSocket):
        s = self.conns.get(uid)
        if s:
            s.discard(ws)
            if not s:
                self.conns.pop(uid, None)

    async def push(self, uid: int, payload: dict):
        for ws in list(self.conns.get(uid, ())):
            try:
                await ws.send_json(jsonable_encoder(payload))
            except Exception:
                self.disconnect(uid, ws)


manager = WSManager()

NOTIF_SELECT = """
    SELECT n.id, n.type, n.is_read, n.created_at, n.video_id, n.comment_id, n.actor_id,
           COALESCE(ch.channel_name, au.name)      AS actor_name,
           ch.handle                               AS actor_handle,
           COALESCE(ch.avatar_url, au.avatar_url)  AS actor_avatar,
           v.viewkey AS video_viewkey, v.title AS video_title,
           v.thumbnail AS video_thumbnail, v.is_premium AS video_is_premium,
           LEFT(cm.content, 120) AS comment_text
    FROM notifications n
    LEFT JOIN mydata au   ON au.id = n.actor_id
    LEFT JOIN channels ch ON ch.user_id = n.actor_id
    LEFT JOIN videos v    ON v.id = n.video_id
    LEFT JOIN comments cm ON cm.id = n.comment_id
"""


def _ser_notification(r: dict) -> dict:
    who = r.get("actor_name") or "Someone"
    title = r.get("video_title") or "your video"
    t = r["type"]
    if t == "video_like":
        text = f'{who} liked your video "{title}"'
    elif t == "comment":
        text = f'{who} commented on your video "{title}": {r.get("comment_text") or ""}'
    elif t == "reply":
        text = f'{who} replied to your comment: {r.get("comment_text") or ""}'
    elif t == "comment_like":
        text = f'{who} liked your comment'
    elif t == "new_subscriber":
        text = f'{who} subscribed to your channel'
    elif t == "new_upload":
        text = f'{who} uploaded a new video: {title}'
    else:
        text = "New notification"
    url = None
    if r.get("video_viewkey"):
        url = f"/view_video?viewkey={r['video_viewkey']}&type={'premium' if r.get('video_is_premium') else 'free'}"
    elif t == "new_subscriber" and r.get("actor_handle"):
        url = f"/channel/{r['actor_handle']}"
    r["text"] = text.strip()
    r["url"] = url
    return r


_UNIQUE_TYPES = ("video_like", "comment_like", "new_subscriber")


async def notify(user_id, ntype: str, actor_id, video_id=None, comment_id=None):
    try:
        if not user_id or user_id == actor_id:
            return
        if ntype in _UNIQUE_TYPES and get_one("""
                SELECT id FROM notifications WHERE user_id=%s AND type=%s
                  AND actor_id IS NOT DISTINCT FROM %s::int
                  AND video_id IS NOT DISTINCT FROM %s::int
                  AND comment_id IS NOT DISTINCT FROM %s::int""",
                (user_id, ntype, actor_id, video_id, comment_id)):
            return
        new = get_one("""INSERT INTO notifications (user_id, actor_id, type, video_id, comment_id)
                         VALUES (%s,%s,%s,%s,%s) RETURNING id""", (user_id, actor_id, ntype, video_id, comment_id))
        row = get_one(NOTIF_SELECT + " WHERE n.id=%s", (new["id"],))
        unread = get_one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=%s AND is_read=false", (user_id,))
        await manager.push(user_id, {"type": "notification", "notification": _ser_notification(row),
                                     "unread": unread["n"] if unread else 0})
    except Exception:
        logger.exception("notify failed")


def _drop_notification(user_id, ntype, actor_id, video_id=None, comment_id=None):
    try:
        get_one("""DELETE FROM notifications WHERE user_id=%s AND type=%s
                     AND actor_id IS NOT DISTINCT FROM %s::int
                     AND video_id IS NOT DISTINCT FROM %s::int
                     AND comment_id IS NOT DISTINCT FROM %s::int RETURNING id""",
                (user_id, ntype, actor_id, video_id, comment_id))
    except Exception:
        logger.exception("drop notification failed")


async def _notify_new_upload(owner_id: int, video_id: int, is_premium: bool):
    try:
        subs = execute_query("""
            SELECT s.subscriber_id FROM subscriptions s JOIN mydata m ON m.id = s.subscriber_id
            WHERE s.channel_user_id = %s AND (%s::boolean = false OR m.is_premium = true) LIMIT 2000
        """, (owner_id, is_premium), fetch=True) or []
        if not subs:
            return
        get_one("""
            INSERT INTO notifications (user_id, actor_id, type, video_id)
            SELECT s.subscriber_id, %s, 'new_upload', %s
            FROM subscriptions s JOIN mydata m ON m.id = s.subscriber_id
            WHERE s.channel_user_id = %s AND (%s::boolean = false OR m.is_premium = true)
            RETURNING id""", (owner_id, video_id, owner_id, is_premium))
        for s in subs:
            await manager.push(s["subscriber_id"], {"type": "refresh"})
    except Exception:
        logger.exception("_notify_new_upload failed")


@router.get("/notifications")
async def list_notifications(limit: int = 20, offset: int = 0, unread_only: bool = False,
                             actor: dict = Depends(get_actor)):
    need_verified(actor)
    limit = max(1, min(limit, 50))
    where = "n.user_id = %s" + (" AND n.is_read = false" if unread_only else "")
    rows = execute_query(NOTIF_SELECT + f" WHERE {where} ORDER BY n.created_at DESC LIMIT %s OFFSET %s",
                         (actor["user_id"], limit + 1, max(0, offset)), fetch=True) or []
    unread = get_one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=%s AND is_read=false", (actor["user_id"],))
    return {"success": True, "unread": unread["n"] if unread else 0, "has_more": len(rows) > limit,
            "notifications": [_ser_notification(r) for r in rows[:limit]]}


@router.get("/notifications/unread_count")
async def unread_count(actor: dict = Depends(get_actor)):
    need_verified(actor)
    unread = get_one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=%s AND is_read=false", (actor["user_id"],))
    return {"success": True, "unread": unread["n"] if unread else 0}


class ReadIn(BaseModel):
    ids: Optional[List[int]] = None


@router.post("/notifications/read")
async def mark_read(body: ReadIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    if body.ids:
        execute_query("UPDATE notifications SET is_read = true WHERE user_id = %s AND id = ANY(%s)",
                      (actor["user_id"], body.ids), fetch=False)
    else:
        execute_query("UPDATE notifications SET is_read = true WHERE user_id = %s",
                      (actor["user_id"],), fetch=False)
    unread = get_one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=%s AND is_read=false", (actor["user_id"],))
    return {"success": True, "unread": unread["n"] if unread else 0}


@router.delete("/notifications/{notification_id}")
async def delete_notification(notification_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    get_one("DELETE FROM notifications WHERE id=%s AND user_id=%s RETURNING id", (notification_id, actor["user_id"]))
    return {"success": True}


@router.websocket("/ws/notifications")
async def ws_notifications(ws: WebSocket):
    uid = read_token(ws.query_params.get("token"))
    if not uid or not get_one("SELECT id FROM mydata WHERE id=%s", (uid,)):
        await ws.close(code=4401)
        return
    await manager.connect(uid, ws)
    try:
        unread = get_one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=%s AND is_read=false", (uid,))
        await ws.send_json({"type": "connected", "unread": unread["n"] if unread else 0})
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("ws error")
    finally:
        manager.disconnect(uid, ws)


# =====================================================================
#  COMMENTS
# =====================================================================
class CommentIn(BaseModel):
    content: str
    parent_id: Optional[int] = None


_last_comment = {}

COMMENT_SELECT = """
    SELECT c.id, c.video_id, c.parent_id, c.user_id, c.content, c.created_at,
           COALESCE(ch.channel_name, u.name)        AS name,
           ch.handle                                AS handle,
           COALESCE(ch.avatar_url, u.avatar_url)    AS avatar,
           (SELECT COUNT(*) FROM comment_likes l WHERE l.comment_id = c.id)  AS likes,
           EXISTS(
               SELECT 1 FROM comment_likes l2
               WHERE l2.comment_id = c.id
                 AND ( (l2.user_id IS NOT NULL    AND l2.user_id    = %s::int)
                    OR (l2.visitor_id IS NOT NULL AND l2.visitor_id = %s::text) )
           )                                                                  AS liked,
           (SELECT COUNT(*) FROM comments r WHERE r.parent_id = c.id)         AS reply_count,
           (c.user_id = v.user_id)                                            AS is_creator,
           COALESCE(c.user_id = %s::int, false)                               AS is_owner,
           COALESCE(v.user_id = %s::int, false)                               AS is_video_owner
    FROM comments c
    JOIN videos v         ON v.id = c.video_id
    JOIN mydata u         ON u.id = c.user_id
    LEFT JOIN channels ch ON ch.user_id = c.user_id
"""


def _cp(actor: dict, with_visitor: bool = True):
    uid = actor["user_id"]
    vid = actor["visitor_id"] if with_visitor else None
    return (uid, vid, uid, uid)


def _comment_video(viewkey: str, actor: dict):
    v = get_one("SELECT id, user_id, is_premium, visibility FROM videos WHERE viewkey=%s", (viewkey,))
    if not v or (v["visibility"] == "private" and not _is_owner(actor, v["user_id"])):
        raise HTTPException(404, "Video not found")
    if not _can_view_video(v, actor):
        raise HTTPException(403, "Premium content")
    return v


@router.get("/videos/{viewkey}/comments")
async def get_comments(viewkey: str, sort: str = "top", limit: int = 20, offset: int = 0,
                       actor: dict = Depends(get_actor)):
    video = _comment_video(viewkey, actor)
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    order = "likes DESC, c.created_at DESC" if sort == "top" else "c.created_at DESC"
    rows = execute_query(
        COMMENT_SELECT + f" WHERE c.video_id=%s AND c.parent_id IS NULL ORDER BY {order} LIMIT %s OFFSET %s",
        (*_cp(actor), video["id"], limit + 1, offset), fetch=True) or []
    total = get_one("SELECT COUNT(*) AS n FROM comments WHERE video_id=%s", (video["id"],))
    return {"success": True, "total": total["n"] if total else 0,
            "has_more": len(rows) > limit, "comments": rows[:limit]}


@router.get("/comments/{comment_id}/replies")
async def get_replies(comment_id: int, actor: dict = Depends(get_actor)):
    parent = get_one("""SELECT v.id, v.user_id, v.is_premium, v.visibility FROM comments c
                        JOIN videos v ON v.id = c.video_id WHERE c.id=%s""", (comment_id,))
    if not parent or not _can_view_video(parent, actor):
        raise HTTPException(404, "Comment not found")
    rows = execute_query(COMMENT_SELECT + " WHERE c.parent_id=%s ORDER BY c.created_at ASC LIMIT 200",
                         (*_cp(actor), comment_id), fetch=True) or []
    return {"success": True, "replies": rows}


@router.post("/videos/{viewkey}/comments")
async def post_comment(viewkey: str, body: CommentIn, actor: dict = Depends(get_actor)):
    need_login(actor)
    uid = actor["user_id"]
    if not rate_limit(f"comment:{uid}", 5, 60):
        return {"success": False, "message": "You are commenting too fast. Please wait."}
    video = _comment_video(viewkey, actor)

    text = (body.content or "").strip()
    if not text:
        return {"success": False, "message": "Comment cannot be empty"}
    if len(text) > 1000:
        return {"success": False, "message": "Comment is too long (max 1000 characters)"}
    now = time.time()
    if now - _last_comment.get(uid, 0) < 5:
        return {"success": False, "message": "You are commenting too fast. Please wait a few seconds."}

    parent_id, reply_to_user = None, None
    if body.parent_id:
        p = get_one("SELECT id, parent_id, user_id FROM comments WHERE id=%s AND video_id=%s",
                    (body.parent_id, video["id"]))
        if not p:
            return {"success": False, "message": "The comment you are replying to no longer exists"}
        parent_id = p["parent_id"] or p["id"]
        reply_to_user = p["user_id"]

    try:
        new = get_one("INSERT INTO comments (video_id, user_id, parent_id, content) VALUES (%s,%s,%s,%s) RETURNING id",
                      (video["id"], uid, parent_id, text))
        _last_comment[uid] = now
        if len(_last_comment) > 5000:
            for k in [k for k, t in _last_comment.items() if now - t > 60]:
                _last_comment.pop(k, None)
        row = get_one(COMMENT_SELECT + " WHERE c.id=%s", (*_cp(actor, False), new["id"]))
    except Exception:
        logger.exception("post_comment")
        return {"success": False, "message": "Could not post comment"}

    if reply_to_user:
        await notify(reply_to_user, "reply", uid, video_id=video["id"], comment_id=new["id"])
    else:
        await notify(video["user_id"], "comment", uid, video_id=video["id"], comment_id=new["id"])
    return {"success": True, "comment": row}


@router.delete("/comments/{comment_id}")
async def delete_comment(comment_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = get_one("""SELECT c.id, c.user_id, v.user_id AS video_owner
                   FROM comments c JOIN videos v ON v.id = c.video_id WHERE c.id=%s""", (comment_id,))
    if not c:
        raise HTTPException(404, "Comment not found")
    if actor["user_id"] not in (c["user_id"], c["video_owner"]):
        raise HTTPException(403, "You can't delete this comment")
    n = get_one("SELECT COUNT(*) AS n FROM comments WHERE id=%s OR parent_id=%s", (comment_id, comment_id))
    get_one("DELETE FROM comments WHERE id=%s RETURNING id", (comment_id,))
    return {"success": True, "deleted": n["n"] if n else 1}


@router.post("/comments/{comment_id}/like")
async def toggle_comment_like(comment_id: int, actor: dict = Depends(get_actor)):
    uid, vid = actor["user_id"], actor["visitor_id"]
    if not uid and not vid:
        raise HTTPException(400, "Missing visitor id")
    if uid and not rate_limit(f"clike:{uid}", 30, 60):
        raise HTTPException(429, "Too many likes. Slow down.")
    c = get_one("""SELECT c.id, c.user_id, c.video_id, v.user_id AS vo, v.is_premium, v.visibility
                   FROM comments c JOIN videos v ON v.id = c.video_id WHERE c.id=%s""", (comment_id,))
    if not c or not _can_view_video({"user_id": c["vo"], "is_premium": c["is_premium"],
                                     "visibility": c["visibility"]}, actor):
        raise HTTPException(404, "Comment not found")

    if uid:
        ins = get_one("""INSERT INTO comment_likes (comment_id, user_id) VALUES (%s,%s)
                         ON CONFLICT DO NOTHING RETURNING comment_id""", (comment_id, uid))
        liked = bool(ins)
        if not liked:
            get_one("DELETE FROM comment_likes WHERE comment_id=%s AND user_id=%s RETURNING comment_id",
                    (comment_id, uid))
    else:
        ins = get_one("""INSERT INTO comment_likes (comment_id, visitor_id) VALUES (%s,%s)
                         ON CONFLICT DO NOTHING RETURNING comment_id""", (comment_id, vid))
        liked = bool(ins)
        if not liked:
            get_one("DELETE FROM comment_likes WHERE comment_id=%s AND visitor_id=%s RETURNING comment_id",
                    (comment_id, vid))

    if uid:
        if liked:
            await notify(c["user_id"], "comment_like", uid, video_id=c["video_id"], comment_id=comment_id)
        else:
            _drop_notification(c["user_id"], "comment_like", uid, video_id=c["video_id"], comment_id=comment_id)

    cnt = get_one("SELECT COUNT(*) AS n FROM comment_likes WHERE comment_id=%s", (comment_id,))
    return {"success": True, "liked": liked, "likes": cnt["n"] if cnt else 0}


# =====================================================================
#  PART 1: TAGS + SMART SEARCH + RELATED
# =====================================================================
import re as _re


def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = _re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:60] or "tag"


def _normalize_tag(raw: str) -> Optional[str]:
    t = (raw or "").strip().lower()
    t = _re.sub(r"\s+", " ", t)
    if not (2 <= len(t) <= 30):
        return None
    if not _re.fullmatch(r"[a-z0-9][a-z0-9 \-_.]*", t):
        return None
    return t


def _upsert_tag(name: str) -> Optional[int]:
    slug = _slugify(name)
    row = get_one("""
        INSERT INTO tags (name, slug) VALUES (%s, %s)
        ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
        RETURNING id
    """, (name, slug))
    return row["id"] if row else None


def _recount_tag(tag_id: int):
    get_one("""
        UPDATE tags SET usage_count = (
            SELECT COUNT(*) FROM video_tags WHERE tag_id = %s
        ) WHERE id = %s RETURNING id
    """, (tag_id, tag_id))


def _set_video_tags(video_id: int, tags_in: List[str]) -> List[dict]:
    cleaned = []
    seen = set()
    for raw in (tags_in or [])[:30]:
        n = _normalize_tag(raw)
        if n and n not in seen:
            seen.add(n)
            cleaned.append(n)
        if len(cleaned) >= 15:
            break

    old = execute_query("SELECT tag_id FROM video_tags WHERE video_id = %s", (video_id,), fetch=True) or []
    old_ids = {r["tag_id"] for r in old}

    new_ids = set()
    for name in cleaned:
        tid = _upsert_tag(name)
        if tid:
            new_ids.add(tid)
            get_one("""
                INSERT INTO video_tags (video_id, tag_id) VALUES (%s, %s)
                ON CONFLICT DO NOTHING RETURNING video_id
            """, (video_id, tid))

    to_remove = old_ids - new_ids
    if to_remove:
        execute_query("DELETE FROM video_tags WHERE video_id = %s AND tag_id = ANY(%s)",
                      (video_id, list(to_remove)), fetch=False)

    for tid in (old_ids | new_ids):
        _recount_tag(tid)

    return _get_video_tags(video_id)


def _get_video_tags(video_id: int) -> List[dict]:
    return execute_query("""
        SELECT t.id, t.name, t.slug, t.usage_count
        FROM video_tags vt JOIN tags t ON t.id = vt.tag_id
        WHERE vt.video_id = %s
        ORDER BY t.usage_count DESC, t.name ASC
    """, (video_id,), fetch=True) or []


def _video_owned_by(viewkey: str, uid: int) -> Optional[dict]:
    v = get_one("SELECT id, user_id FROM videos WHERE viewkey = %s", (viewkey,))
    if not v:
        return None
    if v["user_id"] != uid:
        return None
    return v


@router.get("/tags/popular")
async def tags_popular(limit: int = 30):
    limit = max(1, min(limit, 100))
    rows = execute_query("""
        SELECT id, name, slug, usage_count FROM tags
        WHERE usage_count > 0
        ORDER BY usage_count DESC, name ASC LIMIT %s
    """, (limit,), fetch=True) or []
    return {"success": True, "tags": rows}


@router.get("/tags/autocomplete")
async def tags_autocomplete(q: str = "", limit: int = 10):
    q = (q or "").strip().lower()
    if len(q) < 1:
        return {"success": True, "tags": []}
    limit = max(1, min(limit, 20))
    rows = execute_query("""
        SELECT id, name, slug, usage_count FROM tags
        WHERE LOWER(name) LIKE %s OR slug LIKE %s
        ORDER BY usage_count DESC, name ASC LIMIT %s
    """, (f"%{q}%", f"{q}%", limit), fetch=True) or []
    return {"success": True, "tags": rows}


@router.get("/tags/{slug}/videos")
async def videos_by_tag(slug: str, limit: int = 20, offset: int = 0,
                        actor: dict = Depends(get_actor)):
    tag = get_one("SELECT id, name FROM tags WHERE slug = %s", (slug.lower(),))
    if not tag:
        raise HTTPException(404, "Tag not found")
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    rows = execute_query("""
        SELECT v.id, v.title, v.viewkey, v.thumbnail, v.category, v.is_premium,
               v.views, v.duration, v.uploaded_at,
               COALESCE(c.channel_name, u.name) AS channel_name,
               c.handle AS channel_handle,
               COALESCE(c.avatar_url, u.avatar_url) AS channel_avatar
        FROM video_tags vt
        JOIN videos v ON v.id = vt.video_id
        LEFT JOIN channels c ON c.user_id = v.user_id
        LEFT JOIN mydata u   ON u.id = v.user_id
        WHERE vt.tag_id = %s AND v.visibility = 'public'
          AND (%s::boolean OR v.is_premium = false)
        ORDER BY v.views DESC, v.uploaded_at DESC
        LIMIT %s OFFSET %s
    """, (tag["id"], actor["is_premium"] or False, limit + 1, offset), fetch=True) or []
    return {"success": True, "tag": tag,
            "has_more": len(rows) > limit, "videos": rows[:limit]}


@router.get("/videos/{viewkey}/tags")
async def video_tags_get(viewkey: str):
    v = get_one("SELECT id FROM videos WHERE viewkey = %s", (viewkey,))
    if not v:
        raise HTTPException(404, "Video not found")
    return {"success": True, "tags": _get_video_tags(v["id"])}


@router.post("/videos/{viewkey}/tags")
async def video_tags_set(viewkey: str, body: TagsForVideoIn,
                         actor: dict = Depends(get_actor)):
    need_verified(actor)
    v = _video_owned_by(viewkey, actor["user_id"])
    if not v:
        raise HTTPException(404, "Video not found or not yours")
    tags = _set_video_tags(v["id"], body.tags)
    return {"success": True, "tags": tags}


@router.get("/search")
async def smart_search(
    q: str = "",
    sort: str = "relevance",
    limit: int = 20,
    offset: int = 0,
    actor: dict = Depends(get_actor),
):
    q = (q or "").strip()
    if len(q) < 2:
        return {"success": True, "query": q, "total": 0, "has_more": False, "videos": []}

    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    like = f"%{q.lower()}%"
    prefix = f"{q.lower()}%"

    order_sql = {
        "latest":  "v.uploaded_at DESC",
        "popular": "v.views DESC, v.uploaded_at DESC",
    }.get(sort, "rank_score DESC, v.views DESC")

    rows = execute_query(f"""
        WITH matched AS (
            SELECT
                v.id,
                (
                    CASE WHEN LOWER(v.title) LIKE %s THEN 100 ELSE 0 END +
                    CASE WHEN LOWER(v.title) LIKE %s THEN 40  ELSE 0 END +
                    CASE WHEN EXISTS (
                        SELECT 1 FROM video_tags vt JOIN tags t ON t.id = vt.tag_id
                        WHERE vt.video_id = v.id AND (LOWER(t.name) LIKE %s OR t.slug LIKE %s)
                    ) THEN 60 ELSE 0 END +
                    CASE WHEN LOWER(COALESCE(v.description,'')) LIKE %s THEN 20 ELSE 0 END +
                    CASE WHEN LOWER(COALESCE(c.channel_name, u.name, '')) LIKE %s THEN 15 ELSE 0 END +
                    LEAST(COALESCE(v.views,0) / 100.0, 20)
                ) AS rank_score
            FROM videos v
            LEFT JOIN channels c ON c.user_id = v.user_id
            LEFT JOIN mydata u   ON u.id = v.user_id
            WHERE v.visibility = 'public'
              AND (%s::boolean OR v.is_premium = false)
              AND (
                    LOWER(v.title) LIKE %s
                 OR LOWER(COALESCE(v.description,'')) LIKE %s
                 OR LOWER(COALESCE(c.channel_name, u.name, '')) LIKE %s
                 OR EXISTS (
                        SELECT 1 FROM video_tags vt JOIN tags t ON t.id = vt.tag_id
                        WHERE vt.video_id = v.id AND (LOWER(t.name) LIKE %s OR t.slug LIKE %s)
                    )
              )
        )
        SELECT
            v.id, v.title, v.viewkey, v.thumbnail, v.category, v.is_premium,
            v.views, v.duration, v.uploaded_at,
            COALESCE(c.channel_name, u.name) AS channel_name,
            c.handle AS channel_handle,
            COALESCE(c.avatar_url, u.avatar_url) AS channel_avatar,
            m.rank_score,
            COALESCE((
                SELECT json_agg(json_build_object('name', t.name, 'slug', t.slug)
                                ORDER BY t.usage_count DESC)
                FROM video_tags vt JOIN tags t ON t.id = vt.tag_id
                WHERE vt.video_id = v.id
                LIMIT 3
            ), '[]'::json) AS top_tags
        FROM matched m
        JOIN videos v        ON v.id = m.id
        LEFT JOIN channels c ON c.user_id = v.user_id
        LEFT JOIN mydata u   ON u.id = v.user_id
        ORDER BY {order_sql}
        LIMIT %s OFFSET %s
    """, (
        prefix, like,
        like, prefix,
        like,
        like,
        actor["is_premium"] or False,
        like, like, like,
        like, prefix,
        limit + 1, offset,
    ), fetch=True) or []

    return {
        "success": True,
        "query": q,
        "has_more": len(rows) > limit,
        "videos": rows[:limit],
    }


@router.get("/videos/{viewkey}/related")
async def related_videos(viewkey: str, limit: int = 12,
                         actor: dict = Depends(get_actor)):
    v = get_one("SELECT id, user_id, category FROM videos WHERE viewkey = %s", (viewkey,))
    if not v:
        raise HTTPException(404, "Video not found")
    limit = max(1, min(limit, 30))
    rows = execute_query("""
        WITH my_tags AS (
            SELECT tag_id FROM video_tags WHERE video_id = %s
        ),
        scored AS (
            SELECT v.id,
                   (SELECT COUNT(*) FROM video_tags vt
                    WHERE vt.video_id = v.id AND vt.tag_id IN (SELECT tag_id FROM my_tags)
                   ) * 10
                   + CASE WHEN %s IS NOT NULL AND v.category = %s THEN 3 ELSE 0 END
                   + CASE WHEN v.user_id = %s THEN 2 ELSE 0 END
                   + LEAST(COALESCE(v.views,0) / 200.0, 5) AS score
            FROM videos v
            WHERE v.id <> %s AND v.visibility = 'public'
              AND (%s::boolean OR v.is_premium = false)
        )
        SELECT
            v.id, v.title, v.viewkey, v.thumbnail, v.category, v.is_premium,
            v.views, v.duration, v.uploaded_at,
            COALESCE(c.channel_name, u.name) AS channel_name,
            c.handle AS channel_handle,
            COALESCE(c.avatar_url, u.avatar_url) AS channel_avatar,
            s.score
        FROM scored s
        JOIN videos v        ON v.id = s.id
        LEFT JOIN channels c ON c.user_id = v.user_id
        LEFT JOIN mydata u   ON u.id = v.user_id
        ORDER BY s.score DESC, v.views DESC, v.uploaded_at DESC
        LIMIT %s
    """, (v["id"], v["category"], v["category"], v["user_id"], v["id"],
          actor["is_premium"] or False, limit), fetch=True) or []
    return {"success": True, "videos": rows}


# =====================================================================
#  CUSTOM PLAYLISTS v2 (user playlists)
# =====================================================================
_PL2_COLS = ("id, user_id, title, description, thumbnail, visibility, "
             "is_system, created_at, updated_at")


def _pl2_can_view(pl: dict, actor: dict) -> bool:
    if pl["visibility"] == "private":
        return bool(actor["user_id"] and actor["user_id"] == pl["user_id"])
    return True


def _pl2_own(pl_id: int, uid: int) -> Optional[dict]:
    return get_one(f"SELECT {_PL2_COLS} FROM playlists_v2 WHERE id = %s AND user_id = %s",
                   (pl_id, uid))


@router.post("/playlists/create")
async def playlist_create(body: PlaylistCreateIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    if not rate_limit(f"plcreate:{actor['user_id']}", 10, 3600):
        return {"success": False, "message": "Too many playlists created. Try again later."}
    title = (body.title or "").strip()
    if not (2 <= len(title) <= 150):
        return {"success": False, "message": "Title must be 2-150 characters"}
    if body.visibility not in ("public", "unlisted", "private"):
        return {"success": False, "message": "Invalid visibility"}
    desc = (body.description or "").strip()[:1000]
    thumb = (body.thumbnail or "").strip()
    if thumb and not thumb.startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Thumbnail must be a Cloudinary URL"}

    count = get_one("SELECT COUNT(*) AS n FROM playlists_v2 WHERE user_id = %s", (actor["user_id"],))
    if count and count["n"] >= 100:
        return {"success": False, "message": "Maximum 100 playlists per user"}

    row = get_one(f"""
        INSERT INTO playlists_v2 (user_id, title, description, thumbnail, visibility)
        VALUES (%s, %s, %s, %s, %s) RETURNING {_PL2_COLS}
    """, (actor["user_id"], title, desc, thumb or None, body.visibility))
    return {"success": True, "playlist": row}


@router.get("/me/playlists")
async def playlist_my(limit: int = 50, offset: int = 0,
                      actor: dict = Depends(get_actor)):
    need_verified(actor)
    limit = max(1, min(limit, 100))
    rows = execute_query(f"""
        SELECT p.{_PL2_COLS.replace(', ', ', p.').replace('p.id', 'id')},
               (SELECT COUNT(*) FROM playlist_items pi WHERE pi.playlist_id = p.id) AS item_count
        FROM playlists_v2 p
        WHERE p.user_id = %s
        ORDER BY p.is_system DESC, p.updated_at DESC
        LIMIT %s OFFSET %s
    """, (actor["user_id"], limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "playlists": rows[:limit]}


@router.get("/me/playlists/user/{user_id}")
async def playlist_by_user(user_id: int, actor: dict = Depends(get_actor)):
    rows = execute_query(f"""
        SELECT p.{_PL2_COLS.replace(', ', ', p.').replace('p.id', 'id')},
               (SELECT COUNT(*) FROM playlist_items pi WHERE pi.playlist_id = p.id) AS item_count
        FROM playlists_v2 p
        WHERE p.user_id = %s AND p.visibility = 'public'
        ORDER BY p.updated_at DESC LIMIT 100
    """, (user_id,), fetch=True) or []
    return {"success": True, "playlists": rows}


@router.get("/playlists/detail/{pl_id}")
async def playlist_detail(pl_id: int, actor: dict = Depends(get_actor)):
    pl = get_one(f"SELECT {_PL2_COLS} FROM playlists_v2 WHERE id = %s", (pl_id,))
    if not pl:
        raise HTTPException(404, "Playlist not found")
    if not _pl2_can_view(pl, actor):
        raise HTTPException(403, "This playlist is private")
    items = execute_query("""
        SELECT pi.id AS item_id, pi.position,
               v.id AS video_id, v.title, v.viewkey, v.thumbnail, v.category,
               v.is_premium, v.views, v.duration, v.uploaded_at,
               v.visibility,
               COALESCE(c.channel_name, u.name) AS channel_name,
               c.handle AS channel_handle,
               COALESCE(c.avatar_url, u.avatar_url) AS channel_avatar
        FROM playlist_items pi
        JOIN videos v        ON v.id = pi.video_id
        LEFT JOIN channels c ON c.user_id = v.user_id
        LEFT JOIN mydata u   ON u.id = v.user_id
        WHERE pi.playlist_id = %s
        ORDER BY pi.position ASC, pi.added_at ASC
    """, (pl_id,), fetch=True) or []

    for it in items:
        it["locked"] = bool(it["is_premium"] and not actor["is_premium"]
                            and actor["user_id"] != pl["user_id"])
        if it["locked"]:
            it.pop("viewkey", None)

    pl["is_owner"] = bool(actor["user_id"] and actor["user_id"] == pl["user_id"])
    return {"success": True, "playlist": pl, "items": items}


@router.put("/playlists/detail/{pl_id}")
async def playlist_update(pl_id: int, body: PlaylistUpdateIn,
                          actor: dict = Depends(get_actor)):
    need_verified(actor)
    pl = _pl2_own(pl_id, actor["user_id"])
    if not pl:
        raise HTTPException(404, "Playlist not found")

    fields = {}
    if body.title is not None:
        t = body.title.strip()
        if not (2 <= len(t) <= 150):
            return {"success": False, "message": "Title must be 2-150 characters"}
        fields["title"] = t
    if body.description is not None:
        fields["description"] = body.description.strip()[:1000]
    if body.thumbnail is not None:
        th = body.thumbnail.strip()
        if th and not th.startswith("https://res.cloudinary.com/"):
            return {"success": False, "message": "Thumbnail must be a Cloudinary URL"}
        fields["thumbnail"] = th or None
    if body.visibility is not None:
        if body.visibility not in ("public", "unlisted", "private"):
            return {"success": False, "message": "Invalid visibility"}
        if pl["is_system"] and body.visibility != "private":
            return {"success": False, "message": "System playlist must stay private"}
        fields["visibility"] = body.visibility

    if not fields:
        return {"success": False, "message": "Nothing to update"}

    sets = ", ".join(f"{k} = %s" for k in fields)
    row = get_one(f"""
        UPDATE playlists_v2 SET {sets}, updated_at = now()
        WHERE id = %s RETURNING {_PL2_COLS}
    """, (*fields.values(), pl_id))
    return {"success": True, "playlist": row}


@router.delete("/playlists/detail/{pl_id}")
async def playlist_delete(pl_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    pl = _pl2_own(pl_id, actor["user_id"])
    if not pl:
        raise HTTPException(404, "Playlist not found")
    if pl["is_system"]:
        return {"success": False, "message": "System playlist cannot be deleted"}
    get_one("DELETE FROM playlists_v2 WHERE id = %s RETURNING id", (pl_id,))
    return {"success": True}


@router.post("/playlists/detail/{pl_id}/add")
async def playlist_add_video(pl_id: int, body: PlaylistAddVideoIn,
                             actor: dict = Depends(get_actor)):
    """
    OPTIMIZED: 2 queries instead of 6.
    """
    need_verified(actor)
    if not rate_limit(f"pladd:{actor['user_id']}", 60, 60):
        return {"success": False, "message": "Slow down a bit."}

    info = get_one("""
        SELECT
            p.id AS pl_id,
            (SELECT COUNT(*) FROM playlist_items WHERE playlist_id = p.id) AS item_count,
            (SELECT COALESCE(MAX(position), -1) + 1 FROM playlist_items WHERE playlist_id = p.id) AS next_pos
        FROM playlists_v2 p
        WHERE p.id = %s AND p.user_id = %s
    """, (pl_id, actor["user_id"]))

    if not info:
        raise HTTPException(404, "Playlist not found")
    if info["item_count"] >= 500:
        return {"success": False, "message": "Playlist is full (max 500 videos)"}

    ins = get_one("""
        INSERT INTO playlist_items (playlist_id, video_id, position)
        SELECT %s, v.id, COALESCE(%s, %s)
        FROM videos v
        WHERE v.viewkey = %s AND v.visibility <> 'private'
        ON CONFLICT (playlist_id, video_id) DO NOTHING
        RETURNING id, video_id, position
    """, (pl_id, body.position, info["next_pos"], body.viewkey))

    if not ins:
        exists = get_one("SELECT 1 FROM videos WHERE viewkey = %s AND visibility <> 'private'",
                         (body.viewkey,))
        if not exists:
            return {"success": False, "message": "Video not found or is private"}
        return {"success": False, "message": "Video already in this playlist"}

    try:
        get_one("UPDATE playlists_v2 SET updated_at = now() WHERE id = %s RETURNING id", (pl_id,))
    except Exception:
        pass

    return {"success": True, "item_id": ins["id"], "position": ins["position"]}


@router.delete("/playlists/detail/{pl_id}/remove/{video_id}")
async def playlist_remove_video(pl_id: int, video_id: int,
                                actor: dict = Depends(get_actor)):
    need_verified(actor)
    pl = _pl2_own(pl_id, actor["user_id"])
    if not pl:
        raise HTTPException(404, "Playlist not found")
    row = get_one("""
        DELETE FROM playlist_items WHERE playlist_id = %s AND video_id = %s
        RETURNING id
    """, (pl_id, video_id))
    if not row:
        raise HTTPException(404, "Video not in playlist")
    get_one("UPDATE playlists_v2 SET updated_at = now() WHERE id = %s RETURNING id", (pl_id,))
    return {"success": True}


@router.put("/playlists/detail/{pl_id}/reorder")
async def playlist_reorder(pl_id: int, body: PlaylistReorderIn,
                           actor: dict = Depends(get_actor)):
    need_verified(actor)
    pl = _pl2_own(pl_id, actor["user_id"])
    if not pl:
        raise HTTPException(404, "Playlist not found")
    if not body.video_ids:
        return {"success": False, "message": "Empty order"}

    existing = execute_query("SELECT video_id FROM playlist_items WHERE playlist_id = %s",
                             (pl_id,), fetch=True) or []
    existing_ids = {r["video_id"] for r in existing}
    if set(body.video_ids) - existing_ids:
        return {"success": False, "message": "Some videos are not in this playlist"}

    for idx, vid in enumerate(body.video_ids):
        get_one("UPDATE playlist_items SET position = %s WHERE playlist_id = %s AND video_id = %s RETURNING id",
                (idx, pl_id, vid))
    get_one("UPDATE playlists_v2 SET updated_at = now() WHERE id = %s RETURNING id", (pl_id,))
    return {"success": True, "count": len(body.video_ids)}


@router.post("/playlists/watch-later/ensure")
async def ensure_watch_later(actor: dict = Depends(get_actor)):
    need_verified(actor)
    pl = get_one("""
        SELECT id, user_id, title, description, thumbnail, visibility, is_system,
               created_at, updated_at
        FROM playlists_v2 WHERE user_id = %s AND is_system = true AND title = 'Watch Later'
    """, (actor["user_id"],))
    if pl:
        return {"success": True, "playlist": pl, "created": False}
    row = get_one("""
        INSERT INTO playlists_v2 (user_id, title, description, visibility, is_system)
        VALUES (%s, 'Watch Later', 'Videos you saved for later', 'private', true)
        RETURNING id, user_id, title, description, thumbnail, visibility, is_system,
                  created_at, updated_at
    """, (actor["user_id"],))
    return {"success": True, "playlist": row, "created": True}


# =====================================================================
#  PART 2: PLANS + PAYMENTS + SUPPORT + ADMIN
# =====================================================================
@router.get("/plans")
async def list_plans():
    rows = execute_query("""
        SELECT id, code, name, description, price_pkr, price_usd,
               duration_days, features, sort_order
        FROM plans WHERE is_active = true
        ORDER BY sort_order ASC, id ASC
    """, fetch=True) or []
    return {"success": True, "plans": rows}


@router.get("/ad-pricing")
async def list_ad_pricing():
    rows = execute_query("""
        SELECT id, model, price_pkr, price_usd, min_budget
        FROM ad_pricing WHERE is_active = true ORDER BY model ASC
    """, fetch=True) or []
    return {"success": True, "pricing": rows}


@router.post("/payments/submit")
async def payment_submit(body: PaymentSubmitIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    uid = actor["user_id"]
    if not rate_limit(f"pay:{uid}", 5, 3600):
        return {"success": False, "message": "Too many payment submissions. Try later."}

    method = (body.method or "").strip().lower()
    if method not in ("jazzcash", "easypaisa", "bank", "crypto", "other"):
        return {"success": False, "message": "Invalid payment method"}
    tid = (body.transaction_id or "").strip()
    if not (4 <= len(tid) <= 120):
        return {"success": False, "message": "Transaction ID must be 4-120 characters"}
    try:
        amount = float(body.amount)
    except Exception:
        return {"success": False, "message": "Invalid amount"}
    if amount <= 0 or amount > 10_000_000:
        return {"success": False, "message": "Invalid amount"}

    plan = get_one("SELECT id, price_pkr FROM plans WHERE id = %s AND is_active = true",
                   (body.plan_id,))
    if not plan:
        return {"success": False, "message": "Plan not found"}

    ss = (body.screenshot_url or "").strip()
    if ss and not ss.startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Screenshot must be a Cloudinary URL"}

    dup = get_one("""
        SELECT id FROM payments
        WHERE method = %s AND transaction_id = %s AND status <> 'rejected'
    """, (method, tid))
    if dup:
        return {"success": False, "message": "This transaction ID is already submitted"}

    pend = get_one("""
        SELECT COUNT(*) AS n FROM payments WHERE user_id = %s AND status = 'pending'
    """, (uid,))
    if pend and pend["n"] >= 3:
        return {"success": False, "message": "You already have 3 pending payments."}

    row = get_one("""
        INSERT INTO payments
            (user_id, plan_id, amount, currency, method, transaction_id,
             sender_name, sender_account, screenshot_url, user_note)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id, user_id, plan_id, amount, currency, method,
                  transaction_id, status, created_at
    """, (
        uid, plan["id"], amount, (body.currency or "PKR").upper()[:10],
        method, tid,
        (body.sender_name or "").strip()[:120] or None,
        (body.sender_account or "").strip()[:120] or None,
        ss or None,
        (body.user_note or "").strip()[:500],
    ))

    try:
        for admin_id in ADMIN_USER_IDS:
            await notify(admin_id, "payment_submitted", uid)
    except Exception:
        logger.exception("notify payment_submitted")

    return {"success": True, "message": "Payment submitted. Admin will verify soon.",
            "payment": row}


@router.get("/payments/my")
async def my_payments(limit: int = 20, offset: int = 0, actor: dict = Depends(get_actor)):
    need_verified(actor)
    limit = max(1, min(limit, 50))
    rows = execute_query("""
        SELECT p.id, p.plan_id, pl.name AS plan_name,
               p.amount, p.currency, p.method, p.transaction_id,
               p.status, p.admin_note, p.created_at, p.reviewed_at
        FROM payments p
        LEFT JOIN plans pl ON pl.id = p.plan_id
        WHERE p.user_id = %s
        ORDER BY p.created_at DESC LIMIT %s OFFSET %s
    """, (actor["user_id"], limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "payments": rows[:limit]}


@router.get("/payments/status")
async def my_payment_status(actor: dict = Depends(get_actor)):
    need_verified(actor)
    s = get_one("""
        SELECT
          COUNT(*) FILTER (WHERE status = 'pending')  AS pending,
          COUNT(*) FILTER (WHERE status = 'approved') AS approved,
          COUNT(*) FILTER (WHERE status = 'rejected') AS rejected
        FROM payments WHERE user_id = %s
    """, (actor["user_id"],))
    latest = get_one("""
        SELECT id, status, created_at FROM payments
        WHERE user_id = %s ORDER BY created_at DESC LIMIT 1
    """, (actor["user_id"],))
    return {"success": True, "counts": s or {}, "latest": latest}


# ---------- SUPPORT CHAT ----------

@router.post("/support/threads/create")
async def support_create_thread(body: SupportThreadCreateIn,
                                actor: dict = Depends(get_actor)):
    need_verified(actor)
    if not rate_limit(f"supp:{actor['user_id']}", 5, 3600):
        return {"success": False, "message": "Too many support threads. Try later."}
    msg = (body.message or "").strip()
    if not (1 <= len(msg) <= 2000):
        return {"success": False, "message": "Message must be 1-2000 characters"}
    subj = (body.subject or "Support").strip()[:200] or "Support"

    op = get_one("""
        SELECT COUNT(*) AS n FROM support_threads
        WHERE user_id = %s AND status = 'open'
    """, (actor["user_id"],))
    if op and op["n"] >= 5:
        return {"success": False, "message": "You already have 5 open support threads"}

    th = get_one("""
        INSERT INTO support_threads (user_id, subject, unread_admin, unread_user)
        VALUES (%s, %s, 1, 0) RETURNING id, user_id, subject, status, created_at
    """, (actor["user_id"], subj))

    get_one("""
        INSERT INTO support_messages (thread_id, sender_id, is_admin, content, attachment)
        VALUES (%s, %s, false, %s, %s) RETURNING id
    """, (th["id"], actor["user_id"], msg, (body.attachment or None)))

    try:
        for admin_id in ADMIN_USER_IDS:
            await notify(admin_id, "support_message", actor["user_id"])
    except Exception:
        logger.exception("notify support create")

    return {"success": True, "thread": th}


@router.get("/support/threads/my")
async def support_my_threads(actor: dict = Depends(get_actor)):
    need_verified(actor)
    rows = execute_query("""
        SELECT t.id, t.subject, t.status, t.priority,
               t.unread_user, t.last_message_at, t.created_at,
               (SELECT content FROM support_messages m
                WHERE m.thread_id = t.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
               (SELECT COUNT(*) FROM support_messages m WHERE m.thread_id = t.id) AS message_count
        FROM support_threads t
        WHERE t.user_id = %s
        ORDER BY t.last_message_at DESC LIMIT 50
    """, (actor["user_id"],), fetch=True) or []
    return {"success": True, "threads": rows}


@router.get("/support/threads/{thread_id}")
async def support_get_thread(thread_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    t = get_one("SELECT * FROM support_threads WHERE id = %s AND user_id = %s",
                (thread_id, actor["user_id"]))
    if not t:
        raise HTTPException(404, "Thread not found")
    msgs = execute_query("""
        SELECT m.id, m.sender_id, m.is_admin, m.content, m.attachment,
               m.created_at,
               COALESCE(c.channel_name, u.name) AS sender_name,
               COALESCE(c.avatar_url, u.avatar_url) AS sender_avatar
        FROM support_messages m
        JOIN mydata u ON u.id = m.sender_id
        LEFT JOIN channels c ON c.user_id = u.id
        WHERE m.thread_id = %s ORDER BY m.created_at ASC LIMIT 500
    """, (thread_id,), fetch=True) or []
    get_one("UPDATE support_threads SET unread_user = 0 WHERE id = %s RETURNING id",
            (thread_id,))
    get_one("""
        UPDATE support_messages SET is_read = true
        WHERE thread_id = %s AND is_admin = true AND is_read = false RETURNING id
    """, (thread_id,))
    return {"success": True, "thread": t, "messages": msgs}


@router.post("/support/threads/{thread_id}/reply")
async def support_user_reply(thread_id: int, body: SupportMessageIn,
                             actor: dict = Depends(get_actor)):
    need_verified(actor)
    t = get_one("SELECT id, user_id, status FROM support_threads WHERE id = %s",
                (thread_id,))
    if not t or t["user_id"] != actor["user_id"]:
        raise HTTPException(404, "Thread not found")
    if t["status"] == "closed":
        return {"success": False, "message": "This thread is closed"}

    content = (body.content or "").strip()
    if not (1 <= len(content) <= 2000):
        return {"success": False, "message": "Message must be 1-2000 characters"}

    att = (body.attachment or "").strip()
    if att and not att.startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Attachment must be a Cloudinary URL"}

    m = get_one("""
        INSERT INTO support_messages (thread_id, sender_id, is_admin, content, attachment)
        VALUES (%s, %s, false, %s, %s)
        RETURNING id, thread_id, sender_id, is_admin, content, attachment, created_at
    """, (thread_id, actor["user_id"], content, att or None))

    get_one("""
        UPDATE support_threads SET last_message_at = now(), unread_admin = unread_admin + 1
        WHERE id = %s RETURNING id
    """, (thread_id,))

    try:
        for admin_id in ADMIN_USER_IDS:
            await notify(admin_id, "support_message", actor["user_id"])
    except Exception:
        logger.exception("notify support reply")

    return {"success": True, "message": m}


@router.post("/support/threads/{thread_id}/close")
async def support_user_close(thread_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    t = get_one("SELECT id, user_id FROM support_threads WHERE id = %s", (thread_id,))
    if not t or t["user_id"] != actor["user_id"]:
        raise HTTPException(404, "Thread not found")
    get_one("UPDATE support_threads SET status = 'closed' WHERE id = %s RETURNING id",
            (thread_id,))
    return {"success": True}


# =====================================================================
#  ADMIN ENDPOINTS
# =====================================================================
def _need_admin(actor: dict):
    need_verified(actor)
    if actor["user_id"] not in ADMIN_USER_IDS:
        raise HTTPException(403, "Admins only")


@router.get("/admin/dashboard")
async def admin_dashboard(actor: dict = Depends(get_actor)):
    _need_admin(actor)
    stats = get_one("""
        SELECT
          (SELECT COUNT(*) FROM mydata)                                  AS total_users,
          (SELECT COUNT(*) FROM mydata WHERE is_premium = true)          AS premium_users,
          (SELECT COUNT(*) FROM payments WHERE status = 'pending')       AS pending_payments,
          (SELECT COUNT(*) FROM payments WHERE status = 'approved')      AS approved_payments,
          (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='approved') AS total_revenue,
          (SELECT COUNT(*) FROM support_threads WHERE status = 'open')   AS open_threads,
          (SELECT COUNT(*) FROM support_threads WHERE unread_admin > 0)  AS unread_threads,
          (SELECT COUNT(*) FROM videos)                                  AS total_videos,
          (SELECT COUNT(*) FROM channels)                                AS total_channels
    """)
    return {"success": True, "stats": stats}


@router.get("/admin/payments")
async def admin_list_payments(status: str = "pending", limit: int = 30, offset: int = 0,
                              actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if status not in ("pending", "approved", "rejected", "all"):
        raise HTTPException(400, "Invalid status")
    limit = max(1, min(limit, 100))
    where = "" if status == "all" else "WHERE p.status = %s"
    params = (limit + 1, max(0, offset)) if status == "all" else (status, limit + 1, max(0, offset))
    rows = execute_query(f"""
        SELECT p.id, p.user_id, u.name AS user_name, u.email AS user_email,
               p.plan_id, pl.name AS plan_name,
               p.amount, p.currency, p.method, p.transaction_id,
               p.sender_name, p.sender_account, p.screenshot_url, p.user_note,
               p.status, p.admin_note, p.reviewed_by, p.reviewed_at, p.created_at
        FROM payments p
        JOIN mydata u ON u.id = p.user_id
        LEFT JOIN plans pl ON pl.id = p.plan_id
        {where}
        ORDER BY p.created_at DESC LIMIT %s OFFSET %s
    """, params, fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "payments": rows[:limit]}


@router.get("/admin/payments/{payment_id}")
async def admin_get_payment(payment_id: int, actor: dict = Depends(get_actor)):
    _need_admin(actor)
    row = get_one("""
        SELECT p.*, u.name AS user_name, u.email AS user_email,
               pl.name AS plan_name, pl.duration_days
        FROM payments p
        JOIN mydata u ON u.id = p.user_id
        LEFT JOIN plans pl ON pl.id = p.plan_id
        WHERE p.id = %s
    """, (payment_id,))
    if not row:
        raise HTTPException(404, "Payment not found")
    return {"success": True, "payment": row}


@router.post("/admin/payments/{payment_id}/review")
async def admin_review_payment(payment_id: int, body: PaymentReviewIn,
                               actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action must be approve or reject")

    p = get_one("""
        SELECT p.*, pl.duration_days
        FROM payments p LEFT JOIN plans pl ON pl.id = p.plan_id
        WHERE p.id = %s
    """, (payment_id,))
    if not p:
        raise HTTPException(404, "Payment not found")
    if p["status"] != "pending":
        return {"success": False, "message": f"Payment already {p['status']}"}

    note = (body.admin_note or "").strip()[:1000]

    if body.action == "approve":
        get_one("UPDATE mydata SET is_premium = true WHERE id = %s RETURNING id",
                (p["user_id"],))
        get_one("""
            UPDATE payments SET status='approved', admin_note=%s,
                                reviewed_by=%s, reviewed_at=now()
            WHERE id = %s RETURNING id
        """, (note, actor["user_id"], payment_id))

        try:
            await notify(p["user_id"], "payment_approved", actor["user_id"])
            await manager.push(p["user_id"], {
                "type": "payment_status",
                "payment_id": payment_id,
                "status": "approved",
            })
        except Exception:
            logger.exception("notify payment approved")

        return {"success": True, "message": "Payment approved, user is now premium"}

    get_one("""
        UPDATE payments SET status='rejected', admin_note=%s,
                            reviewed_by=%s, reviewed_at=now()
        WHERE id = %s RETURNING id
    """, (note, actor["user_id"], payment_id))

    try:
        await notify(p["user_id"], "payment_rejected", actor["user_id"])
        await manager.push(p["user_id"], {
            "type": "payment_status",
            "payment_id": payment_id,
            "status": "rejected",
            "admin_note": note,
        })
    except Exception:
        logger.exception("notify payment rejected")

    return {"success": True, "message": "Payment rejected"}


@router.get("/admin/support/threads")
async def admin_list_threads(status: str = "open", limit: int = 40, offset: int = 0,
                             actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if status not in ("open", "closed", "all"):
        raise HTTPException(400, "Invalid status")
    limit = max(1, min(limit, 100))
    where = "" if status == "all" else "WHERE t.status = %s"
    params = (limit + 1, max(0, offset)) if status == "all" else (status, limit + 1, max(0, offset))
    rows = execute_query(f"""
        SELECT t.id, t.user_id, u.name AS user_name, u.email AS user_email,
               t.subject, t.status, t.priority,
               t.unread_admin, t.unread_user,
               t.last_message_at, t.created_at,
               (SELECT content FROM support_messages m
                WHERE m.thread_id = t.id ORDER BY m.created_at DESC LIMIT 1) AS last_message
        FROM support_threads t
        JOIN mydata u ON u.id = t.user_id
        {where}
        ORDER BY t.unread_admin DESC, t.last_message_at DESC
        LIMIT %s OFFSET %s
    """, params, fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "threads": rows[:limit]}


@router.get("/admin/support/threads/{thread_id}")
async def admin_get_thread(thread_id: int, actor: dict = Depends(get_actor)):
    _need_admin(actor)
    t = get_one("""
        SELECT t.*, u.name AS user_name, u.email AS user_email, u.is_premium
        FROM support_threads t JOIN mydata u ON u.id = t.user_id
        WHERE t.id = %s
    """, (thread_id,))
    if not t:
        raise HTTPException(404, "Thread not found")
    msgs = execute_query("""
        SELECT m.id, m.sender_id, m.is_admin, m.content, m.attachment, m.created_at,
               COALESCE(c.channel_name, u.name) AS sender_name,
               COALESCE(c.avatar_url, u.avatar_url) AS sender_avatar
        FROM support_messages m
        JOIN mydata u ON u.id = m.sender_id
        LEFT JOIN channels c ON c.user_id = u.id
        WHERE m.thread_id = %s ORDER BY m.created_at ASC LIMIT 500
    """, (thread_id,), fetch=True) or []
    get_one("UPDATE support_threads SET unread_admin = 0 WHERE id = %s RETURNING id",
            (thread_id,))
    get_one("""
        UPDATE support_messages SET is_read = true
        WHERE thread_id = %s AND is_admin = false AND is_read = false RETURNING id
    """, (thread_id,))
    return {"success": True, "thread": t, "messages": msgs}


@router.post("/admin/support/threads/{thread_id}/reply")
async def admin_thread_reply(thread_id: int, body: SupportMessageIn,
                             actor: dict = Depends(get_actor)):
    _need_admin(actor)
    t = get_one("SELECT id, user_id, status FROM support_threads WHERE id = %s",
                (thread_id,))
    if not t:
        raise HTTPException(404, "Thread not found")
    if t["status"] == "closed":
        return {"success": False, "message": "Thread is closed"}

    content = (body.content or "").strip()
    if not (1 <= len(content) <= 2000):
        return {"success": False, "message": "Message must be 1-2000 characters"}
    att = (body.attachment or "").strip()
    if att and not att.startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Attachment must be Cloudinary URL"}

    m = get_one("""
        INSERT INTO support_messages (thread_id, sender_id, is_admin, content, attachment)
        VALUES (%s, %s, true, %s, %s)
        RETURNING id, thread_id, sender_id, is_admin, content, attachment, created_at
    """, (thread_id, actor["user_id"], content, att or None))

    get_one("""
        UPDATE support_threads SET last_message_at = now(), unread_user = unread_user + 1
        WHERE id = %s RETURNING id
    """, (thread_id,))

    try:
        await notify(t["user_id"], "support_reply", actor["user_id"])
        await manager.push(t["user_id"], {
            "type": "support_message",
            "thread_id": thread_id,
            "admin_message": content[:120],
        })
    except Exception:
        logger.exception("notify admin reply")

    return {"success": True, "message": m}


@router.post("/admin/support/threads/{thread_id}/status")
async def admin_thread_status(thread_id: int, body: SupportStatusIn,
                              actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if body.status not in ("open", "closed"):
        raise HTTPException(400, "Invalid status")
    prio = body.priority
    if prio is not None and prio not in ("low", "normal", "high"):
        raise HTTPException(400, "Invalid priority")

    fields = {"status": body.status}
    if prio:
        fields["priority"] = prio

    sets = ", ".join(f"{k} = %s" for k in fields)
    row = get_one(f"""
        UPDATE support_threads SET {sets} WHERE id = %s
        RETURNING id, status, priority
    """, (*fields.values(), thread_id))
    if not row:
        raise HTTPException(404, "Thread not found")
    return {"success": True, "thread": row}


@router.get("/admin/users")
async def admin_list_users(q: str = "", limit: int = 30, offset: int = 0,
                           actor: dict = Depends(get_actor)):
    _need_admin(actor)
    limit = max(1, min(limit, 100))
    like = f"%{q.strip()}%" if q.strip() else None
    rows = execute_query("""
        SELECT u.id, u.name, u.email, u.is_premium, u.created_at,
               (SELECT COUNT(*) FROM payments WHERE user_id = u.id AND status='pending') AS pending_payments,
               (SELECT COUNT(*) FROM support_threads WHERE user_id = u.id AND status='open') AS open_threads
        FROM mydata u
        WHERE (%s::text IS NULL OR u.name ILIKE %s OR u.email ILIKE %s)
        ORDER BY u.id DESC LIMIT %s OFFSET %s
    """, (like, like, like, limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "users": rows[:limit]}


@router.post("/admin/users/{user_id}/toggle-premium")
async def admin_toggle_premium(user_id: int, actor: dict = Depends(get_actor)):
    _need_admin(actor)
    u = get_one("SELECT id, is_premium FROM mydata WHERE id = %s", (user_id,))
    if not u:
        raise HTTPException(404, "User not found")
    new_val = not u["is_premium"]
    get_one("UPDATE mydata SET is_premium = %s WHERE id = %s RETURNING id",
            (new_val, user_id))
    return {"success": True, "user_id": user_id, "is_premium": new_val}


class PlanEditIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price_pkr: Optional[float] = None
    price_usd: Optional[float] = None
    duration_days: Optional[int] = None
    features: Optional[list] = None
    is_active: Optional[bool] = None
    sort_order: Optional[int] = None


@router.get("/admin/plans")
async def admin_list_plans(actor: dict = Depends(get_actor)):
    _need_admin(actor)
    rows = execute_query("SELECT * FROM plans ORDER BY sort_order, id", fetch=True) or []
    return {"success": True, "plans": rows}


@router.put("/admin/plans/{plan_id}")
async def admin_edit_plan(plan_id: int, body: PlanEditIn,
                          actor: dict = Depends(get_actor)):
    _need_admin(actor)
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        return {"success": False, "message": "Nothing to update"}
    if "features" in fields:
        import json as _json
        fields["features"] = _json.dumps(fields["features"])
        row = get_one(f"""
            UPDATE plans SET {", ".join(f"{k} = %s" for k in fields)},
                             updated_at = now(),
                             features = %s::jsonb
            WHERE id = %s RETURNING *
        """, (*[v for k, v in fields.items() if k != "features"],
              fields["features"], plan_id))
    else:
        sets = ", ".join(f"{k} = %s" for k in fields)
        row = get_one(f"""
            UPDATE plans SET {sets}, updated_at = now()
            WHERE id = %s RETURNING *
        """, (*fields.values(), plan_id))
    if not row:
        raise HTTPException(404, "Plan not found")
    return {"success": True, "plan": row}


class AdPricingEditIn(BaseModel):
    price_pkr: Optional[float] = None
    price_usd: Optional[float] = None
    min_budget: Optional[float] = None
    is_active: Optional[bool] = None


@router.put("/admin/ad-pricing/{model}")
async def admin_edit_ad_pricing(model: str, body: AdPricingEditIn,
                                actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if model not in ("cpm", "cpc"):
        raise HTTPException(400, "model must be cpm or cpc")
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        return {"success": False, "message": "Nothing to update"}
    sets = ", ".join(f"{k} = %s" for k in fields)
    row = get_one(f"""
        UPDATE ad_pricing SET {sets}, updated_at = now()
        WHERE model = %s RETURNING *
    """, (*fields.values(), model))
    if not row:
        raise HTTPException(404, "Pricing not found")
    return {"success": True, "pricing": row}


# =====================================================================
#  AD CENTER — MODELS + HELPERS
# =====================================================================
from decimal import Decimal as _Dec


class AdCampaignCreateIn(BaseModel):
    name: str
    model: str
    budget_total: float
    budget_daily: Optional[float] = 0
    target_categories: Optional[List[str]] = []
    target_tags: Optional[List[int]] = []
    starts_at: Optional[str] = None
    ends_at: Optional[str] = None


class AdCampaignUpdateIn(BaseModel):
    name: Optional[str] = None
    budget_total: Optional[float] = None
    budget_daily: Optional[float] = None
    target_categories: Optional[List[str]] = None
    target_tags: Optional[List[int]] = None
    starts_at: Optional[str] = None
    ends_at: Optional[str] = None


class AdCreativeIn(BaseModel):
    type: str
    url: str
    thumbnail: Optional[str] = None
    title: str
    description: Optional[str] = ""
    cta_text: Optional[str] = "Learn More"
    destination_url: str


class AdTopupSubmitIn(BaseModel):
    amount: float
    method: str
    transaction_id: str
    sender_name: Optional[str] = None
    sender_account: Optional[str] = None
    screenshot_url: Optional[str] = None
    user_note: Optional[str] = ""


class AdReviewIn(BaseModel):
    action: str
    admin_note: Optional[str] = ""


class AdWalletAdjustIn(BaseModel):
    user_id: int
    amount: float
    note: Optional[str] = ""


def _ad_get_wallet(uid: int) -> dict:
    w = get_one("SELECT * FROM ad_wallets WHERE user_id = %s", (uid,))
    if not w:
        w = get_one("""
            INSERT INTO ad_wallets (user_id, balance, total_spent, total_added)
            VALUES (%s, 0, 0, 0) RETURNING *
        """, (uid,))
    return w


def _ad_tx(uid: int, kind: str, amount: float, ref: str = None, note: str = ""):
    amt = _Dec(str(amount))
    w = _ad_get_wallet(uid)
    new_balance = _Dec(str(w["balance"])) + amt
    if new_balance < 0:
        new_balance = _Dec("0")

    if amt > 0:
        get_one("""
            UPDATE ad_wallets
            SET balance = balance + %s, total_added = total_added + %s, updated_at = now()
            WHERE user_id = %s RETURNING user_id
        """, (float(amt), float(amt), uid))
    else:
        get_one("""
            UPDATE ad_wallets
            SET balance = balance + %s, total_spent = total_spent + %s, updated_at = now()
            WHERE user_id = %s RETURNING user_id
        """, (float(amt), float(-amt), uid))

    get_one("""
        INSERT INTO ad_transactions (user_id, kind, amount, balance_after, reference, note)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (uid, kind, float(amt), float(new_balance), ref, note))


def _ad_get_rate(model: str) -> Optional[dict]:
    return get_one("""
        SELECT model, price_pkr, price_usd, min_budget
        FROM ad_pricing WHERE model = %s AND is_active = true
    """, (model,))


def _ad_campaign_owned(campaign_id: int, uid: int) -> Optional[dict]:
    return get_one("SELECT * FROM ad_campaigns WHERE id = %s AND user_id = %s",
                   (campaign_id, uid))


# =====================================================================
#  AD CENTER — USER WALLET
# =====================================================================
@router.get("/ads/wallet")
async def ad_wallet(actor: dict = Depends(get_actor)):
    need_verified(actor)
    w = _ad_get_wallet(actor["user_id"])
    return {"success": True, "wallet": w}


@router.get("/ads/wallet/transactions")
async def ad_wallet_tx(limit: int = 20, offset: int = 0,
                       actor: dict = Depends(get_actor)):
    need_verified(actor)
    limit = max(1, min(limit, 50))
    rows = execute_query("""
        SELECT id, kind, amount, balance_after, reference, note, created_at
        FROM ad_transactions WHERE user_id = %s
        ORDER BY created_at DESC LIMIT %s OFFSET %s
    """, (actor["user_id"], limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "transactions": rows[:limit]}


@router.post("/ads/wallet/topup")
async def ad_wallet_topup(body: AdTopupSubmitIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    uid = actor["user_id"]
    if not rate_limit(f"adtopup:{uid}", 5, 3600):
        return {"success": False, "message": "Too many topup requests. Try later."}

    method = (body.method or "").strip().lower()
    if method not in ("jazzcash", "easypaisa", "bank", "crypto", "other"):
        return {"success": False, "message": "Invalid payment method"}
    tid = (body.transaction_id or "").strip()
    if not (4 <= len(tid) <= 120):
        return {"success": False, "message": "Transaction ID must be 4-120 characters"}

    try:
        amount = float(body.amount)
    except Exception:
        return {"success": False, "message": "Invalid amount"}
    if amount < 500 or amount > 10_000_000:
        return {"success": False, "message": "Amount must be between 500 and 10,000,000"}

    ss = (body.screenshot_url or "").strip()
    if ss and not ss.startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Screenshot must be a Cloudinary URL"}

    dup = get_one("""
        SELECT id FROM payments
        WHERE method = %s AND transaction_id = %s AND status <> 'rejected'
    """, (method, tid))
    if dup:
        return {"success": False, "message": "This transaction ID is already submitted"}

    pend = get_one("""
        SELECT COUNT(*) AS n FROM payments
        WHERE user_id = %s AND status = 'pending' AND purpose = 'ad_topup'
    """, (uid,))
    if pend and pend["n"] >= 3:
        return {"success": False, "message": "You have 3 pending top-ups."}

    row = get_one("""
        INSERT INTO payments
            (user_id, plan_id, amount, currency, method, transaction_id,
             sender_name, sender_account, screenshot_url, user_note, purpose)
        VALUES (%s, NULL, %s, %s, %s, %s, %s, %s, %s, %s, 'ad_topup')
        RETURNING id, user_id, amount, currency, method, transaction_id, status, purpose, created_at
    """, (
        uid, amount, "PKR", method, tid,
        (body.sender_name or "").strip()[:120] or None,
        (body.sender_account or "").strip()[:120] or None,
        ss or None,
        (body.user_note or "").strip()[:500],
    ))

    try:
        for admin_id in ADMIN_USER_IDS:
            await notify(admin_id, "ad_topup_submitted", uid)
    except Exception:
        logger.exception("notify ad_topup")

    return {"success": True, "message": "Top-up submitted. Admin will verify soon.",
            "payment": row}


# =====================================================================
#  AD CENTER — USER CAMPAIGNS
# =====================================================================
@router.post("/ads/campaigns")
async def ad_campaign_create(body: AdCampaignCreateIn, actor: dict = Depends(get_actor)):
    need_verified(actor)
    uid = actor["user_id"]
    if not rate_limit(f"adcamp:{uid}", 10, 3600):
        return {"success": False, "message": "Too many campaigns. Try later."}

    name = (body.name or "").strip()
    if not (2 <= len(name) <= 150):
        return {"success": False, "message": "Name must be 2-150 characters"}
    model = (body.model or "").strip().lower()
    if model not in ("cpm", "cpc"):
        return {"success": False, "message": "model must be cpm or cpc"}

    rate = _ad_get_rate(model)
    if not rate:
        return {"success": False, "message": "Pricing not available"}

    try:
        budget_total = float(body.budget_total)
        budget_daily = float(body.budget_daily or 0)
    except Exception:
        return {"success": False, "message": "Invalid budget"}

    min_budget = float(rate["min_budget"] or 500)
    if budget_total < min_budget:
        return {"success": False, "message": f"Minimum budget is Rs. {min_budget:.0f}"}
    if budget_daily < 0 or (budget_daily and budget_daily > budget_total):
        return {"success": False, "message": "Daily budget invalid"}

    w = _ad_get_wallet(uid)
    if float(w["balance"]) < budget_total:
        return {"success": False,
                "message": f"Insufficient wallet. Need Rs. {budget_total:.0f}, have Rs. {float(w['balance']):.0f}"}

    cats = [c.strip() for c in (body.target_categories or []) if c.strip()][:20]
    tags = [int(t) for t in (body.target_tags or [])][:30]

    row = get_one("""
        INSERT INTO ad_campaigns
            (user_id, name, model, rate_pkr, budget_total, budget_daily,
             target_categories, target_tags, starts_at, ends_at, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'draft')
        RETURNING *
    """, (
        uid, name, model, float(rate["price_pkr"]), budget_total, budget_daily,
        cats, tags,
        body.starts_at or None, body.ends_at or None,
    ))
    return {"success": True, "campaign": row}


@router.get("/ads/campaigns/my")
async def ad_campaigns_my(limit: int = 50, offset: int = 0,
                          actor: dict = Depends(get_actor)):
    need_verified(actor)
    limit = max(1, min(limit, 100))
    rows = execute_query("""
        SELECT c.*,
               (SELECT COUNT(*) FROM ad_creatives cr WHERE cr.campaign_id = c.id) AS creative_count
        FROM ad_campaigns c
        WHERE c.user_id = %s
        ORDER BY c.created_at DESC LIMIT %s OFFSET %s
    """, (actor["user_id"], limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "campaigns": rows[:limit]}


@router.get("/ads/campaigns/{campaign_id}")
async def ad_campaign_get(campaign_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    crs = execute_query("SELECT * FROM ad_creatives WHERE campaign_id = %s ORDER BY id",
                        (campaign_id,), fetch=True) or []
    return {"success": True, "campaign": c, "creatives": crs}


@router.put("/ads/campaigns/{campaign_id}")
async def ad_campaign_update(campaign_id: int, body: AdCampaignUpdateIn,
                             actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] in ("active", "completed"):
        return {"success": False, "message": f"Cannot edit a {c['status']} campaign"}

    fields = {}
    if body.name is not None:
        n = body.name.strip()
        if not (2 <= len(n) <= 150):
            return {"success": False, "message": "Name must be 2-150 characters"}
        fields["name"] = n
    if body.budget_total is not None:
        bt = float(body.budget_total)
        if bt < float(c["spend_total"]):
            return {"success": False, "message": "Budget cannot be less than spent"}
        w = _ad_get_wallet(actor["user_id"])
        if float(w["balance"]) < bt:
            return {"success": False, "message": "Insufficient wallet balance"}
        fields["budget_total"] = bt
    if body.budget_daily is not None:
        fields["budget_daily"] = float(body.budget_daily or 0)
    if body.target_categories is not None:
        fields["target_categories"] = [x.strip() for x in body.target_categories if x.strip()][:20]
    if body.target_tags is not None:
        fields["target_tags"] = [int(t) for t in body.target_tags][:30]
    if body.starts_at is not None:
        fields["starts_at"] = body.starts_at or None
    if body.ends_at is not None:
        fields["ends_at"] = body.ends_at or None

    if not fields:
        return {"success": False, "message": "Nothing to update"}
    sets = ", ".join(f"{k} = %s" for k in fields)
    row = get_one(f"""
        UPDATE ad_campaigns SET {sets}, updated_at = now()
        WHERE id = %s RETURNING *
    """, (*fields.values(), campaign_id))
    return {"success": True, "campaign": row}


@router.delete("/ads/campaigns/{campaign_id}")
async def ad_campaign_delete(campaign_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] == "active":
        return {"success": False, "message": "Pause the campaign before deleting"}
    get_one("DELETE FROM ad_campaigns WHERE id = %s RETURNING id", (campaign_id,))
    return {"success": True}


@router.post("/ads/campaigns/{campaign_id}/submit")
async def ad_campaign_submit(campaign_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] != "draft":
        return {"success": False, "message": f"Only draft campaigns can be submitted (current: {c['status']})"}

    n = get_one("SELECT COUNT(*) AS n FROM ad_creatives WHERE campaign_id = %s", (campaign_id,))
    if not n or n["n"] < 1:
        return {"success": False, "message": "Add at least one creative before submitting"}

    w = _ad_get_wallet(actor["user_id"])
    if float(w["balance"]) < float(c["budget_total"]):
        return {"success": False, "message": "Insufficient wallet balance for this budget"}

    row = get_one("""
        UPDATE ad_campaigns SET status = 'pending', updated_at = now()
        WHERE id = %s RETURNING *
    """, (campaign_id,))

    try:
        for admin_id in ADMIN_USER_IDS:
            await notify(admin_id, "ad_campaign_submitted", actor["user_id"])
    except Exception:
        logger.exception("notify ad campaign submit")

    return {"success": True, "campaign": row}


@router.post("/ads/campaigns/{campaign_id}/pause")
async def ad_campaign_pause(campaign_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] != "active":
        return {"success": False, "message": f"Only active campaigns can be paused (current: {c['status']})"}
    row = get_one("""
        UPDATE ad_campaigns SET status = 'paused', updated_at = now()
        WHERE id = %s RETURNING *
    """, (campaign_id,))
    return {"success": True, "campaign": row}


@router.post("/ads/campaigns/{campaign_id}/resume")
async def ad_campaign_resume(campaign_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] != "paused":
        return {"success": False, "message": f"Only paused campaigns can be resumed (current: {c['status']})"}
    w = _ad_get_wallet(actor["user_id"])
    if float(w["balance"]) < float(c["budget_total"]) - float(c["spend_total"]):
        return {"success": False, "message": "Insufficient wallet balance to resume"}
    row = get_one("""
        UPDATE ad_campaigns SET status = 'active', updated_at = now()
        WHERE id = %s RETURNING *
    """, (campaign_id,))
    return {"success": True, "campaign": row}


@router.get("/ads/campaigns/{campaign_id}/stats")
async def ad_campaign_stats(campaign_id: int, days: int = 28,
                            actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")

    days = max(1, min(days, 90))
    totals = get_one("""
        SELECT
          (SELECT COUNT(*) FROM ad_impressions WHERE campaign_id = %s) AS impressions,
          (SELECT COUNT(*) FROM ad_clicks      WHERE campaign_id = %s) AS clicks,
          (SELECT COALESCE(SUM(cost), 0) FROM ad_impressions WHERE campaign_id = %s) AS spend_imp,
          (SELECT COALESCE(SUM(cost), 0) FROM ad_clicks      WHERE campaign_id = %s) AS spend_clk
    """, (campaign_id, campaign_id, campaign_id, campaign_id)) or {}

    imp = int(totals.get("impressions", 0) or 0)
    clk = int(totals.get("clicks", 0) or 0)
    ctr = (clk / imp * 100) if imp > 0 else 0
    spend = float(totals.get("spend_imp", 0) or 0) + float(totals.get("spend_clk", 0) or 0)

    daily = execute_query("""
        SELECT to_char(d, 'Mon DD') AS day,
               COALESCE((SELECT COUNT(*) FROM ad_impressions WHERE campaign_id = %s AND created_at::date = d), 0) AS impressions,
               COALESCE((SELECT COUNT(*) FROM ad_clicks      WHERE campaign_id = %s AND created_at::date = d), 0) AS clicks
        FROM generate_series(CURRENT_DATE - %s + 1, CURRENT_DATE, interval '1 day') d
        ORDER BY d
    """, (campaign_id, campaign_id, days), fetch=True) or []

    return {
        "success": True,
        "totals": {"impressions": imp, "clicks": clk, "ctr": round(ctr, 2), "spend": round(spend, 2)},
        "daily": daily,
    }


# =====================================================================
#  AD CENTER — CREATIVES
# =====================================================================
@router.post("/ads/campaigns/{campaign_id}/creatives")
async def ad_creative_add(campaign_id: int, body: AdCreativeIn,
                          actor: dict = Depends(get_actor)):
    need_verified(actor)
    c = _ad_campaign_owned(campaign_id, actor["user_id"])
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] in ("active", "completed"):
        return {"success": False, "message": f"Cannot add creative to a {c['status']} campaign"}

    if body.type not in ("image", "video"):
        return {"success": False, "message": "type must be image or video"}
    if not body.url or not body.url.startswith("https://res.cloudinary.com/"):
        return {"success": False, "message": "Creative must be a Cloudinary URL"}
    if not body.destination_url or not body.destination_url.startswith(("http://", "https://")):
        return {"success": False, "message": "Destination URL must be http(s)"}
    if not (2 <= len((body.title or "").strip()) <= 150):
        return {"success": False, "message": "Title must be 2-150 characters"}

    row = get_one("""
        INSERT INTO ad_creatives
            (campaign_id, type, url, thumbnail, title, description, cta_text, destination_url)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *
    """, (
        campaign_id, body.type, body.url.strip(), (body.thumbnail or "").strip() or None,
        body.title.strip(), (body.description or "").strip()[:500],
        (body.cta_text or "Learn More").strip()[:40], body.destination_url.strip(),
    ))
    return {"success": True, "creative": row}


@router.delete("/ads/creatives/{creative_id}")
async def ad_creative_delete(creative_id: int, actor: dict = Depends(get_actor)):
    need_verified(actor)
    cr = get_one("""
        SELECT cr.*, c.user_id AS owner_id, c.status AS camp_status
        FROM ad_creatives cr JOIN ad_campaigns c ON c.id = cr.campaign_id
        WHERE cr.id = %s
    """, (creative_id,))
    if not cr or cr["owner_id"] != actor["user_id"]:
        raise HTTPException(404, "Creative not found")
    if cr["camp_status"] in ("active", "completed"):
        return {"success": False, "message": "Cannot delete creative of an active campaign"}
    get_one("DELETE FROM ad_creatives WHERE id = %s RETURNING id", (creative_id,))
    return {"success": True}


# =====================================================================
#  AD CENTER — SERVING
# =====================================================================
def _ad_pick_for_video(video_id: int, video_category: str, video_tags: list):
    rows = execute_query("""
        SELECT c.id AS campaign_id, c.user_id, c.model, c.rate_pkr,
               c.budget_total, c.budget_daily, c.spend_total, c.spend_today,
               c.spend_today_date, c.target_categories, c.target_tags,
               c.starts_at, c.ends_at
        FROM ad_campaigns c
        WHERE c.status = 'active'
          AND (c.starts_at IS NULL OR c.starts_at <= now())
          AND (c.ends_at   IS NULL OR c.ends_at   >= now())
          AND c.spend_total < c.budget_total
          AND (c.budget_daily = 0 OR
               c.spend_today_date <> CURRENT_DATE OR
               c.spend_today < c.budget_daily)
        ORDER BY random()
        LIMIT 20
    """, fetch=True) or []

    cat = (video_category or "").strip().lower()
    tag_set = set(video_tags or [])

    best = None
    best_score = -1
    for r in rows:
        score = 0
        tcats = [c.strip().lower() for c in (r.get("target_categories") or [])]
        ttags = set(r.get("target_tags") or [])

        if tcats:
            if cat and cat in tcats:
                score += 3
            else:
                continue
        if ttags:
            if tag_set & ttags:
                score += 5
            else:
                if not tcats or (cat and cat in tcats):
                    score += 1

        if score > best_score:
            best_score = score
            best = r

    return best


def _ad_pick_creative(campaign_id: int) -> Optional[dict]:
    return get_one("""
        SELECT * FROM ad_creatives WHERE campaign_id = %s
        ORDER BY random() LIMIT 1
    """, (campaign_id,))


def _ad_cost_for(model: str, rate_pkr: float) -> float:
    if model == "cpm":
        return float(_Dec(str(rate_pkr)) / _Dec("1000"))
    return float(rate_pkr)


def _ad_recent_served(creative_id: int, viewer_ip: str, minutes: int = 30) -> bool:
    row = get_one("""
        SELECT 1 FROM ad_impressions
        WHERE creative_id = %s AND viewer_ip = %s
          AND created_at >= now() - (%s || ' minutes')::interval
        LIMIT 1
    """, (creative_id, viewer_ip, str(minutes)))
    return bool(row)


@router.get("/ads/serve")
async def ad_serve(viewkey: str, request: Request, actor: dict = Depends(get_actor)):
    """Video page ke liye ek ad pick karo."""
    v = get_one("""
        SELECT v.id, v.category,
               COALESCE((SELECT array_agg(tag_id) FROM video_tags WHERE video_id = v.id), '{}') AS tags
        FROM videos v WHERE v.viewkey = %s
    """, (viewkey,))
    if not v:
        return {"success": False, "message": "Video not found"}

    camp = _ad_pick_for_video(v["id"], v["category"], v["tags"] or [])
    if not camp:
        return {"success": True, "ad": None}

    cr = _ad_pick_creative(camp["campaign_id"])
    if not cr:
        return {"success": True, "ad": None}

    ip = _ip(request)
    if _ad_recent_served(cr["id"], ip, 30):
        return {"success": True, "ad": None}

    cost = _ad_cost_for(camp["model"], float(camp["rate_pkr"]))

    imp = get_one("""
        INSERT INTO ad_impressions
            (campaign_id, creative_id, video_id, viewer_ip, viewer_id, cost)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (camp["campaign_id"], cr["id"], v["id"], ip, actor["user_id"], cost))

    get_one("""
        UPDATE ad_campaigns
        SET spend_total = spend_total + %s,
            spend_today = CASE WHEN spend_today_date = CURRENT_DATE THEN spend_today + %s ELSE %s END,
            spend_today_date = CURRENT_DATE,
            status = CASE WHEN spend_total + %s >= budget_total THEN 'completed' ELSE status END,
            updated_at = now()
        WHERE id = %s RETURNING id
    """, (cost, cost, cost, cost, camp["campaign_id"]))

    _ad_tx(camp["user_id"], "spend", -cost, ref=f"camp:{camp['campaign_id']}",
           note=f"impression ad:{imp['id']}")

    return {
        "success": True,
        "ad": {
            "impression_id": imp["id"],
            "campaign_id": camp["campaign_id"],
            "creative_id": cr["id"],
            "type": cr["type"],
            "url": cr["url"],
            "thumbnail": cr["thumbnail"],
            "title": cr["title"],
            "description": cr["description"],
            "cta_text": cr["cta_text"],
            "destination_url": cr["destination_url"],
        }
    }


@router.post("/ads/click/{impression_id}")
async def ad_click(impression_id: int, request: Request, actor: dict = Depends(get_actor)):
    imp = get_one("""
        SELECT i.*, c.model, c.rate_pkr, c.user_id, c.destination_url
        FROM ad_impressions i
        JOIN ad_campaigns c ON c.id = i.campaign_id
        WHERE i.id = %s
    """, (impression_id,))
    if not imp:
        raise HTTPException(404, "Impression not found")

    if imp["model"] != "cpc":
        return {"success": True, "destination_url": imp.get("destination_url"), "charged": False}

    cost = _ad_cost_for("cpc", float(imp["rate_pkr"]))

    get_one("""
        INSERT INTO ad_clicks
            (campaign_id, creative_id, impression_id, video_id, viewer_ip, viewer_id, cost)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
    """, (imp["campaign_id"], imp["creative_id"], impression_id, imp["video_id"],
          _ip(request), actor["user_id"], cost))

    get_one("""
        UPDATE ad_campaigns
        SET spend_total = spend_total + %s,
            spend_today = CASE WHEN spend_today_date = CURRENT_DATE THEN spend_today + %s ELSE %s END,
            spend_today_date = CURRENT_DATE,
            status = CASE WHEN spend_total + %s >= budget_total THEN 'completed' ELSE status END,
            updated_at = now()
        WHERE id = %s RETURNING id
    """, (cost, cost, cost, cost, imp["campaign_id"]))

    _ad_tx(imp["user_id"], "spend", -cost, ref=f"camp:{imp['campaign_id']}",
           note=f"click imp:{impression_id}")

    return {"success": True, "destination_url": imp.get("destination_url"), "charged": True}


# =====================================================================
#  AD CENTER — ADMIN
# =====================================================================
@router.get("/admin/ads/campaigns")
async def admin_ad_campaigns(status: str = "all", limit: int = 30, offset: int = 0,
                             actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if status not in ("all", "draft", "pending", "active", "paused", "rejected", "completed"):
        raise HTTPException(400, "Invalid status")
    limit = max(1, min(limit, 100))
    where = "" if status == "all" else "WHERE c.status = %s"
    params = (limit + 1, max(0, offset)) if status == "all" else (status, limit + 1, max(0, offset))
    rows = execute_query(f"""
        SELECT c.*, u.name AS user_name, u.email AS user_email,
               (SELECT COUNT(*) FROM ad_creatives cr WHERE cr.campaign_id = c.id) AS creative_count
        FROM ad_campaigns c
        JOIN mydata u ON u.id = c.user_id
        {where}
        ORDER BY c.created_at DESC LIMIT %s OFFSET %s
    """, params, fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "campaigns": rows[:limit]}


@router.get("/admin/ads/campaigns/{campaign_id}")
async def admin_ad_campaign_get(campaign_id: int, actor: dict = Depends(get_actor)):
    _need_admin(actor)
    c = get_one("""
        SELECT c.*, u.name AS user_name, u.email AS user_email
        FROM ad_campaigns c JOIN mydata u ON u.id = c.user_id
        WHERE c.id = %s
    """, (campaign_id,))
    if not c:
        raise HTTPException(404, "Campaign not found")
    crs = execute_query("SELECT * FROM ad_creatives WHERE campaign_id = %s ORDER BY id",
                        (campaign_id,), fetch=True) or []
    return {"success": True, "campaign": c, "creatives": crs}


@router.post("/admin/ads/campaigns/{campaign_id}/review")
async def admin_ad_campaign_review(campaign_id: int, body: AdReviewIn,
                                   actor: dict = Depends(get_actor)):
    _need_admin(actor)
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action must be approve or reject")

    c = get_one("SELECT * FROM ad_campaigns WHERE id = %s", (campaign_id,))
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c["status"] != "pending":
        return {"success": False, "message": f"Campaign is {c['status']}, not pending"}

    note = (body.admin_note or "").strip()[:1000]

    if body.action == "approve":
        row = get_one("""
            UPDATE ad_campaigns SET status='active', admin_note=%s,
                                    reviewed_by=%s, reviewed_at=now(),
                                    updated_at=now()
            WHERE id = %s RETURNING *
        """, (note, actor["user_id"], campaign_id))
        try:
            await notify(c["user_id"], "ad_campaign_approved", actor["user_id"])
            await manager.push(c["user_id"], {"type": "ad_campaign_status",
                                              "campaign_id": campaign_id, "status": "active"})
        except Exception:
            logger.exception("notify ad approve")
        return {"success": True, "message": "Campaign approved", "campaign": row}

    row = get_one("""
        UPDATE ad_campaigns SET status='rejected', admin_note=%s,
                                reviewed_by=%s, reviewed_at=now(),
                                updated_at=now()
        WHERE id = %s RETURNING *
    """, (note, actor["user_id"], campaign_id))
    try:
        await notify(c["user_id"], "ad_campaign_rejected", actor["user_id"])
        await manager.push(c["user_id"], {"type": "ad_campaign_status",
                                          "campaign_id": campaign_id, "status": "rejected"})
    except Exception:
        logger.exception("notify ad reject")
    return {"success": True, "message": "Campaign rejected", "campaign": row}


@router.get("/admin/ads/revenue")
async def admin_ad_revenue(actor: dict = Depends(get_actor)):
    _need_admin(actor)
    stats = get_one("""
        SELECT
          (SELECT COALESCE(SUM(amount),0) FROM ad_transactions WHERE kind='topup') AS total_topfup,
          (SELECT COALESCE(SUM(-amount),0) FROM ad_transactions WHERE kind='spend') AS total_spend,
          (SELECT COUNT(*) FROM ad_campaigns WHERE status='pending') AS pending_campaigns,
          (SELECT COUNT(*) FROM ad_campaigns WHERE status='active')  AS active_campaigns,
          (SELECT COUNT(*) FROM ad_impressions) AS total_impressions,
          (SELECT COUNT(*) FROM ad_clicks) AS total_clicks
    """)
    return {"success": True, "stats": stats}


@router.post("/admin/ads/wallet/adjust")
async def admin_ad_wallet_adjust(body: AdWalletAdjustIn, actor: dict = Depends(get_actor)):
    _need_admin(actor)
    u = get_one("SELECT id FROM mydata WHERE id = %s", (body.user_id,))
    if not u:
        raise HTTPException(404, "User not found")
    try:
        amount = float(body.amount)
    except Exception:
        raise HTTPException(400, "Invalid amount")
    if amount == 0:
        raise HTTPException(400, "Amount cannot be zero")

    _ad_tx(body.user_id, "adjust", amount, ref=f"admin:{actor['user_id']}",
           note=(body.note or "").strip()[:500])

    w = _ad_get_wallet(body.user_id)
    return {"success": True, "wallet": w}


@router.get("/admin/ads/wallets")
async def admin_ad_wallets(limit: int = 30, offset: int = 0, actor: dict = Depends(get_actor)):
    _need_admin(actor)
    limit = max(1, min(limit, 100))
    rows = execute_query("""
        SELECT w.user_id, u.name AS user_name, u.email AS user_email,
               w.balance, w.total_spent, w.total_added, w.updated_at
        FROM ad_wallets w JOIN mydata u ON u.id = w.user_id
        ORDER BY w.updated_at DESC LIMIT %s OFFSET %s
    """, (limit + 1, max(0, offset)), fetch=True) or []
    return {"success": True, "has_more": len(rows) > limit, "wallets": rows[:limit]}


# =====================================================================
#  ADMIN PANEL HTML
# =====================================================================
@router.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Serve admin panel HTML."""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(current_dir, "static", "admin.html"), "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading admin.html: {e}")
        return "<h1>Admin panel not found. Make sure static/admin.html exists.</h1>"
