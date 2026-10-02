import secrets
import hmac
import base64
import json
import hashlib
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import (APIRouter, HTTPException, status, Header, Request, Depends,
                     WebSocket, WebSocketDisconnect)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from database import execute_query, get_one
from models import User, UserCreate, UserLogin, APIKeyRequest, Video

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
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_api_key(api_key: str, endpoint: str = None, method: str = "GET"):
    """Validate API key, return user data. If endpoint is given, the call is logged."""
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
    """Save one API call for analytics. Never breaks the main request."""
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
        ip = request.client.host if request.client else "?"
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
async def register(user: UserCreate):
    try:
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


# ---------------------------------------------------------------------
#  FIX 3: PUT /profile/update  aur  PUT /profile/password
#  Legacy-safe (current password verify), ApiDashboard.jsx in dono ko call karta hai.
# ---------------------------------------------------------------------
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
    """Password sahi ho to user row, warna None. Brute-force guard ke saath."""
    ip = request.client.host if request.client else "?"
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
#  CLOUDINARY (2nd account) - signed upload
# =====================================================================
UPLOAD_PURPOSES = {
    "avatar":   {"folder": "profiles", "type": "image", "formats": "jpg,jpeg,png,webp", "admin": False},
    "channel":  {"folder": "channels", "type": "image", "formats": "jpg,jpeg,png,webp", "admin": False},
    "banner":   {"folder": "banners",  "type": "image", "formats": "jpg,jpeg,png,webp", "admin": False},
    "ad_image": {"folder": "ads",      "type": "image", "formats": "jpg,jpeg,png,webp,gif", "admin": True},
    "ad_video": {"folder": "ads",      "type": "video", "formats": "mp4,webm,mov", "admin": True},
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
#  ADMIN: ADS
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
    """Token wala user sirf apni hi id use kar sakta hai. Legacy mode me purana behaviour."""
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
        # FIX 1: request_count aur last_used_at bhi bhejein taake frontend me
        # "Total requests" aur "Last used" sahi dikhein.
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


# ---------------------------------------------------------------------
#  FIX 2: GET /analytics  (Developer Console > Analytics tab)
#  Response shape wahi jo ApiDashboard.jsx expect karta hai.
# ---------------------------------------------------------------------
@router.get("/analytics")
async def api_analytics(api_key: str = Header(...)):
    k = validate_api_key(api_key)          # endpoint nahi diya => ye call khud count nahi hoti
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
    """Free PUBLIC videos. No login needed. FIX 6: channel info bhi aati hai."""
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
    """Premium PUBLIC videos - valid API key + ACTIVE premium account zaroori. FIX 6: channel info."""
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
    """Old upload endpoint (API key)."""
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
    """Single video. FIX 5: is_own_channel bhi bhejta hai."""
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

        # FIX 5: apna hi video ho to frontend Subscribe button chupa sake
        row["is_own_channel"] = bool(actor["user_id"] and actor["user_id"] == row.get("user_id"))

        return {"success": True, "video": row}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_video_by_key: {e}")
        return {"success": False, "message": "Database error"}


@router.post("/videos/{viewkey}/like")
async def toggle_video_like(viewkey: str, actor: dict = Depends(get_actor)):
    """Video like / unlike. Login zaroori."""
    need_login(actor)
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
#  PLAYLISTS
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


@router.get("/playlists/{playlist_id}")
async def get_playlist(playlist_id: int, actor: dict = Depends(get_actor)):
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
    """Random ads: 2 image + 1 video. No login needed."""
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
    ip = request.client.host if request.client else "unknown"
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


# ---------------------------------------------------------------------
#  Studio Analytics: internal helper (dono /studio/analytics aur /studio/init use karte hain)
# ---------------------------------------------------------------------
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
    u = current_user(api_key)               # tracking off: dashboard baar baar refresh hota hai
    a = _analytics_for(u["user_id"])
    if a:
        return {"success": True, "analytics": a}
    return {"success": False, "message": "Could not load analytics"}


# ---------------------------------------------------------------------
#  FIX 4: /studio/init — dashboard ke liye sirf EK request (4 ki jagah)
# ---------------------------------------------------------------------
@router.get("/studio/init")
async def studio_init(api_key: str = Header(...)):
    u = current_user(api_key)               # tracking off
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
@router.get("/channels/{handle}")
async def get_channel(handle: str, actor: dict = Depends(get_actor)):
    """Public channel page data. FIX 5: is_own bhi bhejta hai."""
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
    # FIX 5: apna channel ho to Subscribe button chupa sake
    row["is_own"] = bool(actor["user_id"] and actor["user_id"] == row["user_id"])
    return {"success": True, "channel": row}


@router.get("/channels/{handle}/videos")
async def get_channel_videos(handle: str, sort: str = "latest", limit: int = 20, offset: int = 0,
                             actor: dict = Depends(get_actor)):
    """Channel ki videos. Free user ko premium videos nahi milti."""
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
    """Subscribers ki list sirf channel owner dekh sakta hai (token zaroori)."""
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
    """Subscribed channels ki latest videos (premium sirf premium user ko)."""
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
    get_one("""UPDATE notifications SET is_read = true
               WHERE user_id = %s AND (%s::int[] IS NULL OR id = ANY(%s::int[])) RETURNING id""",
            (actor["user_id"], body.ids, body.ids))
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
