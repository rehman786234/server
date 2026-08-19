import secrets
from fastapi import APIRouter, HTTPException, status, Header
from fastapi.responses import HTMLResponse
from typing import Optional
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
    """
    Login endpoint for frontend
    - Checks if credentials are valid
    - Returns user data
    """
    try:
        # Get user by email
        query = "SELECT * FROM mydata WHERE email = %s"
        db_user = get_one(query, (user.email,))
        
        if not db_user:
            return {
                "success": False,
                "message": "Invalid email or password"
            }
        
        # Verify password
        hashed_input = hash_password(user.password)
        if db_user['password'] != hashed_input:
            return {
                "success": False,
                "message": "Invalid email or password"
            }
        
        # Remove password from user data
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
        return {
            "success": False,
            "message": f"Login error: {str(e)}"
        }


@router.post("/register")
async def register(user: UserCreate):
    """
    Register endpoint for frontend
    - Creates a new user account
    - Password is hashed before storage
    - Returns user details
    """
    try:
        # Check if user already exists
        check_query = "SELECT id FROM mydata WHERE email = %s"
        existing_user = get_one(check_query, (user.email,))
        
        if existing_user:
            return {
                "success": False,
                "message": "User with this email already exists"
            }
        
        # Hash password
        hashed_password = hash_password(user.password)
        
        # Insert new user
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
            return {
                "success": True,
                "message": "User registered successfully",
                "user": result
            }
        else:
            return {
                "success": False,
                "message": "Failed to register user"
            }
            
    except Exception as e:
        logger.error(f"Error in register: {e}")
        return {
            "success": False,
            "message": f"Registration error: {str(e)}"
        }


# ============ API KEY MANAGEMENT ENDPOINTS ============

@router.post("/apikey/gen")
async def generate_api_key(request: APIKeyRequest):
    """
    Generate a new API key for a user
    - Requires user_id
    - Creates a permanent API key for external access
    """
    try:
        # Check if user exists
        user_query = "SELECT * FROM mydata WHERE id = %s"
        user_exists = get_one(user_query, (request.user_id,))
        
        if not user_exists:
            return {
                "success": False,
                "message": "User not found"
            }
        
        api_key = secrets.token_hex(16)
        expiry_date = datetime.now() + timedelta(days=30)
        
        # Store API key in database
        query = """
            INSERT INTO apikeys (user_id, api_key, created_at, expiry_date) 
            VALUES (%s, %s, %s, %s) 
            RETURNING id, user_id, api_key, created_at, expiry_date
        """
        result = get_one(query, (request.user_id, api_key, datetime.now(), expiry_date))
        
        if result:
            return {
                "success": True,
                "message": "API Key generated successfully",
                "api_key": result
            }
        else:
            return {
                "success": False,
                "message": "Failed to create API key"
            }
            
    except Exception as e:
        logger.error(f"Error in generate_api_key: {e}")
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }


@router.get("/apikey/list")
async def list_user_apikeys(user_id: int):
    """
    Get all API keys for a specific user
    - Requires user_id as query parameter
    """
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
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }


@router.delete("/apikey/del")
async def delete_apikey(api_key: str):
    """
    Delete/Revoke an API key
    - Requires api_key as query parameter
    """
    try:
        # Check if API key exists
        check_query = "SELECT id FROM apikeys WHERE api_key = %s"
        existing_key = get_one(check_query, (api_key,))
        
        if not existing_key:
            return {
                "success": False,
                "message": "API key not found"
            }
        
        # Delete the API key
        query = "DELETE FROM apikeys WHERE api_key = %s RETURNING id"
        result = get_one(query, (api_key,))
        
        if result:
            return {
                "success": True,
                "message": "API key deleted successfully"
            }
        else:
            return {
                "success": False,
                "message": "Failed to delete API key"
            }
            
    except Exception as e:
        logger.error(f"Error in delete_apikey: {e}")
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }


# ============ VIDEOS ENDPOINTS ============

@router.get("/videos")
async def get_videos():
    """
    Get all free videos (is_premium = false)
    - No API key required
    - Returns direct array (old format)
    """
    try:
        query = """
            SELECT * FROM videos 
            WHERE is_premium = false 
            ORDER BY uploaded_at DESC
        """
        results = execute_query(query, fetch=True)
        
        # Return direct array (old format)
        return results if results else []
        
    except Exception as e:
        logger.error(f"Error in get_videos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.get("/premium_videos")
async def get_premium_videos(api_key: str = Header(...)):
    """
    Get all premium videos (is_premium = true)
    - Requires API key
    """
    # Validate API key
    user_data = validate_api_key(api_key)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )
    
    try:
        query = """
            SELECT * FROM videos 
            WHERE is_premium = true 
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
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }


@router.post("/upload_videos")
async def upload_video(video: Video, api_key: str = Header(...)):
    """
    Upload a new video
    - Requires API key
    - Returns the uploaded video object
    """
    # Validate API key
    user_data = validate_api_key(api_key)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )
    
    viewkey = secrets.token_hex(6)
    
    try:
        query = """
            INSERT INTO videos (title, stream_link, viewkey, thumbnail, category, is_premium) 
            VALUES (%s, %s, %s, %s, %s, %s) 
            RETURNING id, title, stream_link, viewkey, thumbnail, category, is_premium, uploaded_at
        """
        result = get_one(
            query, 
            (video.title, video.stream_link, viewkey, video.thumbnail, video.category, video.is_premium)
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
            return {
                "success": False,
                "message": "Failed to upload video"
            }
            
    except Exception as e:
        logger.error(f"Error in upload_video: {e}")
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            return {
                "success": False,
                "message": "Video with this viewkey already exists"
            }
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }


@router.get("/videos/{viewkey}")
async def get_video_by_key(viewkey: str):
    """
    Get a video by its viewkey
    - No API key required for free videos
    """
    try:
        query = "SELECT * FROM videos WHERE viewkey = %s"
        result = get_one(query, (viewkey,))
        
        if result:
            return {
                "success": True,
                "video": result
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Video not found"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_video_by_key: {e}")
        return {
            "success": False,
            "message": f"Database error: {str(e)}"
        }


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
