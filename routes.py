import secrets
from fastapi import APIRouter, HTTPException, status, Header
from fastapi.responses import HTMLResponse
from typing import List, Dict, Any
import logging
from datetime import datetime
import os

from database import execute_query, get_one
from models import User, Video, UserCreate, APIKeyRequest

logger = logging.getLogger(__name__)
router = APIRouter()

# Helper function to validate API key
def validate_api_key(api_key: str):
    """Validate API key and return user data if valid"""
    try:
        query = """
            SELECT a.*, u.id as user_id, u.name, u.email 
            FROM apikeys a
            JOIN mydata u ON a.user_id = u.id
            WHERE a.api_key = %s
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
        # Get the directory where routes.py is located
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


@router.get("/get_users")
async def get_users():
    """Get all users"""
    try:
        query = "SELECT * FROM mydata ORDER BY id"
        results = execute_query(query, fetch=True)
        
        if not results:
            return {"message": "No Users Found"}
        
        return results
        
    except Exception as e:
        logger.error(f"Error in get_users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.post("/users")
async def create_user(user: UserCreate):
    """Create a new user"""
    try:
        query = """
            INSERT INTO mydata (name, email, password) 
            VALUES (%s, %s, %s) 
            RETURNING id, name, email, created_at
        """
        result = get_one(query, (user.name, user.email, user.password))
        
        if result:
            return {"message": "User Added Successfully", "user": result}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
            
    except Exception as e:
        logger.error(f"Error in create_user: {e}")
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.post("/apikey")
async def generate_api_key(user: APIKeyRequest):
    """Generate a new API key for a user and store in database"""
    try:
        # Check if user exists
        user_query = "SELECT * FROM mydata WHERE id = %s"
        user_exists = get_one(user_query, (user.user_id,))
        
        if not user_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        api_key = secrets.token_hex(16)
        
        # Store API key in database
        query = """
            INSERT INTO apikeys (user_id, api_key) 
            VALUES (%s, %s) 
            RETURNING id, user_id, api_key, created_at
        """
        result = get_one(query, (user.user_id, api_key))
        
        if result:
            return {
                "message": "API Key generated successfully",
                "api_key": result
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create API key"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in generate_api_key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.post("/user_apikeys")
async def get_user_apikeys(user: User):
    """Get all API keys for a specific user"""
    try:
        query = "SELECT * FROM apikeys WHERE user_id = %s ORDER BY created_at DESC"
        results = execute_query(query, (user.id,), fetch=True)
        return results if results else []
        
    except Exception as e:
        logger.error(f"Error in get_user_apikeys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.post("/user_apikeys/create")
async def create_user_apikey(user: User):
    """Create a new API key for a user"""
    try:
        api_key = secrets.token_hex(16)
        query = """
            INSERT INTO apikeys (user_id, api_key) 
            VALUES (%s, %s) 
            RETURNING id, user_id, api_key, created_at
        """
        result = get_one(query, (user.id, api_key))
        
        if result:
            return {"message": "API Key created", "apikey": result}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create API key"
            )
            
    except Exception as e:
        logger.error(f"Error in create_user_apikey: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.delete("/apikey")
async def delete_apikey(api_key: str):
    """Delete an API key"""
    try:
        query = "DELETE FROM apikeys WHERE api_key = %s RETURNING id"
        result = get_one(query, (api_key,))
        
        if result:
            return {"message": "API key deleted successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in delete_apikey: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.get("/videos")
async def get_videos():
    """Get all non-premium videos only (no API key required)"""
    try:
        query = """
            SELECT * FROM videos 
            WHERE is_premium = false 
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
    """Get all premium videos (requires API key)"""
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
                "email": user_data['email']
            }
        }
        
    except Exception as e:
        logger.error(f"Error in get_premium_videos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.get("/all_videos")
async def get_all_videos():
    """Get all videos (both premium and non-premium) - no API key required"""
    try:
        query = "SELECT * FROM videos ORDER BY uploaded_at DESC"
        results = execute_query(query, fetch=True)
        return results if results else []
        
    except Exception as e:
        logger.error(f"Error in get_all_videos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.post("/upload_videos")
async def upload_video(video: Video, api_key: str = Header(...)):
    """Upload a new video (requires API key)"""
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
                "message": "Video Upload Success",
                "viewkey": viewkey,
                "video": result,
                "uploaded_by": user_data.get('name', 'Unknown'),
                "user_id": user_data.get('user_id')
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to upload video"
            )
            
    except Exception as e:
        logger.error(f"Error in upload_video: {e}")
        if "unique constraint" in str(e).lower() or "duplicate key" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Video with this viewkey already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.get("/videos/{viewkey}")
async def get_video_by_key(viewkey: str):
    """Get a video by its viewkey"""
    try:
        query = "SELECT * FROM videos WHERE viewkey = %s"
        result = get_one(query, (viewkey,))
        
        if result:
            return result
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Video not found"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_video_by_key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
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
