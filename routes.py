import secrets
from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any
import logging

from database import execute_query, get_one, get_connection, get_cursor
from models import User, Video, UserCreate, VideoResponse, APIKeyResponse, ErrorResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
async def home():
    """Root endpoint"""
    return {"message": "FastAPI Server Running Successfully"}


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


@router.get("/apikey")
async def generate_api_key():
    """Generate a new API key"""
    return {"ApiKey": secrets.token_hex(16)}


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


@router.get("/videos")
async def get_videos():
    """Get all videos"""
    try:
        query = "SELECT * FROM videos ORDER BY uploaded_at DESC"
        results = execute_query(query, fetch=True)
        return results if results else []
        
    except Exception as e:
        logger.error(f"Error in get_videos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.post("/upload_videos")
async def upload_video(video: Video):
    """Upload a new video"""
    viewkey = secrets.token_hex(6)
    
    try:
        query = """
            INSERT INTO videos (title, stream_link, viewkey, thumbnail) 
            VALUES (%s, %s, %s, %s) 
            RETURNING id, title, stream_link, viewkey, thumbnail, uploaded_at
        """
        result = get_one(query, (video.title, video.stream_link, viewkey, video.thumbnail))
        
        if result:
            return {
                "message": "Video Upload Success",
                "viewkey": viewkey,
                "video": result
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
        "timestamp": __import__('datetime').datetime.now().isoformat()
    }
