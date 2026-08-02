from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class User(BaseModel):
    id: int
    name: str
    email: str
    is_premium: bool
    created_at: Optional[datetime] = None


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    is_premium: Optional[bool] = False


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    is_premium: bool
    created_at: Optional[datetime] = None


class APIKeyRequest(BaseModel):
    user_id: int


class APIKeyResponse(BaseModel):
    id: int
    user_id: int
    api_key: str
    created_at: datetime
    expiry_date: datetime


class Video(BaseModel):
    title: str
    stream_link: str
    thumbnail: Optional[str] = None
    category: Optional[str] = None
    is_premium: bool = False


class VideoResponse(BaseModel):
    id: int
    title: str
    stream_link: str
    viewkey: str
    thumbnail: Optional[str] = None
    category: Optional[str] = None
    is_premium: bool
    uploaded_at: datetime


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None


class LoginResponse(BaseModel):
    success: bool
    message: str
    user: Optional[UserResponse] = None
    api_key: Optional[str] = None
    expires_in: Optional[str] = None


class RegisterResponse(BaseModel):
    success: bool
    message: str
    user: Optional[UserResponse] = None


class APIKeyGenerateResponse(BaseModel):
    success: bool
    message: str
    api_key: Optional[APIKeyResponse] = None


class APIKeyListResponse(BaseModel):
    success: bool
    total: int
    api_keys: list[APIKeyResponse] = []


class VideoListResponse(BaseModel):
    success: bool
    total: int
    videos: list[VideoResponse] = []


class VideoUploadResponse(BaseModel):
    success: bool
    message: str
    viewkey: Optional[str] = None
    video: Optional[VideoResponse] = None
    uploaded_by: Optional[str] = None
    user_id: Optional[int] = None
