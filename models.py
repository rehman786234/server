from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class User(BaseModel):
    id: int
    name: str


class UserCreate(BaseModel):
    name: str
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    created_at: Optional[datetime] = None


class APIKeyRequest(BaseModel):
    user_id: int


class Video(BaseModel):
    title: str
    stream_link: str
    thumbnail: Optional[str] = None
    category: Optional[str] = None
    is_premium: Optional[bool] = False


class VideoResponse(BaseModel):
    id: int
    title: str
    stream_link: str
    viewkey: str
    thumbnail: Optional[str] = None
    category: Optional[str] = None
    is_premium: Optional[bool] = False
    uploaded_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: int
    user_id: int
    api_key: str
    created_at: Optional[datetime] = None


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
