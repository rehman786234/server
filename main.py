import os
import secrets
import sqlite3
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ==========================
# Models
# ==========================

class User(BaseModel):
    id: int
    name: str

class Video(BaseModel):
    title: str
    stream_link: str
    thumbnail: str

# ==========================
# Database Connection
# ==========================

DB_PATH = os.getenv("SQLITE_DB_PATH", "database.db")

@contextmanager
def get_connection():
    """Context manager for database connections"""
    connection = None
    try:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        yield connection
    except sqlite3.Error as e:
        raise Exception(f"Database connection error: {e}")
    finally:
        if connection:
            connection.close()

@contextmanager
def get_cursor(connection):
    """Context manager for database cursors"""
    cursor = connection.cursor()
    try:
        yield cursor
    finally:
        cursor.close()

# ==========================
# Database Functions
# ==========================

def get_data():
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute("SELECT * FROM mydata")
                results = cursor.fetchall()
                
                if not results:
                    return {"message": "No Users Found"}
                
                return [dict(row) for row in results]
    
    except Exception as e:
        return {"error": str(e)}

def insert_data(name: str, email: str, password: str):
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                cursor.execute(
                    "INSERT INTO mydata (name, email, Password) VALUES (?, ?, ?)",
                    (name, email, password),
                )
                connection.commit()
                return {"message": "User Added Successfully"}
    
    except sqlite3.IntegrityError as e:
        return {"error": f"Integrity error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}

# ==========================
# FastAPI App
# ==========================

app = FastAPI()

origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# Routes
# ==========================

@app.get("/")
def home():
    return {"message": "FastAPI Server Running Successfully"}

@app.get("/get_users")
def get_users():
    return get_data()

@app.get("/apikey")
def api_key():
    return {"ApiKey": secrets.token_hex(16)}

@app.post("/user_apikeys")
def user_apikeys(user: User):
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                query = "SELECT * FROM apikeys WHERE USER_ID = ?"
                cursor.execute(query, (user.id,))
                apikeys = cursor.fetchall()
                return [dict(row) for row in apikeys]
    
    except Exception as e:
        return {"Error": str(e)}

@app.get("/videos")
def getvideos():
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                query = 'SELECT * FROM videos'
                cursor.execute(query)
                videos = cursor.fetchall()
                return [dict(row) for row in videos]
    
    except Exception as e:
        return {"message": str(e)}

@app.post("/upload_videos")
def upload_video(video: Video):
    viewkey = secrets.token_hex(6)
    
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                query = 'INSERT INTO videos (title, stream_link, viewkey, thumbnail) VALUES (?, ?, ?, ?)'
                cursor.execute(query, (video.title, video.stream_link, viewkey, video.thumbnail))
                connection.commit()
                return {
                    "message": "Video Upload Success",
                    "viewkey": viewkey
                }
    
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail=f"Database integrity error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# ==========================
# Database Initialization
# ==========================

def init_database():
    """Initialize database tables if they don't exist"""
    try:
        with get_connection() as connection:
            with get_cursor(connection) as cursor:
                # Create mydata table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS mydata (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        Password TEXT NOT NULL
                    )
                ''')
                
                # Create apikeys table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS apikeys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        USER_ID INTEGER NOT NULL,
                        api_key TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (USER_ID) REFERENCES mydata(id)
                    )
                ''')
                
                # Create videos table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS videos (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        stream_link TEXT NOT NULL,
                        viewkey TEXT UNIQUE NOT NULL,
                        thumbnail TEXT,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                connection.commit()
                print("Database initialized successfully!")
    
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize database on startup
@app.on_event("startup")
def startup_event():
    init_database()
