import os
import secrets
from urllib.parse import urlparse

import mysql.connector
from mysql.connector import Error
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

class User(BaseModel):
    id : int
    name : str
class video(BaseModel):
    title:str
    stream_link :str
    thumbnail : str
def get_connection():
    mysql_url = os.getenv("MYSQL_URL")

    if not mysql_url:
        raise Exception("MYSQL_URL environment variable not found.")

    url = urlparse(mysql_url)

    return mysql.connector.connect(
        host=url.hostname,
        port=url.port or 3306,
        user=url.username,
        password=url.password,
        database=url.path.lstrip("/"),
        connection_timeout=30,
        use_pure=True,  # Use pure Python implementation
        auth_plugin='mysql_native_password'  # Force native password auth
    )


# ==========================
# Database Functions
# ==========================

def get_data():
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM mydata")
        results = cursor.fetchall()
        
        if not results:
            return {"message": "No Users Found"}
        return results

    except Error as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def insert_data(name: str, email: str, password: str):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO mydata (name, email, Password) VALUES (%s, %s, %s)",
            (name, email, password),
        )
        connection.commit()
        return {"message": "User Added Successfully"}

    except Error as e:
        return {"error": str(e)}
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ==========================
# FastAPI App
# ==========================

app = FastAPI()

origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://localhost:5173/",
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
    user_id = user.id
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM apikeys WHERE USER_ID = %s"
        cursor.execute(query,(user_id,))
        apikeys = cursor.fetchall()
        return apikeys
    except Error as e:
        return {"Error": str(e)}
    finally:
        if connection:
            connection.close()
        if cursor:
            cursor.close()
@app.get("/videos")
def getvideos():
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        query = 'SELECT * FROM videos'
        cursor.execute(query)
        videos = cursor.fetchall()
        return videos
    except Error as e:
        return {"message" : str(e)}
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
@app.post("/upload_videos")
def getvideos(video : video):
    connection = None
    cursor = None
    title = video.title
    thumbnail = video.thumbnail
    stream_link = video.stream_link
    viewkey = secrets.token_hex(6)
    try:
        connection = get_connection()
        cursor = connection.cursor()
        query = 'INSERT INTO videos (title,stream_link,viewkey,thumbnail) VALUES (%s,%s,%s,%s)'
        cursor.execute(query,(title,stream_link,viewkey,thumbnail))
        connection.commit()
        return {"message":"Video Upload Sucess",
                "viewkey": viewkey}
    except Error as e:
        return {"message" : str(e)}
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()