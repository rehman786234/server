import secrets
from fastapi import APIRouter, HTTPException, status, Header
from typing import List, Dict, Any
import logging
from datetime import datetime

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


@router.get("/")
async def home():
    """Root endpoint"""
    return """
        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Video Server 2.0 - API Documentation</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 40px 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 50px;
        }

        .header h1 {
            font-size: 4rem;
            font-weight: 800;
            margin-bottom: 10px;
            text-shadow: 0 4px 20px rgba(0,0,0,0.2);
            animation: fadeInDown 0.8s ease;
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
            animation: fadeInUp 0.8s ease;
        }

        .badge {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 8px 20px;
            border-radius: 50px;
            font-size: 0.9rem;
            margin-top: 15px;
            backdrop-filter: blur(10px);
        }

        .badge i {
            margin-right: 8px;
        }

        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .status-card {
            background: rgba(255,255,255,0.15);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 16px;
            text-align: center;
            color: white;
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease;
        }

        .status-card:hover {
            transform: translateY(-5px);
        }

        .status-card .number {
            font-size: 2.5rem;
            font-weight: 700;
        }

        .status-card .label {
            font-size: 0.9rem;
            opacity: 0.8;
            margin-top: 5px;
        }

        .endpoints-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }

        .endpoint-card {
            background: white;
            border-radius: 16px;
            padding: 25px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.15);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            animation: fadeInUp 0.6s ease;
            animation-fill-mode: both;
        }

        .endpoint-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 30px 80px rgba(0,0,0,0.2);
        }

        .endpoint-card:nth-child(1) { animation-delay: 0.1s; }
        .endpoint-card:nth-child(2) { animation-delay: 0.2s; }
        .endpoint-card:nth-child(3) { animation-delay: 0.3s; }
        .endpoint-card:nth-child(4) { animation-delay: 0.4s; }
        .endpoint-card:nth-child(5) { animation-delay: 0.5s; }
        .endpoint-card:nth-child(6) { animation-delay: 0.6s; }

        .endpoint-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 15px;
        }

        .method-badge {
            padding: 4px 12px;
            border-radius: 50px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .method-get { background: #10b981; color: white; }
        .method-post { background: #3b82f6; color: white; }
        .method-put { background: #f59e0b; color: white; }
        .method-delete { background: #ef4444; color: white; }

        .endpoint-path {
            font-size: 1.1rem;
            font-weight: 600;
            color: #1f2937;
            font-family: 'Courier New', monospace;
        }

        .endpoint-description {
            color: #6b7280;
            font-size: 0.95rem;
            margin: 10px 0;
            line-height: 1.6;
        }

        .endpoint-details {
            background: #f9fafb;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }

        .endpoint-details code {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: #374151;
            display: block;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .auth-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: #fef3c7;
            color: #92400e;
            padding: 4px 12px;
            border-radius: 50px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-top: 10px;
        }

        .auth-badge i {
            font-size: 0.7rem;
        }

        .code-section {
            background: #1f2937;
            border-radius: 12px;
            padding: 25px;
            margin-top: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }

        .code-section h3 {
            color: white;
            margin-bottom: 20px;
            font-size: 1.3rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .code-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        .code-tab {
            padding: 8px 20px;
            background: rgba(255,255,255,0.1);
            color: #9ca3af;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .code-tab:hover {
            background: rgba(255,255,255,0.2);
            color: white;
        }

        .code-tab.active {
            background: #3b82f6;
            color: white;
        }

        .code-content {
            display: none;
            background: #111827;
            border-radius: 8px;
            padding: 20px;
            overflow-x: auto;
        }

        .code-content.active {
            display: block;
        }

        .code-content pre {
            color: #e5e7eb;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.8;
            margin: 0;
            white-space: pre-wrap;
        }

        .code-content .keyword { color: #60a5fa; }
        .code-content .string { color: #34d399; }
        .code-content .comment { color: #6b7280; }
        .code-content .function { color: #f472b6; }
        .code-content .number { color: #fbbf24; }

        .footer {
            text-align: center;
            color: rgba(255,255,255,0.7);
            margin-top: 50px;
            padding-top: 30px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }

        .footer a {
            color: white;
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        @keyframes fadeInDown {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 2.5rem;
            }
            .endpoints-grid {
                grid-template-columns: 1fr;
            }
            .status-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🚀 FastAPI Server</h1>
            <p>Modern REST API with PostgreSQL</p>
            <div class="badge">
                <i class="fas fa-check-circle"></i>
                API is running successfully
            </div>
        </div>

        <!-- Status Cards -->
        <div class="status-grid">
            <div class="status-card">
                <div class="number" id="totalEndpoints">12</div>
                <div class="label"><i class="fas fa-code"></i> Endpoints</div>
            </div>
            <div class="status-card">
                <div class="number" id="totalUsers">0</div>
                <div class="label"><i class="fas fa-users"></i> Users</div>
            </div>
            <div class="status-card">
                <div class="number" id="totalVideos">0</div>
                <div class="label"><i class="fas fa-video"></i> Videos</div>
            </div>
            <div class="status-card">
                <div class="number" id="serverStatus">🟢</div>
                <div class="label"><i class="fas fa-server"></i> Server Status</div>
            </div>
        </div>

        <!-- Endpoints -->
        <h2 style="color: white; margin-bottom: 25px; font-weight: 700;">
            <i class="fas fa-plug"></i> Available Endpoints
        </h2>

        <div class="endpoints-grid">
            <!-- User Endpoints -->
            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-get">GET</span>
                    <span class="endpoint-path">/</span>
                </div>
                <div class="endpoint-description">Root endpoint - Server status</div>
                <div class="endpoint-details">
                    <code>GET /</code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-get">GET</span>
                    <span class="endpoint-path">/get_users</span>
                </div>
                <div class="endpoint-description">Get all registered users</div>
                <div class="endpoint-details">
                    <code>GET /get_users</code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-post">POST</span>
                    <span class="endpoint-path">/users</span>
                </div>
                <div class="endpoint-description">Create a new user</div>
                <div class="endpoint-details">
                    <code>POST /users</code>
                    <code style="margin-top: 8px; color: #6b7280;">
                        Body: { "name": "John", "email": "john@email.com", "password": "pass123" }
                    </code>
                </div>
            </div>

            <!-- API Key Endpoints -->
            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-post">POST</span>
                    <span class="endpoint-path">/apikey</span>
                </div>
                <div class="endpoint-description">Generate API key for user</div>
                <div class="endpoint-details">
                    <code>POST /apikey</code>
                    <code style="margin-top: 8px; color: #6b7280;">
                        Body: { "user_id": 1 }
                    </code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-post">POST</span>
                    <span class="endpoint-path">/user_apikeys</span>
                </div>
                <div class="endpoint-description">Get all API keys for a user</div>
                <div class="endpoint-details">
                    <code>POST /user_apikeys</code>
                    <code style="margin-top: 8px; color: #6b7280;">
                        Body: { "id": 1, "name": "John" }
                    </code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-delete">DELETE</span>
                    <span class="endpoint-path">/apikey</span>
                </div>
                <div class="endpoint-description">Delete an API key</div>
                <div class="endpoint-details">
                    <code>DELETE /apikey?api_key=YOUR_API_KEY</code>
                </div>
            </div>

            <!-- Video Endpoints -->
            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-get">GET</span>
                    <span class="endpoint-path">/videos</span>
                </div>
                <div class="endpoint-description">Get all non-premium videos</div>
                <div class="endpoint-details">
                    <code>GET /videos</code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-get">GET</span>
                    <span class="endpoint-path">/premium_videos</span>
                </div>
                <div class="endpoint-description">Get all premium videos</div>
                <div class="auth-badge">
                    <i class="fas fa-key"></i> Requires API Key
                </div>
                <div class="endpoint-details">
                    <code>GET /premium_videos</code>
                    <code style="margin-top: 8px; color: #6b7280;">
                        Header: api-key: YOUR_API_KEY
                    </code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-post">POST</span>
                    <span class="endpoint-path">/upload_videos</span>
                </div>
                <div class="endpoint-description">Upload a new video</div>
                <div class="auth-badge">
                    <i class="fas fa-key"></i> Requires API Key
                </div>
                <div class="endpoint-details">
                    <code>POST /upload_videos</code>
                    <code style="margin-top: 8px; color: #6b7280;">
                        Header: api-key: YOUR_API_KEY
                        Body: { "title": "Video", "stream_link": "url", "thumbnail": "url", "category": "Education", "is_premium": false }
                    </code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-get">GET</span>
                    <span class="endpoint-path">/videos/{viewkey}</span>
                </div>
                <div class="endpoint-description">Get video by viewkey</div>
                <div class="endpoint-details">
                    <code>GET /videos/abc123</code>
                </div>
            </div>

            <div class="endpoint-card">
                <div class="endpoint-header">
                    <span class="method-badge method-get">GET</span>
                    <span class="endpoint-path">/health</span>
                </div>
                <div class="endpoint-description">Health check endpoint</div>
                <div class="endpoint-details">
                    <code>GET /health</code>
                </div>
            </div>
        </div>

        <!-- Code Examples -->
        <div class="code-section">
            <h3><i class="fas fa-code"></i> Code Examples</h3>
            
            <div class="code-tabs">
                <button class="code-tab active" onclick="showCode('javascript')">JavaScript</button>
                <button class="code-tab" onclick="showCode('python')">Python</button>
                <button class="code-tab" onclick="showCode('curl')">cURL</button>
                <button class="code-tab" onclick="showCode('java')">Java</button>
            </div>

            <!-- JavaScript -->
            <div id="javascript" class="code-content active">
                <pre>
<span class="comment">// API Configuration</span>
<span class="keyword">const</span> API_URL = <span class="string">'http://localhost:8000'</span>;

<span class="comment">// 1. Create User</span>
<span class="keyword">async function</span> <span class="function">createUser</span>() {
    <span class="keyword">const</span> response = <span class="keyword">await</span> fetch(<span class="string">`${API_URL}/users`</span>, {
        method: <span class="string">'POST'</span>,
        headers: { <span class="string">'Content-Type'</span>: <span class="string">'application/json'</span> },
        body: JSON.stringify({
            name: <span class="string">'John Doe'</span>,
            email: <span class="string">'john@example.com'</span>,
            password: <span class="string">'securepass123'</span>
        })
    });
    <span class="keyword">const</span> data = <span class="keyword">await</span> response.json();
    console.log(data);
}

<span class="comment">// 2. Generate API Key</span>
<span class="keyword">async function</span> <span class="function">generateApiKey</span>(userId) {
    <span class="keyword">const</span> response = <span class="keyword">await</span> fetch(<span class="string">`${API_URL}/apikey`</span>, {
        method: <span class="string">'POST'</span>,
        headers: { <span class="string">'Content-Type'</span>: <span class="string">'application/json'</span> },
        body: JSON.stringify({ user_id: userId })
    });
    <span class="keyword">const</span> data = <span class="keyword">await</span> response.json();
    <span class="keyword">return</span> data.api_key;
}

<span class="comment">// 3. Upload Video</span>
<span class="keyword">async function</span> <span class="function">uploadVideo</span>(apiKey) {
    <span class="keyword">const</span> response = <span class="keyword">await</span> fetch(<span class="string">`${API_URL}/upload_videos`</span>, {
        method: <span class="string">'POST'</span>,
        headers: {
            <span class="string">'Content-Type'</span>: <span class="string">'application/json'</span>,
            <span class="string">'api-key'</span>: apiKey
        },
        body: JSON.stringify({
            title: <span class="string">'My Video'</span>,
            stream_link: <span class="string">'https://example.com/video.mp4'</span>,
            thumbnail: <span class="string">'https://example.com/thumb.jpg'</span>,
            category: <span class="string">'Education'</span>,
            is_premium: <span class="keyword">false</span>
        })
    });
    <span class="keyword">const</span> data = <span class="keyword">await</span> response.json();
    console.log(data);
}

<span class="comment">// 4. Get Premium Videos</span>
<span class="keyword">async function</span> <span class="function">getPremiumVideos</span>(apiKey) {
    <span class="keyword">const</span> response = <span class="keyword">await</span> fetch(<span class="string">`${API_URL}/premium_videos`</span>, {
        headers: { <span class="string">'api-key'</span>: apiKey }
    });
    <span class="keyword">const</span> data = <span class="keyword">await</span> response.json();
    console.log(data);
}

<span class="comment">// 5. Delete API Key</span>
<span class="keyword">async function</span> <span class="function">deleteApiKey</span>(apiKey) {
    <span class="keyword">const</span> response = <span class="keyword">await</span> fetch(<span class="string">`${API_URL}/apikey?api_key=${apiKey}`</span>, {
        method: <span class="string">'DELETE'</span>
    });
    <span class="keyword">const</span> data = <span class="keyword">await</span> response.json();
    console.log(data);
}</pre>
            </div>

            <!-- Python -->
            <div id="python" class="code-content">
                <pre>
<span class="comment"># Python Example</span>
<span class="keyword">import</span> requests
<span class="keyword">import</span> json

<span class="comment"># Configuration</span>
API_URL = <span class="string">"http://localhost:8000"</span>

<span class="comment"># 1. Create User</span>
<span class="keyword">def</span> <span class="function">create_user</span>():
    payload = {
        <span class="string">"name"</span>: <span class="string">"John Doe"</span>,
        <span class="string">"email"</span>: <span class="string">"john@example.com"</span>,
        <span class="string">"password"</span>: <span class="string">"securepass123"</span>
    }
    response = requests.post(<span class="string">f"{API_URL}/users"</span>, json=payload)
    print(response.json())

<span class="comment"># 2. Generate API Key</span>
<span class="keyword">def</span> <span class="function">generate_api_key</span>(user_id):
    payload = {<span class="string">"user_id"</span>: user_id}
    response = requests.post(<span class="string">f"{API_URL}/apikey"</span>, json=payload)
    data = response.json()
    <span class="keyword">return</span> data[<span class="string">'api_key'</span>]

<span class="comment"># 3. Upload Video</span>
<span class="keyword">def</span> <span class="function">upload_video</span>(api_key):
    headers = {<span class="string">"api-key"</span>: api_key}
    payload = {
        <span class="string">"title"</span>: <span class="string">"My Video"</span>,
        <span class="string">"stream_link"</span>: <span class="string">"https://example.com/video.mp4"</span>,
        <span class="string">"thumbnail"</span>: <span class="string">"https://example.com/thumb.jpg"</span>,
        <span class="string">"category"</span>: <span class="string">"Education"</span>,
        <span class="string">"is_premium"</span>: False
    }
    response = requests.post(<span class="string">f"{API_URL}/upload_videos"</span>, 
                           json=payload, headers=headers)
    print(response.json())

<span class="comment"># 4. Get Premium Videos</span>
<span class="keyword">def</span> <span class="function">get_premium_videos</span>(api_key):
    headers = {<span class="string">"api-key"</span>: api_key}
    response = requests.get(<span class="string">f"{API_URL}/premium_videos"</span>, headers=headers)
    print(response.json())

<span class="comment"># 5. Delete API Key</span>
<span class="keyword">def</span> <span class="function">delete_api_key</span>(api_key):
    response = requests.delete(<span class="string">f"{API_URL}/apikey?api_key={api_key}"</span>)
    print(response.json())

<span class="comment"># Usage</span>
<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:
    create_user()
    api_key = generate_api_key(1)
    upload_video(api_key)
    get_premium_videos(api_key)</pre>
            </div>

            <!-- cURL -->
            <div id="curl" class="code-content">
                <pre>
<span class="comment"># 1. Create User</span>
curl -X POST http://localhost:8000/users \
  -H <span class="string">"Content-Type: application/json"</span> \
  -d <span class="string">'{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securepass123"
  }'</span>

<span class="comment"># 2. Generate API Key</span>
curl -X POST http://localhost:8000/apikey \
  -H <span class="string">"Content-Type: application/json"</span> \
  -d <span class="string">'{"user_id": 1}'</span>

<span class="comment"># 3. Upload Video (Requires API Key)</span>
curl -X POST http://localhost:8000/upload_videos \
  -H <span class="string">"Content-Type: application/json"</span> \
  -H <span class="string">"api-key: YOUR_API_KEY_HERE"</span> \
  -d <span class="string">'{
    "title": "My Video",
    "stream_link": "https://example.com/video.mp4",
    "thumbnail": "https://example.com/thumb.jpg",
    "category": "Education",
    "is_premium": false
  }'</span>

<span class="comment"># 4. Get Premium Videos (Requires API Key)</span>
curl -X GET http://localhost:8000/premium_videos \
  -H <span class="string">"api-key: YOUR_API_KEY_HERE"</span>

<span class="comment"># 5. Delete API Key</span>
curl -X DELETE <span class="string">"http://localhost:8000/apikey?api_key=YOUR_API_KEY_HERE"</span>

<span class="comment"># 6. Get All Users</span>
curl -X GET http://localhost:8000/get_users

<span class="comment"># 7. Get Non-Premium Videos</span>
curl -X GET http://localhost:8000/videos

<span class="comment"># 8. Get Video by Viewkey</span>
curl -X GET http://localhost:8000/videos/abc123

<span class="comment"># 9. Health Check</span>
curl -X GET http://localhost:8000/health</pre>
            </div>

            <!-- Java -->
            <div id="java" class="code-content">
                <pre>
<span class="comment">// Java Example using HttpClient (Java 11+)</span>
<span class="keyword">import</span> java.net.http.HttpClient;
<span class="keyword">import</span> java.net.http.HttpRequest;
<span class="keyword">import</span> java.net.http.HttpResponse;
<span class="keyword">import</span> java.net.URI;

<span class="keyword">public class</span> <span class="function">ApiClient</span> {
    <span class="keyword">private static final</span> String API_URL = <span class="string">"http://localhost:8000"</span>;
    <span class="keyword">private static final</span> HttpClient client = HttpClient.newHttpClient();

    <span class="comment">// 1. Create User</span>
    <span class="keyword">public static void</span> <span class="function">createUser</span>() <span class="keyword">throws</span> Exception {
        String json = <span class="string">"""
            {
                "name": "John Doe",
                "email": "john@example.com",
                "password": "securepass123"
            }
            """</span>;
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + <span class="string">"/users"</span>))
            .header(<span class="string">"Content-Type"</span>, <span class="string">"application/json"</span>)
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }

    <span class="comment">// 2. Generate API Key</span>
    <span class="keyword">public static void</span> <span class="function">generateApiKey</span>(<span class="keyword">int</span> userId) <span class="keyword">throws</span> Exception {
        String json = <span class="string">"{"user_id": "</span> + userId + <span class="string">"}"</span>;
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + <span class="string">"/apikey"</span>))
            .header(<span class="string">"Content-Type"</span>, <span class="string">"application/json"</span>)
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }

    <span class="comment">// 3. Upload Video</span>
    <span class="keyword">public static void</span> <span class="function">uploadVideo</span>(String apiKey) <span class="keyword">throws</span> Exception {
        String json = <span class="string">"""
            {
                "title": "My Video",
                "stream_link": "https://example.com/video.mp4",
                "thumbnail": "https://example.com/thumb.jpg",
                "category": "Education",
                "is_premium": false
            }
            """</span>;
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + <span class="string">"/upload_videos"</span>))
            .header(<span class="string">"Content-Type"</span>, <span class="string">"application/json"</span>)
            .header(<span class="string">"api-key"</span>, apiKey)
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();

        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }

    <span class="comment">// 4. Get Premium Videos</span>
    <span class="keyword">public static void</span> <span class="function">getPremiumVideos</span>(String apiKey) <span class="keyword">throws</span> Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + <span class="string">"/premium_videos"</span>))
            .header(<span class="string">"api-key"</span>, apiKey)
            .GET()
            .build();

        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }

    <span class="comment">// 5. Delete API Key</span>
    <span class="keyword">public static void</span> <span class="function">deleteApiKey</span>(String apiKey) <span class="keyword">throws</span> Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + <span class="string">"/apikey?api_key="</span> + apiKey))
            .DELETE()
            .build();

        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }

    <span class="keyword">public static void</span> <span class="function">main</span>(String[] args) <span class="keyword">throws</span> Exception {
        createUser();
        generateApiKey(1);
        <span class="comment">// Use the returned API key from above</span>
        uploadVideo(<span class="string">"YOUR_API_KEY_HERE"</span>);
        getPremiumVideos(<span class="string">"YOUR_API_KEY_HERE"</span>);
    }
}</pre>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>
                <i class="fas fa-heart" style="color: #ef4444;"></i>
                Built with FastAPI · PostgreSQL · 
                <a href="#" onclick="refreshStats()">
                    <i class="fas fa-sync-alt"></i> Refresh Stats
                </a>
            </p>
            <p style="margin-top: 10px; font-size: 0.85rem;">
                <i class="fas fa-shield-alt"></i> All premium endpoints require valid API key
            </p>
        </div>
    </div>

    <script>
        // Fetch real-time stats from the server
        async function fetchStats() {
            try {
                // Fetch users count
                const usersResponse = await fetch('/get_users');
                const users = await usersResponse.json();
                document.getElementById('totalUsers').textContent = Array.isArray(users) ? users.length : 0;

                // Fetch videos count (non-premium)
                const videosResponse = await fetch('/videos');
                const videos = await videosResponse.json();
                document.getElementById('totalVideos').textContent = Array.isArray(videos) ? videos.length : 0;
            } catch (error) {
                console.log('Could not fetch stats:', error);
                // Keep default values if fetch fails
            }
        }

        // Refresh stats on load
        fetchStats();

        // Refresh stats every 30 seconds
        setInterval(fetchStats, 30000);

        // Code tab switching
        function showCode(language) {
            // Hide all code content
            document.querySelectorAll('.code-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected code content
            document.getElementById(language).classList.add('active');
            
            // Update tab styles
            document.querySelectorAll('.code-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Find and activate the clicked tab
            document.querySelectorAll('.code-tab').forEach(tab => {
                if (tab.textContent.toLowerCase() === language) {
                    tab.classList.add('active');
                }
            });
        }

        // Manual refresh function
        function refreshStats() {
            fetchStats();
            document.querySelector('.badge i').style.color = '#34d399';
            setTimeout(() => {
                document.querySelector('.badge i').style.color = '';
            }, 1000);
            return false;
        }

        // Add animation to cards on scroll
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('.endpoint-card').forEach(card => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(30px)';
            observer.observe(card);
        });
    </script>
</body>
</html>
    """


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
    
    viewkey = secrets.token_hex(10)
    
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
