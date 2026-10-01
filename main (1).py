import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import sys

from config import Config
from database import init_connection_pool, close_all_connections, health_check
from routes import router
from init_db import init_database

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    try:
        logger.info("Starting up FastAPI application...")
        logger.info(f"Environment: {os.getenv('ENV', 'production')}")
        
        # Validate configuration
        Config.validate()
        
        # Initialize database connection pool
        init_connection_pool()
        logger.info("Database connection pool initialized")
        
        # Initialize database tables (safe migration)
        init_database()
        logger.info("Database initialization completed")
        
        # Health check
        if health_check():
            logger.info("Database health check passed")
        else:
            logger.warning("Database health check failed")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down FastAPI application...")
        close_all_connections()
        logger.info("Database connections closed")


# Create FastAPI app
app = FastAPI(
    title="FastAPI Backend",
    description="FastAPI backend with PostgreSQL on Render",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)


# Global exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP Exception: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )


# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "FastAPI Server Running Successfully",
        "database": "PostgreSQL",
        "environment": os.getenv("ENV", "production")
    }


# Main entry point
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        workers=2
    )
