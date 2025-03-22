from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .core import config
from .api.v1.api import api_router
from .middleware.audit import audit_middleware
from .middleware.rate_limit import rate_limit_middleware
from .core.security import MasterKeyManager
import structlog
import time
from typing import Callable
import uvicorn

logger = structlog.get_logger()

def create_application() -> FastAPI:
    application = FastAPI(
        title=config.settings.PROJECT_NAME,
        openapi_url="/api/v1/openapi.json",
        description="""
        Secure Cell Vault is a highly secure, cell-based secrets management system with 
        fine-grained access control and API-driven architecture.
        
        Key features:
        - Cell-based isolation for secrets
        - Fine-grained access control
        - Strong encryption (AES-256-GCM)
        - Audit logging
        - Key rotation
        - Hardware Security Module (HSM) support
        """,
        version="0.1.0"
    )

    # Set up CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add custom middleware
    application.middleware("http")(audit_middleware)
    application.middleware("http")(rate_limit_middleware)

    # Add performance logging middleware
    @application.middleware("http")
    async def add_process_time_header(request: Request, call_next: Callable):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        logger.info(
            "request_processed",
            path=request.url.path,
            method=request.method,
            process_time=process_time,
        )
        return response

    # Exception handler for custom error responses
    @application.exception_handler(Exception)
    async def universal_exception_handler(request: Request, exc: Exception):
        logger.error(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error=str(exc),
            error_type=type(exc).__name__
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "An internal error occurred",
                "type": "internal_error"
            }
        )

    # Include API router
    application.include_router(api_router, prefix="/api/v1")

    # Startup event to initialize services
    @application.on_event("startup")
    async def startup_event():
        logger.info("application_starting")
        
        # Initialize master key manager
        key_manager = MasterKeyManager(
            hsm=config.settings.USE_HSM and config.settings.HSM_PROVIDER
        )
        key_manager.initialize()
        
        logger.info("application_started")

    # Shutdown event for cleanup
    @application.on_event("shutdown")
    async def shutdown_event():
        logger.info("application_shutting_down")
        # Add cleanup code here
        logger.info("application_shutdown_complete")

    return application

app = create_application()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )