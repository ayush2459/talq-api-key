"""Loopback-only administrator control-plane ASGI entry point."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.main import app as internal_app


class LoopbackOnlyAdmin(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        host = request.client.host if request.client else ""
        if host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        return await call_next(request)


admin_app = FastAPI(
    title="FlowSense Internal Administration",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
admin_app.openapi = internal_app.openapi
admin_app.add_middleware(LoopbackOnlyAdmin)
admin_app.mount("/", internal_app)
