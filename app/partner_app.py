"""Partner-only ASGI surface. The internal FastAPI app is mounted behind a strict allowlist.

Run separately from app.main:app. Never bind the admin app to a partner-facing interface.
"""
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.main import app as internal_app

_ALLOWED = [
    ("GET", re.compile(r"^/v1/ping$")),
    ("POST", re.compile(r"^/v1/onboarding/requests$")),
    ("GET", re.compile(r"^/v1/onboarding/requests/\d+$")),
    ("POST", re.compile(r"^/v1/onboarding/requests/\d+/claim$")),
    ("POST", re.compile(r"^/oauth/token$")),
    ("GET", re.compile(r"^/integrations/me$")),
    ("GET|POST", re.compile(r"^/integrations/me/api-keys$")),
    ("POST", re.compile(r"^/integrations/me/api-keys/\d+/(rotate|retire|revoke)$")),
    ("GET", re.compile(r"^/v1/test-data$")),
    ("GET", re.compile(r"^/auth/verify$")),
    ("GET", re.compile(r"^/devices(?:/count|/[^/]+)?$")),
    ("GET", re.compile(r"^/(measurements|alerts|events|data-packages|services)(?:/[^/]+)?$")),
]


class PartnerSurfaceGuard(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path
        if not any(
            (methods == method or methods == "GET|POST" and method in {"GET", "POST"})
            and pattern.fullmatch(path)
            for methods, pattern in _ALLOWED
        ):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        return await call_next(request)


partner_app = FastAPI(
    title="FlowSense Partner API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
partner_app.add_middleware(PartnerSurfaceGuard)
partner_app.mount("/", internal_app)
