"""
JWT authentication middleware for SecureOps AI API.
Validates Bearer tokens on all protected routes.
"""

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

from config.settings import settings

UNPROTECTED_PATHS = {"/health", "/health/", "/docs", "/openapi.json", "/redoc"}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in UNPROTECTED_PATHS:
            return await call_next(request)

        # Webhook endpoints use HMAC — handled in route
        if request.url.path.endswith("/webhook/github"):
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing or invalid authorization header"},
            )

        token = auth.removeprefix("Bearer ").strip()
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            request.state.user_id = payload.get("sub")
            request.state.scopes = payload.get("scopes", [])
        except JWTError as exc:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": f"Invalid token: {exc}"},
            )

        return await call_next(request)
