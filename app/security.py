"""Security helpers: JWT issuing/verification, auth middleware,
output encoding (XSS) and login brute-force throttling."""
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request
from markupsafe import escape

from .models import User, db


# --------------------------------------------------------------------------- JWT

def create_access_token(user: User) -> str:
    cfg = current_app.config
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iss": cfg["JWT_ISSUER"],
        "iat": now,
        "exp": now + timedelta(minutes=cfg["JWT_EXPIRES_MINUTES"]),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, cfg["JWT_SECRET"], algorithm=cfg["JWT_ALGORITHM"])


def decode_access_token(token: str) -> dict:
    cfg = current_app.config
    # The algorithm list is pinned, so "alg": "none" or algorithm-confusion
    # tokens are rejected. Signature, exp and iss are verified by PyJWT.
    return jwt.decode(
        token,
        cfg["JWT_SECRET"],
        algorithms=[cfg["JWT_ALGORITHM"]],
        issuer=cfg["JWT_ISSUER"],
        options={"require": ["exp", "iat", "sub", "iss"]},
    )


def _unauthorized(message: str):
    response = jsonify({"error": message})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="api"'
    return response


def jwt_required(view):
    """Middleware decorator: allows the request only with a valid Bearer JWT."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _unauthorized("Missing or malformed Authorization header")

        try:
            claims = decode_access_token(token.strip())
        except jwt.ExpiredSignatureError:
            return _unauthorized("Token expired")
        except jwt.InvalidTokenError:
            return _unauthorized("Invalid token")

        # The user must still exist (e.g. not deleted after token issue).
        user = db.session.get(User, int(claims["sub"])) if claims["sub"].isdigit() else None
        if user is None:
            return _unauthorized("Invalid token")

        g.current_user = user
        return view(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------------- XSS

def sanitize(value):
    """HTML-escape user-controlled data before it is returned by the API
    (< > & ' " become entities), recursively for dicts and lists."""
    if isinstance(value, str):
        return str(escape(value))
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return value


# ---------------------------------------------------------------- brute force

class LoginThrottle:
    """In-memory counter of failed logins per (client IP, username)."""

    def __init__(self):
        self._failures = {}
        self._lock = threading.Lock()

    def _recent(self, key, window):
        cutoff = time.monotonic() - window
        attempts = [t for t in self._failures.get(key, []) if t > cutoff]
        self._failures[key] = attempts
        return attempts

    def is_blocked(self, key, max_attempts, window) -> bool:
        with self._lock:
            return len(self._recent(key, window)) >= max_attempts

    def register_failure(self, key, window) -> None:
        with self._lock:
            self._recent(key, window).append(time.monotonic())

    def reset(self, key) -> None:
        with self._lock:
            self._failures.pop(key, None)


login_throttle = LoginThrottle()


# ------------------------------------------------------------ response headers

def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response
