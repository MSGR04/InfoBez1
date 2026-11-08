"""Application configuration loaded from environment variables."""
import os
import secrets


class Config:
    # Secret for signing JWTs. Must come from the environment in production;
    # a random per-process fallback keeps dev runs safe (tokens die on restart).
    JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
    # HS256 requires a key of at least 256 bits (RFC 7518, section 3.2).
    JWT_SECRET_MIN_BYTES = 32
    JWT_ALGORITHM = "HS256"
    JWT_ISSUER = "secure-api-lab1"
    JWT_EXPIRES_MINUTES = int(os.environ.get("JWT_EXPIRES_MINUTES", "30"))

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Reject oversized request bodies (basic DoS protection).
    MAX_CONTENT_LENGTH = 16 * 1024

    # Brute-force protection for /auth/login.
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 15 * 60

    BCRYPT_ROUNDS = 12
