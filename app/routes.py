"""API endpoints."""
import bcrypt
from flask import Blueprint, current_app, g, jsonify, request

from .models import Post, User, db
from .security import create_access_token, jwt_required, login_throttle, sanitize

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
api_bp = Blueprint("api", __name__, url_prefix="/api")

USERNAME_MAX = 32
PASSWORD_MAX_BYTES = 72  # bcrypt only uses the first 72 bytes
TITLE_MAX = 120
CONTENT_MAX = 5000

_dummy_hash = None


def _get_dummy_hash() -> bytes:
    """Hash compared against when the user does not exist, so the response
    time does not reveal which usernames are registered."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(current_app.config["BCRYPT_ROUNDS"]))
    return _dummy_hash


def _bad_request(message: str):
    return jsonify({"error": message}), 400


def _json_body():
    if not request.is_json:
        return None
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


# ------------------------------------------------------------ POST /auth/login

@auth_bp.post("/login")
def login():
    body = _json_body()
    if body is None:
        return _bad_request("Expected JSON object body")

    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return _bad_request("Fields 'username' and 'password' must be strings")
    if not username or len(username) > USERNAME_MAX:
        return _bad_request("Invalid username length")
    if not password or len(password.encode("utf-8")) > PASSWORD_MAX_BYTES:
        return _bad_request("Invalid password length")

    cfg = current_app.config
    throttle_key = (request.remote_addr, username.lower())
    if login_throttle.is_blocked(throttle_key, cfg["LOGIN_MAX_ATTEMPTS"], cfg["LOGIN_WINDOW_SECONDS"]):
        return jsonify({"error": "Too many failed attempts, try again later"}), 429

    # ORM query: username is passed as a bound parameter, not concatenated.
    user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

    if user is None:
        bcrypt.checkpw(password.encode("utf-8"), _get_dummy_hash())
        valid = False
    else:
        valid = user.check_password(password)

    if not valid:
        login_throttle.register_failure(throttle_key, cfg["LOGIN_WINDOW_SECONDS"])
        # Same message for unknown user and wrong password (no user enumeration).
        return jsonify({"error": "Invalid username or password"}), 401

    login_throttle.reset(throttle_key)
    return jsonify(
        {
            "access_token": create_access_token(user),
            "token_type": "Bearer",  # nosec B105 - token scheme name, not a password
            "expires_in": cfg["JWT_EXPIRES_MINUTES"] * 60,
        }
    )


# --------------------------------------------------------------- GET /api/data

@api_bp.get("/data")
@jwt_required
def get_data():
    """List posts. Optional ?search= filters by title (parameterized LIKE)."""
    query = db.select(Post).order_by(Post.id)

    search = request.args.get("search", "")
    if search:
        if len(search) > TITLE_MAX:
            return _bad_request("Search string too long")
        # Escape LIKE wildcards; the value itself is still a bound parameter.
        pattern = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(Post.title.ilike(f"%{pattern}%", escape="\\"))

    posts = db.session.execute(query).scalars().all()
    items = [
        {
            "id": p.id,
            "title": p.title,
            "content": p.content,
            "author": p.author.username,
            "created_at": p.created_at.isoformat(),
        }
        for p in posts
    ]
    return jsonify(
        {
            "user": sanitize(g.current_user.to_public_dict()),
            "count": len(items),
            "items": sanitize(items),
        }
    )


# -------------------------------------------------------------- POST /api/posts

@api_bp.post("/posts")
@jwt_required
def create_post():
    """Create a post on behalf of the authenticated user."""
    body = _json_body()
    if body is None:
        return _bad_request("Expected JSON object body")

    title = body.get("title")
    content = body.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        return _bad_request("Fields 'title' and 'content' must be strings")
    title, content = title.strip(), content.strip()
    if not title or len(title) > TITLE_MAX:
        return _bad_request(f"Title must be 1..{TITLE_MAX} characters")
    if not content or len(content) > CONTENT_MAX:
        return _bad_request(f"Content must be 1..{CONTENT_MAX} characters")

    # Author is taken from the verified token, never from the request body.
    post = Post(title=title, content=content, author=g.current_user)
    db.session.add(post)
    db.session.commit()

    result = {
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "author": post.author.username,
        "created_at": post.created_at.isoformat(),
    }
    return jsonify(sanitize(result)), 201
