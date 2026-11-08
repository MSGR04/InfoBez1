"""Application factory."""
import os

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from .config import Config
from .models import Post, User, db
from .routes import api_bp, auth_bp
from .security import apply_security_headers

DEMO_USERS = [
    # (username, role, env var with the password, dev-only default)
    ("alice", "admin", "DEMO_ALICE_PASSWORD", "Alice_Passw0rd!"),
    ("bob", "user", "DEMO_BOB_PASSWORD", "Bob_Passw0rd!"),
]


def seed_demo_data() -> None:
    if db.session.execute(db.select(User).limit(1)).first() is not None:
        return
    users = {}
    for username, role, env_var, default in DEMO_USERS:
        user = User(username=username, role=role)
        user.set_password(os.environ.get(env_var, default))
        db.session.add(user)
        users[username] = user
    db.session.add_all(
        [
            Post(title="Welcome", content="First post of the secure API.", author=users["alice"]),
            Post(title="OWASP Top 10", content="Injection, broken auth, XSS...", author=users["bob"]),
        ]
    )
    db.session.commit()


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    # PyJWT does not enforce key length (CVE-2025-45770), so the app does.
    if len(app.config["JWT_SECRET"].encode("utf-8")) < app.config["JWT_SECRET_MIN_BYTES"]:
        raise RuntimeError("JWT_SECRET is too short: at least 32 bytes are required")

    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.after_request(apply_security_headers)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.errorhandler(HTTPException)
    def handle_http_error(err):
        return jsonify({"error": err.name}), err.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(err):
        # Never leak stack traces or internals to the client.
        app.logger.exception("Unhandled error")
        return jsonify({"error": "Internal server error"}), 500

    with app.app_context():
        db.create_all()
        seed_demo_data()

    return app
