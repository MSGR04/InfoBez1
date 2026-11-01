"""ORM models. All DB access goes through SQLAlchemy, which always sends
user input as bound parameters, never by string concatenation."""
from datetime import datetime, timezone

import bcrypt
from flask import current_app
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")

    posts = db.relationship("Post", back_populates="author", lazy="select")

    def set_password(self, password: str) -> None:
        rounds = current_app.config["BCRYPT_ROUNDS"]
        # bcrypt generates a unique random salt per hash.
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))
        self.password_hash = hashed.decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

    def to_public_dict(self) -> dict:
        return {"id": self.id, "username": self.username, "role": self.role}


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    author = db.relationship("User", back_populates="posts")
