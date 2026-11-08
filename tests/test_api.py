"""Functional and security tests for the API."""
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app import create_app
from app.models import User, db
from app.security import login_throttle

TEST_SECRET = "test-secret-key-that-is-long-enough-for-hs256"


@pytest.fixture()
def app():
    login_throttle._failures.clear()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET": TEST_SECRET,
            "BCRYPT_ROUNDS": 4,
        }
    )
    yield app
    with app.app_context():
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="alice", password="Alice_Passw0rd!"):
    return client.post("/auth/login", json={"username": username, "password": password})


@pytest.fixture()
def auth_headers(client):
    token = login(client).get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- auth / JWT

def test_short_jwt_secret_is_rejected_at_startup():
    with pytest.raises(RuntimeError):
        create_app({"JWT_SECRET": "too-short", "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})


def test_login_success_returns_jwt(client):
    resp = login(client)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer"
    claims = jwt.decode(body["access_token"], TEST_SECRET, algorithms=["HS256"], issuer="secure-api-lab1")
    assert claims["username"] == "alice"


def test_login_wrong_password(client):
    resp = login(client, password="wrong")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid username or password"


def test_login_unknown_user_same_message(client):
    resp = login(client, username="nobody")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid username or password"


def test_login_requires_json(client):
    resp = client.post("/auth/login", data="username=alice&password=x")
    assert resp.status_code == 400


def test_login_bruteforce_lockout(client):
    for _ in range(5):
        assert login(client, password="wrong").status_code == 401
    # Even the correct password is refused while locked.
    assert login(client).status_code == 429


def test_passwords_are_hashed_with_bcrypt(app):
    with app.app_context():
        user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
        assert user.password_hash.startswith("$2b$")
        assert "Alice_Passw0rd!" not in user.password_hash


def test_data_without_token_is_forbidden(client):
    resp = client.get("/api/data")
    assert resp.status_code == 401


def test_data_with_invalid_token(client):
    resp = client.get("/api/data", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401


def test_data_with_wrong_signature(client):
    token = jwt.encode(
        {"sub": "1", "iss": "secure-api-lab1", "iat": datetime.now(timezone.utc),
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "attacker-secret-attacker-secret-attacker",
        algorithm="HS256",
    )
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_data_with_alg_none_token(client):
    token = jwt.encode(
        {"sub": "1", "iss": "secure-api-lab1", "iat": 0, "exp": 9999999999}, key=None, algorithm="none"
    )
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_data_with_expired_token(client):
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = jwt.encode(
        {"sub": "1", "iss": "secure-api-lab1", "iat": past, "exp": past + timedelta(minutes=1)},
        TEST_SECRET,
        algorithm="HS256",
    )
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Token expired"


def test_data_with_valid_token(client, auth_headers):
    resp = client.get("/api/data", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["user"]["username"] == "alice"
    assert body["count"] == 2


# ----------------------------------------------------------------------- SQLi

@pytest.mark.parametrize("payload", ["' OR '1'='1", "admin'--", "' OR 1=1; DROP TABLE users;--"])
def test_sqli_in_login_is_rejected(client, payload):
    resp = login(client, username=payload, password=payload)
    assert resp.status_code == 401


def test_sqli_in_search_is_harmless(client, auth_headers):
    resp = client.get("/api/data", query_string={"search": "' OR '1'='1"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0
    # Tables are still intact.
    assert login(client).status_code == 200


def test_search_filters_by_title(client, auth_headers):
    resp = client.get("/api/data", query_string={"search": "owasp"}, headers=auth_headers)
    assert resp.get_json()["count"] == 1


# ------------------------------------------------------------------------ XSS

def test_create_post_escapes_html(client, auth_headers):
    payload = {"title": "<script>alert(1)</script>", "content": '<img src=x onerror="alert(1)">'}
    resp = client.post("/api/posts", json=payload, headers=auth_headers)
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["title"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert "<img" not in body["content"]
    assert body["author"] == "alice"

    listed = client.get("/api/data", headers=auth_headers).get_json()["items"]
    assert all("<script>" not in item["title"] for item in listed)


def test_create_post_requires_token(client):
    resp = client.post("/api/posts", json={"title": "t", "content": "c"})
    assert resp.status_code == 401


def test_create_post_validation(client, auth_headers):
    resp = client.post("/api/posts", json={"title": "", "content": "c"}, headers=auth_headers)
    assert resp.status_code == 400


# -------------------------------------------------------------------- headers

def test_security_headers_present(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
