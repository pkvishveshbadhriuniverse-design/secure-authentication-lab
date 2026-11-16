import pytest
from app import app, USERS_DB, limiter


@pytest.fixture
def client():
    app.config["TESTING"] = True
    USERS_DB.clear()
    limiter.reset()
    with app.test_client() as client:
        yield client


def test_password_hashing_and_validation(client):
    res = client.post("/register", json={"email": "alice@example.com", "password": "123"})
    assert res.status_code == 400

    res = client.post("/register", json={"email": "alice@example.com", "password": "StrongPass123"})
    assert res.status_code == 201
    stored_hash = USERS_DB["alice@example.com"]["password_hash"]
    assert stored_hash != "StrongPass123"
    assert ":" in stored_hash


def test_generic_authentication_errors(client):
    client.post("/register", json={"email": "alice@example.com", "password": "StrongPass123"})

    res_unknown = client.post("/login", json={"email": "nobody@example.com", "password": "WrongPass123"})
    res_wrong_pw = client.post("/login", json={"email": "alice@example.com", "password": "WrongPass123"})

    assert res_unknown.status_code == 401
    assert res_wrong_pw.status_code == 401
    assert res_unknown.get_json() == res_wrong_pw.get_json() == {"error": "Invalid email or password."}


def test_secure_cookie_flags_and_logout(client):
    client.post("/register", json={"email": "alice@example.com", "password": "StrongPass123"})
    res = client.post("/login", json={"email": "alice@example.com", "password": "StrongPass123"})
    assert res.status_code == 200

    cookie_header = res.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header
    assert "SameSite=Strict" in cookie_header

    logout_res = client.post("/logout")
    assert logout_res.status_code == 200
    profile_res = client.get("/profile")
    assert profile_res.status_code == 401


def test_login_rate_limiting(client):
    client.post("/register", json={"email": "alice@example.com", "password": "StrongPass123"})

    for _ in range(5):
        res = client.post("/login", json={"email": "alice@example.com", "password": "WrongPass123"})
        assert res.status_code == 401

    blocked = client.post("/login", json={"email": "alice@example.com", "password": "WrongPass123"})
    assert blocked.status_code == 429
