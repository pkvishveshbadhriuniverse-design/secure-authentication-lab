import re
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-local-lab-secret-key-change-in-prod"

# Secure Cookie Settings & Session Expiry
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

# Rate Limiting Configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://",
)

USERS_DB = {}
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_registration(email: str, password: str):
    if not email or not isinstance(email, str) or not EMAIL_REGEX.match(email.strip()):
        return "Invalid email address format."
    if not password or not isinstance(password, str) or len(password) < 10:
        return "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        return "Password must include at least one uppercase letter and one number."
    return None


@app.route("/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    validation_error = validate_registration(email, password)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    if email in USERS_DB:
        return jsonify({"error": "Unable to complete registration."}), 400

    USERS_DB[email] = {
        "password_hash": generate_password_hash(password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return jsonify({"message": "User registered successfully."}), 201


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = USERS_DB.get(email)

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401

    session.clear()
    session.permanent = True
    session["user_email"] = email
    return jsonify({"message": "Login successful."}), 200


@app.route("/profile", methods=["GET"])
def profile():
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized."}), 401
    return jsonify({"email": session["user_email"]}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    response = jsonify({"message": "Logged out successfully."})
    response.delete_cookie(app.config["SESSION_COOKIE_NAME"])
    return response, 200


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please try again later."}), 429


if __name__ == "__main__":
    app.run(debug=False)
