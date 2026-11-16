# Secure Authentication Lab

A local Python/Flask authentication service demonstrating defensive authentication controls and automated security verification.

## Security Controls Implemented

### 1. Password Hashing & Server-Side Input Validation (`/register`)
* **Safe Password Storage:** Passwords are never stored in plaintext. `werkzeug.security.generate_password_hash` generates a salted cryptographic hash before storing user records.
* **Server-Side Validation:** All registration payloads are validated on the server before processing—enforcing valid email syntax, a minimum length of 10 characters, at least one uppercase letter, and at least one number.

### 2. Secure Cookie Settings, Session Expiry & Logout (`/login`, `/logout`)
* **Hardened Session Cookies:** Configured with `HttpOnly=True` (prevents JavaScript/XSS access), `Secure=True` (enforces HTTPS transport), and `SameSite=Strict` (prevents CSRF attacks).
* **Session Expiry & Rotation:** Sessions regenerate cleanly on login (`session.clear()`) to prevent session fixation and expire automatically after **15 minutes** (`PERMANENT_SESSION_LIFETIME`).
* **Explicit Logout:** Calling `/logout` clears server-side session data and instructs the browser to delete the session cookie.

### 3. Rate Limiting & Generic Authentication Errors (`/login`)
* **Brute-Force Protection:** `Flask-Limiter` restricts `/login` to **5 attempts per minute per IP**, returning HTTP `429 Too Many Requests` when exceeded.
* **Anti-Enumeration:** Failed login attempts return the identical generic message (`"Invalid email or password."` with HTTP `401`) whether the account does not exist or the password is incorrect.

## Repository Structure
* `app.py` — Flask authentication service implementing hashing, validation, secure sessions, and rate limiting.
* `test_auth.py` — Automated `pytest` suite verifying every defensive control.
* `test-output.txt` — Recorded test execution output (`4 passed`).
* `requirements.txt` — Project dependencies.

## How to Run & Verify Locally
```bash
pip install -r requirements.txt
pytest -v
