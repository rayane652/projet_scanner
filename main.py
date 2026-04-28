import os
import secrets
import sqlite3
import json
import threading
from datetime import datetime
from urllib.parse import urlencode

from flask import Flask, render_template, request, redirect, url_for, session
import requests
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler

# 🔥 IMPORT YOUR MODULES
from modules.auth_scanner import run_authenticated_checks
from modules.web_scanner import scan_website
from modules.cve_scanner import search_cves
from modules.risk_report import build_security_report
from modules.utils import resolve_host
from modules.vuln_engine import run_vuln_scan

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    TEMPLATES_AUTO_RELOAD=True,
    SEND_FILE_MAX_AGE_DEFAULT=0,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnix.db")


class NoServerHeaderRequestHandler(WSGIRequestHandler):
    def version_string(self):
        return ""


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_scans_table():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            scan_mode TEXT,
            status TEXT NOT NULL DEFAULT 'scanning',
            result_json TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def ensure_users_schema():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
    )

    columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(users)").fetchall()
    }
    if "auth_provider" not in columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'"
        )
    if "google_sub" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")

    conn.commit()
    conn.close()


def get_google_oauth_config():
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI") or url_for(
        "google_callback",
        _external=True,
    )
    return client_id, client_secret, redirect_uri


def execute_scan(scan_type, scan_mode, target, form_data):
    if scan_type == "security":
        ip = resolve_host(target)
        if not ip:
            return {"error": "Invalid target"}

        port_results = run_vuln_scan(ip)
        web_result = scan_website(target)
        auth_result = None

        if scan_mode == "authenticated":
            auth_result = run_authenticated_checks(
                target,
                form_data.get("auth_type"),
                form_data.get("auth_username"),
                form_data.get("auth_password"),
            )

        return build_security_report(
            target,
            port_results=port_results,
            web_result=web_result,
            scan_mode=scan_mode,
            auth_result=auth_result,
        )

    if scan_type == "port":
        ip = resolve_host(target)
        if not ip:
            return {"error": "Invalid target"}
        return run_vuln_scan(ip)

    if scan_type == "web":
        return scan_website(target)

    if scan_type == "cve":
        return search_cves(target, "")

    return {"error": "Unsupported scan type"}


def run_scan_job(scan_id, scan_type, scan_mode, target, form_data):
    try:
        result = execute_scan(scan_type, scan_mode, target, form_data)
        conn = get_db_connection()
        conn.execute(
            """
            UPDATE scans
            SET status = ?, result_json = ?, error_message = NULL, completed_at = ?
            WHERE id = ?
            """,
            ("done", json.dumps(result, default=str), datetime.utcnow().isoformat(), scan_id),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        conn = get_db_connection()
        conn.execute(
            """
            UPDATE scans
            SET status = ?, error_message = ?, completed_at = ?
            WHERE id = ?
            """,
            ("failed", str(exc), datetime.utcnow().isoformat(), scan_id),
        )
        conn.commit()
        conn.close()


def fetch_user_scans(user_email):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, target, scan_type, scan_mode, status, created_at, completed_at
        FROM scans
        WHERE user_email = ?
        ORDER BY id DESC
        """,
        (user_email,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_scan(scan_id, user_email):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_email = ?",
        (scan_id, user_email),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def build_dashboard_data(user_email):
    scans = fetch_user_scans(user_email)
    total_scans = len(scans)
    running_scans = sum(1 for scan in scans if scan["status"] == "scanning")
    failed_scans = sum(1 for scan in scans if scan["status"] == "failed")
    done_scans = sum(1 for scan in scans if scan["status"] == "done")

    scan_type_counts = {
        "security": 0,
        "web": 0,
        "port": 0,
        "cve": 0,
    }
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for scan in scans:
        scan_type = (scan.get("scan_type") or "").lower()
        if scan_type in scan_type_counts:
            scan_type_counts[scan_type] += 1

        if scan["status"] != "done":
            continue

        full_scan = fetch_scan(scan["id"], user_email)
        if not full_scan or not full_scan.get("result_json"):
            continue

        try:
            payload = json.loads(full_scan["result_json"])
        except json.JSONDecodeError:
            continue

        if not isinstance(payload, dict):
            continue

        risk_level = (payload.get("risk_level") or "").lower()
        if risk_level in severity_counts:
            severity_counts[risk_level] += 1

    completion_rate = 0
    if total_scans:
        completion_rate = int((done_scans / total_scans) * 100)

    return {
        "total_scans": total_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "done_scans": done_scans,
        "completion_rate": completion_rate,
        "scan_type_counts": scan_type_counts,
        "severity_counts": severity_counts,
        "recent_scans": scans[:8],
    }


ensure_scans_table()
ensure_users_schema()


# ================= HOME =================
@app.route("/")
def home():
    return render_template("main.html")


# ================= DASHBOARD =================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))
    ensure_scans_table()
    dashboard_data = build_dashboard_data(session["user"]["email"])

    return render_template(
        "dashboard.html",
        user=session["user"],
        active="dashboard",
        dashboard_data=dashboard_data,
    )


# ================= SCAN PAGE =================
@app.route("/scan")
def scan():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "scan.html",
        user=session["user"],
        active="scan"
    )


# ================= RUN SCAN (🔥 IMPORTANT) =================
@app.route("/run_scan", methods=["POST"])
def run_scan():
    if "user" not in session:
        return redirect(url_for("home"))
    ensure_scans_table()

    scan_type = request.form.get("type")
    scan_mode = request.form.get("scan_mode", "unauthenticated")
    target = request.form.get("target")
    form_data = {
        "auth_type": request.form.get("auth_type"),
        "auth_username": request.form.get("auth_username"),
        "auth_password": request.form.get("auth_password"),
    }

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (user_email, target, scan_type, scan_mode, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session["user"]["email"],
            target,
            scan_type,
            scan_mode,
            "scanning",
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()

    worker = threading.Thread(
        target=run_scan_job,
        args=(scan_id, scan_type, scan_mode, target, form_data),
        daemon=True,
    )
    worker.start()

    return redirect(url_for("result", scan_id=scan_id))


# ================= ASSETS =================
@app.route("/asset")
def asset():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "asset.html",
        user=session["user"],
        active="asset"
    )


# ================= RESULTS =================
@app.route("/result")
def result():
    if "user" not in session:
        return redirect(url_for("home"))
    ensure_scans_table()

    user_email = session["user"]["email"]
    scans = fetch_user_scans(user_email)

    selected_scan = None
    selected_scan_id = request.args.get("scan_id", type=int)
    if selected_scan_id:
        selected_scan = fetch_scan(selected_scan_id, user_email)
    elif scans:
        selected_scan = fetch_scan(scans[0]["id"], user_email)

    result_payload = None
    target = None
    scan_type = None
    scan_error = None
    if selected_scan:
        target = selected_scan["target"]
        scan_type = selected_scan["scan_type"]
        scan_error = selected_scan.get("error_message")
        if selected_scan.get("result_json"):
            result_payload = json.loads(selected_scan["result_json"])

    return render_template(
        "result.html",
        user=session["user"],
        active="result",
        scans=scans,
        selected_scan=selected_scan,
        results=result_payload,
        target=target,
        scan_type=scan_type,
        scan_error=scan_error,
    )


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    if "user" not in session:
        return redirect(url_for("home"))
    ensure_scans_table()

    conn = get_db_connection()
    conn.execute(
        "DELETE FROM scans WHERE id = ? AND user_email = ?",
        (scan_id, session["user"]["email"]),
    )
    conn.commit()
    conn.close()
    return redirect(url_for("result"))


# ================= SIGNUP =================
@app.route("/signup", methods=["POST"])
def signup():
    ensure_users_schema()
    name = request.form.get("name")
    email = request.form.get("email")
    password = generate_password_hash(request.form.get("password", ""))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (name, email, password, auth_provider) VALUES (?, ?, ?, ?)",
            (name, email, password, "local")
        )
        conn.commit()
    except:
        conn.close()
        return render_template(
            "main.html",
            message="Email already exists ❌",
            show_login=False
        )

    conn.close()

    session["user"] = {
        "name": name,
        "email": email
    }

    return redirect(url_for("dashboard"))


# ================= LOGIN =================
@app.route("/login", methods=["POST"])
def login():
    ensure_users_schema()
    email = request.form.get("email")
    password = request.form.get("password")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, email, password, auth_provider FROM users WHERE email=?",
        (email,)
    )

    user = cursor.fetchone()

    valid_password = False

    if user:
        stored_password = user[2]
        auth_provider = user[3] if len(user) > 3 else "local"

        if auth_provider == "google":
            conn.close()
            return render_template(
                "main.html",
                message="This account uses Google Sign-In. Please continue with Google.",
                show_login=True
            )

        try:
            valid_password = check_password_hash(stored_password, password)
        except ValueError:
            valid_password = False

        if not valid_password and stored_password == password:
            valid_password = True
            cursor.execute(
                "UPDATE users SET password=? WHERE email=?",
                (generate_password_hash(password), email)
            )
            conn.commit()

    conn.close()

    if user and valid_password:
        session["user"] = {
            "name": user[0],
            "email": user[1]
        }
        return redirect(url_for("dashboard"))
    else:
        return render_template(
            "main.html",
            message="Invalid credentials ❌",
            show_login=True
        )


@app.route("/auth/google")
def google_auth():
    ensure_users_schema()
    client_id, client_secret, redirect_uri = get_google_oauth_config()
    if not client_id or not client_secret:
        return render_template(
            "main.html",
            message="Google Sign-In is not configured yet.",
            show_login=True
        )

    state = secrets.token_urlsafe(24)
    session["google_oauth_state"] = state

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(auth_url)


@app.route("/auth/google/callback")
def google_callback():
    ensure_users_schema()
    expected_state = session.pop("google_oauth_state", None)
    returned_state = request.args.get("state")
    code = request.args.get("code")
    oauth_error = request.args.get("error")

    if oauth_error:
        return render_template(
            "main.html",
            message=f"Google auth error: {oauth_error}",
            show_login=True
        )

    if not expected_state or expected_state != returned_state or not code:
        return render_template(
            "main.html",
            message="Google authentication failed (invalid state).",
            show_login=True
        )

    client_id, client_secret, redirect_uri = get_google_oauth_config()
    if not client_id or not client_secret:
        return render_template(
            "main.html",
            message="Google Sign-In is not configured yet.",
            show_login=True
        )

    try:
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=20,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise ValueError("Missing Google access token.")

        userinfo_resp = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20,
        )
        userinfo_resp.raise_for_status()
        profile = userinfo_resp.json()
    except Exception as exc:
        return render_template(
            "main.html",
            message=f"Google Sign-In failed: {exc}",
            show_login=True
        )

    email = profile.get("email")
    name = profile.get("name") or (email.split("@")[0] if email else "Google User")
    google_sub = profile.get("sub")

    if not email:
        return render_template(
            "main.html",
            message="Google account does not provide an email.",
            show_login=True
        )

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, email, auth_provider FROM users WHERE email=?",
        (email,),
    )
    user = cursor.fetchone()

    if user:
        current_provider = user[3] if len(user) > 3 else "local"
        if current_provider == "local":
            cursor.execute(
                """
                UPDATE users
                SET google_sub=?, name=?
                WHERE email=?
                """,
                (google_sub, name, email),
            )
        else:
            cursor.execute(
                """
                UPDATE users
                SET auth_provider='google', google_sub=?, name=?
                WHERE email=?
                """,
                (google_sub, name, email),
            )
        conn.commit()
    else:
        random_password = generate_password_hash(secrets.token_hex(24))
        cursor.execute(
            """
            INSERT INTO users (name, email, password, auth_provider, google_sub)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, email, random_password, "google", google_sub),
        )
        conn.commit()

    conn.close()

    session["user"] = {
        "name": name,
        "email": email
    }
    return redirect(url_for("dashboard"))


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1",
        request_handler=NoServerHeaderRequestHandler,
    )

