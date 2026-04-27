import os
import secrets
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler

# 🔥 IMPORT YOUR MODULES
from modules.web_scanner import scan_website
from modules.cve_scanner import search_cves
from modules.utils import resolve_host
from modules.vuln_engine import run_vuln_scan

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)


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


# ================= HOME =================
@app.route("/")
def home():
    return render_template("main.html")


# ================= DASHBOARD =================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        user=session["user"],
        active="dashboard"
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

    scan_type = request.form.get("type")
    target = request.form.get("target")

    result = None

    # ===== PORT SCAN =====
    if scan_type == "port":
        ip = resolve_host(target)

        if not ip:
            result = {"error": "Invalid target"}
        else:
            result = run_vuln_scan(ip)

    # ===== WEB SCAN =====
    elif scan_type == "web":
        result = scan_website(target)

    # ===== CVE SCAN =====
    elif scan_type == "cve":
        result = search_cves(target, "")

    return render_template(
        "result.html",
        user=session["user"],
        active="result",
        results=result,
        target=target,
        scan_type=scan_type
    )


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

    return render_template(
        "result.html",
        user=session["user"],
        active="result",
        results=None
    )


# ================= SIGNUP =================
@app.route("/signup", methods=["POST"])
def signup():
    name = request.form.get("name")
    email = request.form.get("email")
    password = generate_password_hash(request.form.get("password", ""))

    conn = sqlite3.connect("vulnix.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, password)
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
    email = request.form.get("email")
    password = request.form.get("password")

    conn = sqlite3.connect("vulnix.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, email, password FROM users WHERE email=?",
        (email,)
    )

    user = cursor.fetchone()

    valid_password = False

    if user:
        stored_password = user[2]

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

