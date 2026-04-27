from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

# 🔥 IMPORT YOUR MODULES
from modules.port_scanner import scan_ports
from modules.web_scanner import scan_website
from modules.cve_scanner import search_cves
from modules.utils import resolve_host
from modules.vuln_engine import run_vuln_scan

app = Flask(__name__)
app.secret_key = "vulnix_secret_key"


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
    password = request.form.get("password")

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

    return render_template(
        "main.html",
        message="Account created successfully ✅",
        show_login=True
    )


# ================= LOGIN =================
@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")

    conn = sqlite3.connect("vulnix.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, email FROM users WHERE email=? AND password=?",
        (email, password)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
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
    app.run(host="0.0.0.0", port=5000, debug=True)

