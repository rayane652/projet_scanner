import os
import secrets
import sqlite3
import json
import threading
from datetime import datetime
from urllib.parse import urlencode
from datetime import datetime, timedelta
from collections import defaultdict
from modules.ai_remediation import generate_remediation

# Load .env file (GEMINI_API_KEY etc.)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler

# 🔥 IMPORT YOUR MODULES
from modules.ai_analyst import answer_scan_question, build_ai_analysis
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
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            machine_name TEXT,
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
    columns = {
        row[1]
        for row in cursor.execute("PRAGMA table_info(scans)").fetchall()
    }
    if "machine_name" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN machine_name TEXT")
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
            return {
                "error": "Invalid target",
                "target": target,
                "message": "Vulnix could not resolve this target to an IP address.",
            }

        port_results = run_vuln_scan(
            ip,
            scan_method=form_data.get("tcp_scan_method") or "connect",
            include_udp=bool(form_data.get("include_udp")),
        )
        web_result = scan_website(target)
        auth_result = None

        if not port_results and web_result and web_result.get("error"):
            return {
                "error": True,
                "status": "failed",
                "title": "Host Unreachable",
                "message": (
                    "The target is offline, unreachable, or not responding "
                    "to HTTP/HTTPS requests."
                ),
                "recommendation": (
                    "Verify that the device is powered on, connected to the network, "
                    "and that the IP address is correct."
                )
            }

        if scan_mode == "authenticated":
            try:
                auth_result = run_authenticated_checks(
                    target,
                    form_data.get("auth_type"),
                    form_data.get("auth_username"),
                    form_data.get("auth_password"),
                    form_data.get("auth_port"),
                    form_data.get("auth_ssh_key"),
                )
            except Exception as e:
                auth_result = {
                    "status": "failed",
                    "error": str(e)
                }
                print("AUTH ERROR:", repr(e))

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
            return {
                "error": "Invalid target",
                "target": target,
                "message": "Vulnix could not resolve this target to an IP address.",
            }
        port_results = run_vuln_scan(
            ip,
            scan_method=form_data.get("tcp_scan_method") or "connect",
            include_udp=bool(form_data.get("include_udp")),
        )
        if not port_results:
            return {
                "error": "No reachable ports detected",
                "target": target,
                "resolved_ip": ip,
                "message": "No open ports were found in the scanned range.",
            }
        return port_results

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
            (
                "failed" if result.get("status") == "failed" else "done",
                json.dumps(result, default=str),
                datetime.utcnow().isoformat(),
                scan_id
            ),
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
        SELECT id, machine_name, target, scan_type, scan_mode, status, created_at, completed_at
        FROM scans
        WHERE user_email = ?
        ORDER BY created_at DESC, id DESC
        """,
        (user_email,),
    ).fetchall()
    conn.close()
    scans = [dict(row) for row in rows]
    for display_no, scan in enumerate(scans, start=1):
        scan["display_no"] = display_no
        scan["asset_label"] = scan.get("machine_name") or scan.get("target")
    return scans


def fetch_scan(scan_id, user_email):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_email = ?",
        (scan_id, user_email),
    ).fetchone()
    conn.close()
    if not row:
        return None

    scan = dict(row)
    display_no = 1
    for index, listed_scan in enumerate(fetch_user_scans(user_email), start=1):
        if listed_scan["id"] == scan["id"]:
            display_no = index
            break
    scan["display_no"] = display_no
    scan["asset_label"] = scan.get("machine_name") or scan.get("target")
    return scan


def load_scan_result(scan):
    if not scan or not scan.get("result_json"):
        return None, None

    try:
        return json.loads(scan["result_json"]), None
    except (TypeError, json.JSONDecodeError) as exc:
        return None, f"Saved scan result could not be read: {exc}"


def _empty_severity_counts():
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


RISK_COLORS = {
    "critical": "#7f1d1d",
    "high": "#ef4444",
    "medium": "#f97316",
    "low": "#22c55e",
    "info": "#64748b",
}


def _to_int(value, default=0):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def risk_level_from_score(score):
    score = max(0, min(100, _to_int(score)))
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_severity_breakdown(counts, include_info=False):
    rows = [
        {
            "slug": "critical",
            "key": "critical",
            "label": "Critical",
            "count": _to_int(counts.get("critical")),
        },
        {
            "slug": "high",
            "key": "high",
            "label": "High",
            "count": _to_int(counts.get("high")),
        },
        {
            "slug": "medium",
            "key": "medium",
            "label": "Medium",
            "count": _to_int(counts.get("medium")),
        },
        {
            "slug": "low",
            "key": "low",
            "label": "Low",
            "count": _to_int(counts.get("low")),
        },
    ]
    if include_info:
        rows.append({
            "slug": "info",
            "key": "info",
            "label": "Info",
            "count": _to_int(counts.get("info")),
        })

    total = sum(row["count"] for row in rows) or 1
    for row in rows:
        row["percent"] = int((row["count"] / total) * 100)

    return rows


def build_severity_ring_style(counts):
    visible_counts = [
        (item["slug"], item["count"])
        for item in build_severity_breakdown(counts, include_info=True)
        if item["count"] > 0
    ]
    if not visible_counts:
        return f"conic-gradient({RISK_COLORS['low']} 0% 100%)"

    total = sum(count for _, count in visible_counts)
    current = 0
    segments = []

    for slug, count in visible_counts:
        start = current / total * 100
        current += count
        end = current / total * 100
        segments.append(f"{RISK_COLORS[slug]} {start:.2f}% {end:.2f}%")

    return "conic-gradient(" + ", ".join(segments) + ")"


def normalize_counts(counts):
    counts = counts if isinstance(counts, dict) else {}
    normalized = _empty_severity_counts()
    for key in normalized:
        normalized[key] = _to_int(counts.get(key))
    return normalized


def summarize_scan_payload(payload):
    summary = {
        "risk_level": "LOW",
        "risk_class": "low",
        "risk_score": 0,
        "severity_counts": _empty_severity_counts(),
        "findings": 0,
        "open_ports": 0,
        "vulnerabilities": 0,
    }

    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            for cve in item.get("cves") or [item]:
                if not isinstance(cve, dict):
                    continue
                severity = str(cve.get("severity") or "").lower()
                if severity in summary["severity_counts"]:
                    summary["severity_counts"][severity] += 1
        summary["findings"] = sum(summary["severity_counts"].values())
        summary["vulnerabilities"] = summary["findings"]
        summary["open_ports"] = len([item for item in payload if isinstance(item, dict) and item.get("port")])
    elif not isinstance(payload, dict) or payload.get("error"):
        return summary
    else:
        counts = payload.get("severity_counts") or {}
        summary["severity_counts"] = normalize_counts(counts)

        for finding in payload.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "").lower()
            if severity in summary["severity_counts"] and not counts:
                summary["severity_counts"][severity] += 1

        summary["risk_score"] = _to_int(payload.get("risk_score"))
        payload_summary = payload.get("summary") or {}
        if not isinstance(payload_summary, dict):
            payload_summary = {}
        summary["findings"] = _to_int(
            payload_summary.get("findings")
            or payload_summary.get("scanned_items")
            or sum(summary["severity_counts"].values())
        )
        summary["open_ports"] = _to_int(payload_summary.get("open_ports"))
        summary["vulnerabilities"] = _to_int(
            payload_summary.get("vulnerabilities")
            or sum(summary["severity_counts"].values())
        )

    if not summary["risk_score"]:
        summary["risk_score"] = min(
            100,
            summary["severity_counts"]["critical"] * 25
            + summary["severity_counts"]["high"] * 16
            + summary["severity_counts"]["medium"] * 8
            + summary["severity_counts"]["low"] * 3
        )
    summary["risk_level"] = risk_level_from_score(summary["risk_score"])
    summary["risk_class"] = summary["risk_level"].lower()
    return summary


def decorate_result_payload(payload):
    if not isinstance(payload, dict) or payload.get("error"):
        return payload

    summary = summarize_scan_payload(payload)
    payload["risk_score"] = max(0, min(100, _to_int(summary["risk_score"])))
    payload["risk_level"] = summary["risk_level"]
    payload["risk_class"] = summary["risk_class"]
    payload["severity_counts"] = summary["severity_counts"]
    payload["severity_breakdown"] = build_severity_breakdown(
        summary["severity_counts"],
        include_info=True,
    )
    payload["severity_ring_style"] = build_severity_ring_style(summary["severity_counts"])
    return payload


def humanize_timestamp(value):
    if not value:
        return "Never"

    try:
        scanned_at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)

    if scanned_at.tzinfo is not None:
        scanned_at = scanned_at.replace(tzinfo=None)

    seconds = max(0, int((datetime.utcnow() - scanned_at).total_seconds()))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} min ago"
    if seconds < 86400:
        hours = seconds // 3600
        return f"{hours}h ago"
    if seconds < 604800:
        days = seconds // 86400
        return f"{days}d ago"
    return scanned_at.strftime("%b %d, %Y")


def infer_online_status(scan, payload):
    if not scan or scan.get("status") != "done" or payload is None:
        return False

    if isinstance(payload, list):
        return any(isinstance(item, dict) and item.get("port") for item in payload)

    if not isinstance(payload, dict) or payload.get("error"):
        return False

    if payload.get("status_code") or payload.get("final_url"):
        return True

    summary = payload.get("summary") or {}
    if isinstance(summary, dict) and (
        _to_int(summary.get("open_ports"))
        or _to_int(summary.get("services"))
        or _to_int(summary.get("web_paths"))
    ):
        return True

    raw_web = ((payload.get("raw") or {}).get("web") or {})
    if isinstance(raw_web, dict) and not raw_web.get("error") and (
        raw_web.get("status_code") or raw_web.get("final_url")
    ):
        return True

    return False


def extract_os_badge(payload):
    profile = payload.get("system_profile") if isinstance(payload, dict) else {}
    profile = profile if isinstance(profile, dict) else {}
    family = profile.get("family") or ""
    name = profile.get("name") or ""
    text_parts = [family, name]
    detected_ports = set()

    if isinstance(payload, dict):
        raw = payload.get("raw") or {}
        ports = raw.get("ports") if isinstance(raw, dict) else []
        if isinstance(ports, list):
            detected_ports.update(
                port.get("port") for port in ports if isinstance(port, dict)
            )
            text_parts.extend(str(port.get("banner") or "") for port in ports if isinstance(port, dict))
            text_parts.extend(str(port.get("service") or "") for port in ports if isinstance(port, dict))
        raw_web = raw.get("web") if isinstance(raw, dict) else {}
        if isinstance(raw_web, dict):
            text_parts.extend([
                str(raw_web.get("server") or ""),
                str(raw_web.get("powered_by") or ""),
                " ".join(raw_web.get("technologies") or [])
                if isinstance(raw_web.get("technologies"), list)
                else "",
            ])
        text_parts.extend([
            str(payload.get("server") or ""),
            " ".join(payload.get("technologies") or []) if isinstance(payload.get("technologies"), list) else "",
        ])
    elif isinstance(payload, list):
        detected_ports.update(
            item.get("port") for item in payload if isinstance(item, dict)
        )
        text_parts.extend(str(item.get("banner") or "") for item in payload if isinstance(item, dict))
        text_parts.extend(str(item.get("service") or "") for item in payload if isinstance(item, dict))

    combined = " ".join(text_parts).lower()
    detected_ports.discard(None)

    if 5555 in detected_ports:
        return {"label": "Android", "class": "android", "icon": "fa-brands fa-android"}
    if {135, 139, 445, 3389, 5985, 5986} & detected_ports:
        return {"label": "Windows", "class": "windows", "icon": "fa-brands fa-windows"}
    if "windows" in combined or "microsoft" in combined or "rdp" in combined or "smb" in combined:
        return {"label": "Windows", "class": "windows", "icon": "fa-brands fa-windows"}
    if "android" in combined or "adb" in combined:
        return {"label": "Android", "class": "android", "icon": "fa-brands fa-android"}
    if "ubuntu" in combined:
        return {"label": "Ubuntu", "class": "linux", "icon": "fa-brands fa-linux"}
    if "debian" in combined:
        return {"label": "Debian", "class": "linux", "icon": "fa-brands fa-linux"}
    if "kali" in combined:
        return {"label": "Kali", "class": "linux", "icon": "fa-brands fa-linux"}
    if "metasploitable" in combined:
        return {"label": "Metasploitable", "class": "linux", "icon": "fa-brands fa-linux"}
    if "linux" in combined or "unix" in combined or "openssh" in combined or "ssh" in combined:
        return {"label": "Linux", "class": "linux", "icon": "fa-brands fa-linux"}
    if {21, 22, 25, 111, 2049, 5432, 6379} & detected_ports:
        return {"label": "Linux", "class": "linux", "icon": "fa-brands fa-linux"}
    return {"label": "Unknown", "class": "unknown", "icon": "fa-solid fa-circle-question"}


def decorate_asset(asset):
    asset["risk_score"] = max(0, min(100, _to_int(asset.get("risk_score"))))
    asset["risk_level"] = risk_level_from_score(asset["risk_score"])
    asset["risk_class"] = asset["risk_level"].lower()
    asset["risk_label"] = f"{asset['risk_level']} RISK"
    asset["last_scan_human"] = humanize_timestamp(asset.get("last_seen"))

    counts = normalize_counts(asset.get("severity_counts"))
    asset["severity_counts"] = counts
    asset["severity_rows"] = []
    for row in build_severity_breakdown(counts):
        count = row["count"]
        row["width"] = min(100, count * 25) if count else 0
        asset["severity_rows"].append(row)

    return asset


def build_asset_page_stats(assets):
    total_assets = len(assets)
    return {
        "total_assets": total_assets,
        "online_assets": sum(1 for asset in assets if asset.get("is_online")),
        "high_risk_assets": sum(
            1 for asset in assets if asset.get("risk_level") in ("HIGH", "CRITICAL")
        ),
        "average_risk_score": round(
            sum(asset.get("risk_score", 0) for asset in assets) / total_assets,
            1,
        ) if total_assets else 0,
        "total_scans": sum(asset.get("scan_count", 0) for asset in assets),
    }


def fetch_user_assets(user_email):
    scans = fetch_user_scans(user_email)
    assets_by_key = {}

    for scan_item in scans:
        key = (
            (scan_item.get("machine_name") or scan_item.get("target") or "").strip().lower(),
            scan_item.get("target"),
        )
        asset = assets_by_key.setdefault(key, {
            "name": scan_item.get("machine_name") or scan_item.get("target") or "Unnamed machine",
            "target": scan_item.get("target"),
            "scan_count": 0,
            "latest_scan_id": scan_item.get("id"),
            "latest_status": scan_item.get("status"),
            "latest_scan_type": scan_item.get("scan_type"),
            "last_seen": scan_item.get("completed_at") or scan_item.get("created_at"),
            "risk_level": "LOW",
            "risk_class": "low",
            "risk_score": 0,
            "severity_counts": _empty_severity_counts(),
            "findings": 0,
            "open_ports": 0,
            "vulnerabilities": 0,
            "os_label": "Unknown",
            "os_class": "unknown",
            "os_icon": "fa-solid fa-circle-question",
            "is_online": False,
            "_has_result_summary": False,
        })
        asset["scan_count"] += 1

        if asset["scan_count"] == 1:
            asset["latest_scan_id"] = scan_item.get("id")
            asset["latest_status"] = scan_item.get("status")
            asset["latest_scan_type"] = scan_item.get("scan_type")
            asset["last_seen"] = scan_item.get("completed_at") or scan_item.get("created_at")

        full_scan = fetch_scan(scan_item["id"], user_email)
        if not full_scan or not full_scan.get("result_json"):
            continue
        payload, _ = load_scan_result(full_scan)
        if payload is None:
            continue
        if not asset["_has_result_summary"]:
            payload = decorate_result_payload(payload)
            os_badge = extract_os_badge(payload)
            asset.update(summarize_scan_payload(payload))
            asset["os_label"] = os_badge["label"]
            asset["os_class"] = os_badge["class"]
            asset["os_icon"] = os_badge["icon"]
            asset["is_online"] = infer_online_status(full_scan, payload)
            asset["_has_result_summary"] = True

    for asset in assets_by_key.values():
        decorate_asset(asset)
        asset.pop("_has_result_summary", None)

    return sorted(
        assets_by_key.values(),
        key=lambda item: (item.get("last_seen") or ""),
        reverse=True,
    )

def build_dashboard_data(user_email):
    scans  = fetch_user_scans(user_email)
    assets = fetch_user_assets(user_email)
 
    total_scans   = len(scans)
    running_scans = sum(1 for s in scans if s["status"] == "scanning")
    failed_scans  = sum(1 for s in scans if s["status"] == "failed")
    done_scans    = sum(1 for s in scans if s["status"] == "done")
 
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scan_type_counts = {"security": 0, "web": 0, "port": 0, "cve": 0}
    total_vulns = 0
    fixed_vulns = 0
 
    # ── Ports aggregation ──
    ports_map = defaultdict(lambda: {"count": 0, "service": ""})
 
    # ── Risk trend: last 14 days ──
    today = datetime.utcnow().date()
    trend_days   = [(today - timedelta(days=13 - i)) for i in range(14)]
    trend_labels = [d.strftime("%b %d") for d in trend_days]
    trend_data   = {d: {"critical": 0, "high": 0, "medium": 0} for d in trend_days}
 
    # ── Running scan IDs (for live polling) ──
    running_scan_ids = [s["id"] for s in scans if s["status"] == "scanning"]
 
    for scan in scans:
        # Count scan types
        stype = (scan.get("scan_type") or "").lower()
        if stype in scan_type_counts:
            scan_type_counts[stype] += 1
 
        if scan["status"] != "done":
            continue
 
        full_scan = fetch_scan(scan["id"], user_email)
        if not full_scan or not full_scan.get("result_json"):
            continue
        try:
            payload = json.loads(full_scan["result_json"])
        except:
            continue
 
        summary = summarize_scan_payload(payload)
 
        for key in severity_counts:
            severity_counts[key] += summary["severity_counts"][key]
 
        total_vulns += summary["vulnerabilities"]
 
        # ── Aggregate open ports ──
        port_list = []
        if isinstance(payload, list):
            port_list = [
                item for item in payload
                if isinstance(item, dict) and item.get("port")
            ]
        elif isinstance(payload, dict):
            port_list = payload.get("ports") or payload.get("open_ports_list") or []
 
        for item in port_list:
            port_num = str(item.get("port", ""))
            if port_num:
                ports_map[port_num]["count"] += 1
                ports_map[port_num]["service"] = (
                    item.get("service") or item.get("name") or _guess_service(port_num)
                )
 
        # ── Risk trend bucketing ──
        created_str = scan.get("completed_at") or scan.get("created_at") or ""
        try:
            scan_date = datetime.fromisoformat(created_str[:10]).date()
        except:
            continue
        if scan_date in trend_data:
            for sev in ("critical", "high", "medium"):
                trend_data[scan_date][sev] += summary["severity_counts"][sev]
 
    # Build top ports list (sorted by count)
    top_ports = sorted(
        [{"port": k, **v} for k, v in ports_map.items()],
        key=lambda x: -x["count"]
    )[:8]
 
    # Fixed vulns heuristic
    previous_total = sum(a.get("vulnerabilities", 0) for a in assets)
    fixed_vulns = max(0, previous_total - total_vulns)
 
    completion_rate = int((done_scans / total_scans) * 100) if total_scans else 0
 
    return {
        "total_scans":      total_scans,
        "running_scans":    running_scans,
        "failed_scans":     failed_scans,
        "done_scans":       done_scans,
        "completion_rate":  completion_rate,
        "severity_counts":  severity_counts,
        "scan_type_counts": scan_type_counts,
        "recent_scans":     scans[:8],
        "assets":           assets,
        "total_assets":     len(assets),
        "total_vulns":      total_vulns,
        "fixed_vulns":      fixed_vulns,
        "top_ports":        top_ports,
        "total_open_ports": sum(p["count"] for p in top_ports),
        "running_scan_ids": running_scan_ids,
        "risk_trend": {
            "labels":   trend_labels,
            "critical": [trend_data[d]["critical"] for d in trend_days],
            "high":     [trend_data[d]["high"]     for d in trend_days],
            "medium":   [trend_data[d]["medium"]   for d in trend_days],
        }
    }

def _guess_service(port):
    COMMON = {
        "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
        "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP",
        "443": "HTTPS", "445": "SMB", "3306": "MySQL", "3389": "RDP",
        "5432": "PostgreSQL", "6379": "Redis", "8080": "HTTP-Alt",
        "8443": "HTTPS-Alt", "27017": "MongoDB"
    }
    return COMMON.get(str(port), "Unknown")

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
def scan_page():
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

    scan_type = (
        request.form.get("scan_type")
        or request.form.get("type")
        or "security"
    )
    scan_mode = request.form.get("scan_mode", "unauthenticated")
    target = request.form.get("target")
    print("TARGET =", repr(target))
    machine_name = (
        request.form.get("machine_name")
        or request.form.get("asset_name")
        or request.form.get("name")
        or ""
    ).strip()
    form_data = {
        "auth_type": request.form.get("auth_type"),
        "auth_username": request.form.get("auth_username"),
        "auth_password": request.form.get("auth_password"),
        "auth_port": request.form.get("auth_port"),
        "auth_ssh_key": request.form.get("auth_ssh_key"),
        "tcp_scan_method": request.form.get("tcp_scan_method", "connect"),
        "include_udp": request.form.get("include_udp") in {"1", "on", "true"},
    }

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (user_email, machine_name, target, scan_type, scan_mode, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user"]["email"],
            machine_name or target,
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
def asset_page():
    if "user" not in session:
        return redirect(url_for("home"))
    ensure_scans_table()
    user_email = session["user"]["email"]
    scans = fetch_user_scans(user_email)
    assets = fetch_user_assets(user_email)
    asset_stats = build_asset_page_stats(assets)
    return render_template(
        "asset.html",
        user=session["user"],
        active="asset",
        assets=assets,
        asset_stats=asset_stats,
        scans=scans,
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
            try:
                result_payload = json.loads(selected_scan["result_json"])
                result_payload = decorate_result_payload(result_payload)
            except:
                result_payload = None

    findings = (result_payload or {}).get("findings", [])


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

    user_email = session["user"]["email"]

    conn = get_db_connection()
    conn.execute(
        "DELETE FROM scans WHERE id = ? AND user_email = ?",
        (scan_id, user_email),
    )
    conn.commit()
    conn.close()

    remaining_scans = fetch_user_scans(user_email)

    if remaining_scans:
        return redirect(url_for("result", scan_id=remaining_scans[0]["id"]))

    return redirect(url_for("result"))

@app.route("/scan/<int:scan_id>/ai-chat", methods=["POST"])
def ai_chat(scan_id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    selected_scan = fetch_scan(scan_id, session["user"]["email"])
    if not selected_scan or not selected_scan.get("result_json"):
        return jsonify({"error": "Scan result not found"}), 404

    try:
        payload = json.loads(selected_scan["result_json"])
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid scan result"}), 400

    if not isinstance(payload, dict):
        return jsonify({
            "answer": "AI chat is available for Security Scan reports only."
        })

    body     = request.get_json(silent=True) or {}
    question = body.get("question", "")
    history  = body.get("history") or []
    # Sanitise: only allow role/content keys to reach the AI
    safe_history = [
        {"role": str(m.get("role", "user"))[:16], "content": str(m.get("content", ""))[:2000]}
        for m in history
        if isinstance(m, dict) and m.get("role") in ("user", "assistant") and m.get("content")
    ]
    return jsonify({"answer": answer_scan_question(payload, question, safe_history)})


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

@app.route("/update-name", methods=["POST"])
def update_name():
    if "user" not in session:
        return {"status": "error"}, 401

    data = request.get_json()
    new_name = data.get("name", "").strip()

    if not new_name:
        return {"status": "error"}, 400

    # 🔥 update DB
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET name=? WHERE email=?",
        (new_name, session["user"]["email"])
    )
    conn.commit()
    conn.close()

    # 🔥 update session (IMPORTANT)
    session["user"]["name"] = new_name

    return {"status": "success"}


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

@app.route("/api/scan_status/<int:scan_id>")
def api_scan_status(scan_id):
    """Real-time scan progress — polled by dashboard JS every 2.5s"""
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
 
    scan = fetch_scan(scan_id, session["user"]["email"])
    if not scan:
        return jsonify({"error": "not found"}), 404
 
    result = {}
    if scan.get("result_json"):
        try:
            result = json.loads(scan["result_json"])
        except:
            pass
 
    # If scan is done or failed, progress = 100
    if scan["status"] == "done":
        progress_pct = 100
    elif scan["status"] == "failed":
        progress_pct = 0
    else:
        # Real progress stored by scan modules in result_json
        progress_pct = int(result.get("progress_pct", 0) or 0)
 
    return jsonify({
        "id":           scan_id,
        "target":       scan.get("target"),
        "scan_type":    scan.get("scan_type"),
        "status":       scan["status"],
        "progress_pct": progress_pct,
        "phase":        result.get("phase", scan["status"].title()),
        "eta_seconds":  int(result.get("eta_seconds", 0) or 0),
        "current_step": int(result.get("current_step", 0) or 0),
        "steps":        result.get("steps") or ["Resolve", "Scan", "Analyze", "Report"],
    })
 
 
@app.route("/api/active_scans")
def api_active_scans():
    """Returns all currently running scans for the logged-in user"""
    if "user" not in session:
        return jsonify([]), 401
 
    scans = fetch_user_scans(session["user"]["email"])
    running = [s for s in scans if s["status"] == "scanning"]
 
    result = []
    for scan in running:
        full = fetch_scan(scan["id"], session["user"]["email"])
        progress_data = {}
        if full and full.get("result_json"):
            try:
                progress_data = json.loads(full["result_json"])
            except:
                pass
 
        result.append({
            "id":           scan["id"],
            "target":       scan.get("target"),
            "scan_type":    scan.get("scan_type"),
            "status":       "scanning",
            "progress_pct": int(progress_data.get("progress_pct", 0) or 0),
            "phase":        progress_data.get("phase", "Scanning..."),
            "eta_seconds":  int(progress_data.get("eta_seconds", 0) or 0),
            "current_step": int(progress_data.get("current_step", 0) or 0),
            "steps":        progress_data.get("steps") or ["Resolve", "Scan", "Analyze", "Report"],
        })
 
    return jsonify(result)

@app.route("/generate-fix", methods=["POST"])
def generate_fix():

    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        from modules.ai_remediation import generate_single_remediation

        body = request.get_json(silent=True) or {}

        data = {
            "title":          str(body.get("title",          "") or "")[:300],
            "description":    str(body.get("description",    "") or "")[:1000],
            "severity":       str(body.get("severity",       "INFO") or "INFO")[:20],
            "evidence":       str(body.get("evidence",       "") or "")[:500],
            "recommendation": str(body.get("recommendation", "") or "")[:500],
        }

        if not data["title"]:
            return jsonify({"error": "title is required"}), 400

        return jsonify(generate_single_remediation(data))

    except Exception as e:
        print("AI FIX ERROR:", repr(e))
        return jsonify({
            "title":       "Error",
            "explanation": str(e),
            "impact":      "",
            "commands":    [],
            "config":      "",
            "source":      "fallback",
        }), 500


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


