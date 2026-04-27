import re
from urllib.parse import urljoin, urlparse

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects HTTPS sites from downgrade attacks",
    "Content-Security-Policy": "Reduces XSS and content injection risk",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Limits referrer information leaks",
    "Permissions-Policy": "Restricts browser features",
}

INTERESTING_PATHS = (
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/server-status",
    "/phpinfo.php",
    "/admin/",
    "/login/",
)


def normalize_url(target):
    target = (target or "").strip()

    if not target:
        return []

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return [target]

    clean_target = target.lstrip("/")
    return [
        f"https://{clean_target}",
        f"http://{clean_target}",
    ]


def _fetch_first_working_url(target, session):
    errors = []

    for url in normalize_url(target):
        try:
            response = session.get(url, timeout=6, allow_redirects=True)
            return url, response, errors
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")

    return "", None, errors


def _title(html):
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""

    return re.sub(r"\s+", " ", match.group(1)).strip()


def _forms(html):
    forms = []

    for match in re.finditer(r"<form\b([^>]*)>", html, re.IGNORECASE):
        attrs = match.group(1)
        method_match = re.search(r'method=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        action_match = re.search(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)

        forms.append({
            "method": (method_match.group(1) if method_match else "GET").upper(),
            "action": action_match.group(1) if action_match else "",
        })

    return forms


def _technologies(headers, html):
    tech = []
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    generator = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        html,
        re.IGNORECASE,
    )

    if server:
        tech.append(f"Server: {server}")
    if powered_by:
        tech.append(f"X-Powered-By: {powered_by}")
    if generator:
        tech.append(f"Generator: {generator.group(1)}")
    if "wp-content" in html.lower():
        tech.append("WordPress hints found")
    if "jquery" in html.lower():
        tech.append("jQuery hints found")

    return tech


def _header_findings(headers, is_https):
    findings = []
    missing_headers = []

    for header, reason in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and not is_https:
            continue

        if header not in headers:
            missing_headers.append(header)
            findings.append({
                "severity": "LOW",
                "name": f"Missing {header}",
                "detail": reason,
            })

    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")

    if server:
        findings.append({
            "severity": "INFO",
            "name": "Server header exposed",
            "detail": server,
        })

    if powered_by:
        findings.append({
            "severity": "INFO",
            "name": "X-Powered-By header exposed",
            "detail": powered_by,
        })

    return missing_headers, findings


def _cookie_findings(response):
    findings = []
    cookies = []

    for cookie in response.cookies:
        rest_flags = {key.lower() for key in cookie._rest.keys()}
        cookie_info = {
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": "httponly" in rest_flags,
        }
        cookies.append(cookie_info)

        if not cookie.secure:
            findings.append({
                "severity": "LOW",
                "name": f"Cookie without Secure flag: {cookie.name}",
                "detail": "Browser may send this cookie over plain HTTP.",
            })

        if not cookie_info["httponly"]:
            findings.append({
                "severity": "LOW",
                "name": f"Cookie without HttpOnly flag: {cookie.name}",
                "detail": "Client-side scripts may be able to read this cookie.",
            })

    return cookies, findings


def _path_checks(base_url, session):
    checks = []

    for path in INTERESTING_PATHS:
        url = urljoin(base_url, path)

        try:
            response = session.get(url, timeout=4, allow_redirects=False)
        except requests.RequestException:
            continue

        if response.status_code in (200, 401, 403):
            checks.append({
                "path": path,
                "status": response.status_code,
                "note": "Accessible or protected endpoint found",
            })

    return checks


def scan_website(target):
    data = {
        "input": target,
        "tested_urls": normalize_url(target),
        "findings": [],
        "missing_headers": [],
        "cookies": [],
        "forms": [],
        "interesting_paths": [],
        "technologies": [],
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Vulnix-WebScanner/1.0",
    })

    requested_url, response, errors = _fetch_first_working_url(target, session)

    if response is None:
        data["error"] = "Could not connect to the target as a website."
        data["errors"] = errors
        return data

    final_url = response.url
    parsed = urlparse(final_url)
    html = response.text if "text/html" in response.headers.get("Content-Type", "") else ""
    headers = dict(response.headers)

    missing_headers, header_findings = _header_findings(headers, parsed.scheme == "https")
    cookies, cookie_findings = _cookie_findings(response)

    data.update({
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "content_type": headers.get("Content-Type", ""),
        "server": headers.get("Server", ""),
        "powered_by": headers.get("X-Powered-By", ""),
        "title": _title(html),
        "headers": headers,
        "missing_headers": missing_headers,
        "cookies": cookies,
        "forms": _forms(html),
        "interesting_paths": _path_checks(final_url, session),
        "technologies": _technologies(headers, html),
        "findings": header_findings + cookie_findings,
    })

    return data
