import logging
import re
from urllib.parse import urljoin, urlparse

from modules.utils import grab_banner_tls
from .fetcher import fetch

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"desc": "Enforces HTTPS — prevents SSL-stripping", "severity": "MEDIUM", "cwe": "CWE-319", "owasp": "A02"},
    "Content-Security-Policy": {"desc": "Reduces XSS and content injection risk", "severity": "HIGH", "cwe": "CWE-1021", "owasp": "A05"},
    "X-Frame-Options": {"desc": "Prevents clickjacking attacks", "severity": "MEDIUM", "cwe": "CWE-1021", "owasp": "A05"},
    "X-Content-Type-Options": {"desc": "Prevents MIME-type sniffing", "severity": "LOW", "cwe": "CWE-261", "owasp": "A05"},
    "Referrer-Policy": {"desc": "Controls referrer header leakage", "severity": "LOW", "cwe": "CWE-200", "owasp": "A05"},
    "Permissions-Policy": {"desc": "Restricts browser feature access", "severity": "LOW", "cwe": "CWE-693", "owasp": "A05"},
}

INTERESTING_PATHS = [
    "/robots.txt", "/security.txt", "/.well-known/security.txt",
    "/server-status", "/phpinfo.php",
    "/admin/", "/admin", "/login/", "/login", "/wp-admin/",
    "/backup/", "/backup", "/.git/", "/.env", "/config/",
    "/config.php", "/config.json", "/.htaccess", "/crossdomain.xml",
    "/sitemap.xml", "/Dockerfile", "/docker-compose.yml",
    "/api/", "/api/v1/", "/swagger.json", "/api-docs",
    "/debug/", "/console/", "/actuator/", "/.DS_Store",
    "/wp-config.php", "/wp-content/", "/xmlrpc.php",
    "/.aws/credentials", "/.azure/config",
    "/package.json", "/.npmrc",
    "/test/", "/dev/", "/staging/",
    "/manager/", "/manager/html", "/admin-console",
    "/webadmin/", "/cpanel/", "/wp-login.php",
    "/administrator/", "/panel/", "/jenkins/",
    "/zabbix/", "/grafana/", "/prometheus/",
    "/kibana/", "/sonar/", "/nexus/",
    "/phpMyAdmin/", "/phpmyadmin/", "/pma/",
    "/graphql", "/graphiql", "/voyager",
    "/health", "/healthz", "/readyz", "/metrics",
    "/.well-known/change-password",
    "/version", "/version.txt", "/VERSION",
    "/composer.json", "/yarn.lock", "/package-lock.json",
    "/license.txt", "/LICENSE", "/CHANGELOG", "/README.md",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/nginx.conf", "/web.config",
    "/dump.sql", "/export.sql",
    "/__init__.py", "/manage.py", "/artisan", "/craft",
]

ADMIN_PATHS = [
    "/admin/", "/admin", "/wp-admin/", "/administrator/",
    "/manager/", "/manager/html", "/admin-console/",
    "/webadmin/", "/cpanel/", "/wp-login.php",
    "/panel/", "/jenkins/", "/zabbix/",
    "/grafana/", "/kibana/", "/console/",
    "/actuator/", "/swagger-ui/", "/api-docs/",
    "/phpMyAdmin/", "/phpmyadmin/", "/pma/",
    "/adminer/", "/adminer.php",
]

WEAK_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
WEAK_CIPHERS = {"rc4", "des", "3des", "md5", "export", "null", "anon"}


def _s(pattern, text, flags=0):
    if not isinstance(text, str):
        return None
    try:
        return re.search(pattern, text, flags)
    except re.error:
        return None


def _fi(pattern, text, flags=0):
    if not isinstance(text, str):
        return []
    try:
        return list(re.finditer(pattern, text, flags))
    except re.error:
        return []


def _fa(pattern, text, flags=0):
    if not isinstance(text, str):
        return []
    try:
        return re.findall(pattern, text, flags)
    except re.error:
        return []


def analyze_headers(headers, is_https):
    findings, present, missing = [], [], []
    for hdr, info in SECURITY_HEADERS.items():
        if hdr == "Strict-Transport-Security" and not is_https:
            continue
        val = headers.get(hdr)
        if val:
            present.append(hdr)
            if hdr == "Content-Security-Policy":
                if "'unsafe-inline'" in val or "'unsafe-eval'" in val:
                    findings.append({"severity": "MEDIUM", "name": "CSP allows unsafe-inline/eval", "detail": "CSP header contains unsafe directives that weaken XSS protection", "cwe": "CWE-1021", "owasp": "A05", "header": hdr, "value": val})
                if "frame-ancestors" not in val:
                    findings.append({"severity": "MEDIUM", "name": "CSP missing frame-ancestors", "detail": "Without frame-ancestors, CSP does not fully protect against clickjacking", "cwe": "CWE-1021", "owasp": "A05", "header": hdr})
            if hdr == "Strict-Transport-Security":
                m = _s(r'max-age=(\d+)', val)
                if m and int(m.group(1)) < 31536000:
                    findings.append({"severity": "LOW", "name": "HSTS max-age too short", "detail": f"HSTS max-age is {m.group(1)}s — should be at least 31536000s (1 year)", "cwe": "CWE-319", "owasp": "A02", "header": hdr, "value": val})
                if "includeSubDomains" not in val:
                    findings.append({"severity": "LOW", "name": "HSTS missing includeSubDomains", "detail": "Subdomains are not covered by HSTS policy", "cwe": "CWE-319", "owasp": "A02", "header": hdr})
            if hdr == "X-Frame-Options":
                if val.lower() not in ("deny", "sameorigin"):
                    findings.append({"severity": "MEDIUM", "name": "X-Frame-Options has weak value", "detail": f"Value '{val}' — use DENY or SAMEORIGIN", "cwe": "CWE-1021", "owasp": "A05", "header": hdr, "value": val})
        else:
            missing.append(hdr)
            findings.append({"severity": info["severity"], "name": f"Missing {hdr}", "detail": info["desc"], "cwe": info["cwe"], "owasp": info["owasp"], "header": hdr})

    info_leaks = [
        ("Server", "Server header exposes software info"),
        ("X-Powered-By", "X-Powered-By exposes tech stack"),
        ("Via", "Via header reveals proxy info"),
        ("X-Generator", "X-Generator header exposes CMS info"),
        ("X-Runtime", "X-Runtime header exposes timing info"),
    ]
    for hdr, name in info_leaks:
        if headers.get(hdr):
            findings.append({"severity": "INFO", "name": name, "detail": f"{hdr}: {headers[hdr]}", "cwe": "CWE-200", "owasp": "A01", "header": hdr, "value": headers[hdr]})

    if headers.get("X-Debug-Token") or headers.get("X-Debug-Token-Link"):
        findings.append({"severity": "HIGH", "name": "Symfony debug toolbar active", "detail": "Debug toolbar enabled in production — leaks sensitive app data", "cwe": "CWE-489", "owasp": "A05"})
    if headers.get("X-AspNet-Version"):
        findings.append({"severity": "LOW", "name": "ASP.NET version exposed", "detail": f"X-AspNet-Version: {headers['X-AspNet-Version']}", "cwe": "CWE-200", "owasp": "A01"})
    if headers.get("X-AspNetMvc-Version"):
        findings.append({"severity": "LOW", "name": "ASP.NET MVC version exposed", "detail": f"X-AspNetMvc-Version: {headers['X-AspNetMvc-Version']}", "cwe": "CWE-200", "owasp": "A01"})
    if headers.get("X-Drupal-Cache"):
        findings.append({"severity": "INFO", "name": "Drupal CMS detected", "detail": "X-Drupal-Cache header present — Drupal site", "cwe": "CWE-200", "owasp": "A01"})

    return present, missing, findings


def analyze_cookies(response):
    findings, cookies = [], []
    for cookie in response.cookies:
        flags = {k.lower() for k in cookie._rest.keys()}
        ci = {
            "name": cookie.name, "secure": bool(cookie.secure),
            "httponly": "httponly" in flags,
            "samesite": cookie._rest.get("SameSite", "").lower() if hasattr(cookie, "_rest") else "",
            "domain": cookie.domain, "path": cookie.path,
        }
        cookies.append(ci)
        if not cookie.secure:
            findings.append({"severity": "HIGH", "name": f"Insecure cookie: {cookie.name}", "detail": "No Secure flag — sent over HTTP — session hijacking risk", "cwe": "CWE-614", "owasp": "A02", "cookie": cookie.name})
        if not ci["httponly"]:
            findings.append({"severity": "MEDIUM", "name": f"Cookie lacks HttpOnly: {cookie.name}", "detail": "JS can access this cookie — XSS can steal it", "cwe": "CWE-1004", "owasp": "A05", "cookie": cookie.name})
        if ci["samesite"] not in ("lax", "strict"):
            if not ci["samesite"]:
                findings.append({"severity": "MEDIUM", "name": f"Cookie missing SameSite: {cookie.name}", "detail": "Browser may send in cross-site requests — CSRF risk", "cwe": "CWE-1275", "owasp": "A01", "cookie": cookie.name})
        if cookie.secure and ci["httponly"] and ci["samesite"] in ("lax", "strict"):
            findings.append({"severity": "INFO", "name": f"Secure cookie: {cookie.name}", "detail": "Has Secure + HttpOnly + SameSite", "cookie": cookie.name})
    return cookies, findings


def analyze_cors(headers):
    findings = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        findings.append({"severity": "HIGH", "name": "Wildcard CORS", "detail": "Access-Control-Allow-Origin: * — any origin can read responses", "cwe": "CWE-942", "owasp": "A01", "header": "Access-Control-Allow-Origin", "value": acao})
    if acao and acao != "*" and acac and acac.lower() == "true":
        findings.append({"severity": "MEDIUM", "name": "CORS with credentials", "detail": f"CORS allows credentials on specific origin {acao}", "cwe": "CWE-942", "owasp": "A01", "header": "Access-Control-Allow-Origin", "value": acao})
    if acac and acac.lower() == "true" and acao == "*":
        findings.append({"severity": "CRITICAL", "name": "Wildcard CORS with credentials", "detail": "ACAO: * with Allow-Credentials: true — severe data exfiltration risk", "cwe": "CWE-942", "owasp": "A01"})
    return findings


def analyze_xss(html, url):
    findings = []
    parsed = urlparse(url)
    if parsed.query:
        reflected = []
        for param in parsed.query.split("&"):
            key, _, val = param.partition("=")
            decoded = __import__("requests").utils.unquote(val)
            if decoded and len(decoded) > 3 and decoded in html:
                reflected.append({"param": key, "value": decoded[:50]})
        if reflected:
            findings.append({"severity": "MEDIUM", "name": "URL parameters reflected in page", "detail": f"{len(reflected)} param(s) reflected — potential XSS vector", "cwe": "CWE-79", "owasp": "A03", "reflected_params": reflected})
    if _fa(r'eval\s*\(', html):
        findings.append({"severity": "HIGH", "name": "eval() usage detected", "detail": "eval() executes arbitrary code — DOM-based XSS risk", "cwe": "CWE-95", "owasp": "A03"})
    if _fa(r'document\.write\s*\(', html):
        findings.append({"severity": "MEDIUM", "name": "document.write() usage detected", "detail": "Can write attacker-controlled content — DOM XSS risk", "cwe": "CWE-79", "owasp": "A03"})
    if _fa(r'\.innerHTML\s*=', html):
        findings.append({"severity": "MEDIUM", "name": "innerHTML assignments detected", "detail": "Doesn't escape input — XSS if attacker data is assigned", "cwe": "CWE-79", "owasp": "A03"})
    dangerous = _fa(r'(setTimeout\s*\(|setInterval\s*\(|new\s+Function\s*\()', html)
    if dangerous:
        findings.append({"severity": "LOW", "name": f"Dangerous function usage ({len(dangerous)}x)", "detail": "setTimeout/setInterval/Function with string args can lead to DOM XSS", "cwe": "CWE-79", "owasp": "A03"})
    return findings


def analyze_sqli(html, url):
    findings = []
    for pat in [r"'\s*OR\s+'1'\s*=\s*'1", r"'\s*OR\s+1\s*=\s*1", r'"\s*OR\s+"1"\s*=\s*"1']:
        if _fa(pat, html):
            findings.append({"severity": "HIGH", "name": "SQL injection pattern in response", "detail": "Response contains SQL tautology patterns — possible SQLi", "cwe": "CWE-89", "owasp": "A03"})
            break
    parsed = urlparse(url)
    if parsed.query:
        for param in parsed.query.split("&"):
            key = param.split("=")[0]
            if _s(r'^(id|page|cat|pid|user_id|product_id)$', key, re.IGNORECASE):
                findings.append({"severity": "LOW", "name": f"SQLi-susceptible parameter: {key}", "detail": f"Parameter '{key}' commonly targeted by SQL injection", "cwe": "CWE-89", "owasp": "A03"})
    return findings


def analyze_auth(headers, html, cookies):
    findings = []
    mechanisms = []
    if headers.get("WWW-Authenticate"):
        mechanisms.append(f"HTTP Auth: {headers['WWW-Authenticate']}")
        findings.append({"severity": "INFO", "name": "HTTP authentication detected", "detail": f"WWW-Authenticate: {headers['WWW-Authenticate']}", "cwe": "CWE-287", "owasp": "A07", "evidence": headers["WWW-Authenticate"]})
    html_lower = html.lower()
    for pat in ("login", "signin", "sign-in", "auth", "logon"):
        if pat in html_lower:
            mechanisms.append(f"Login form ({pat})")
            findings.append({"severity": "INFO", "name": "Login page detected", "detail": f"Page contains '{pat}' — authentication endpoint identified", "cwe": "CWE-287", "owasp": "A07"})
            break
    if _s(r'type=["\']?password["\']?', html):
        mechanisms.append("Password field")
        findings.append({"severity": "INFO", "name": "Password input field detected", "detail": "Form contains a password field — verify HTTPS", "cwe": "CWE-287", "owasp": "A07"})
    if any(c.name.lower() in ("sessionid", "jsessionid", "phpsessid", "aspsessionid", "token", "auth", "sid") for c in cookies):
        findings.append({"severity": "INFO", "name": "Session cookie detected", "detail": "Application uses session-based authentication", "cwe": "CWE-287", "owasp": "A07"})
    if _fa(r'(oauth|openid|sso|saml)', html):
        findings.append({"severity": "INFO", "name": "OAuth/SSO authentication present", "detail": "OAuth/SSO authentication detected", "cwe": "CWE-287", "owasp": "A07"})
    return mechanisms, findings


def analyze_misconfigs(headers, html, status_code):
    findings = []
    if status_code == 404:
        if "text/html" in headers.get("Content-Type", "") and len(html) > 100:
            findings.append({"severity": "INFO", "name": "Custom 404 page", "detail": "404 returns rich HTML, not raw server error — good", "cwe": "CWE-200", "owasp": "A05"})
    if _s(r'<title>Index\s+of\s+/', html) or _s(r'<h1>Index\s+of\s+', html):
        findings.append({"severity": "HIGH", "name": "Directory listing enabled", "detail": "Server returns an index listing — sensitive files may be exposed", "cwe": "CWE-548", "owasp": "A05"})
    for pat in ("debug", "trace", "test", "staging", "dev mode", "development", "app.env"):
        if pat in html.lower():
            findings.append({"severity": "MEDIUM", "name": "Debug artifact found", "detail": f"Response contains '{pat}' — debug mode may be enabled", "cwe": "CWE-489", "owasp": "A05"})
            break
    if "wp-json" in html.lower() or "/wp-content/" in html.lower():
        findings.append({"severity": "LOW", "name": "WordPress detected", "detail": "WordPress site — verify core/plugin versions", "cwe": "CWE-1104", "owasp": "A06"})
    if "laravel" in html.lower():
        findings.append({"severity": "LOW", "name": "Laravel detected", "detail": "Laravel app — verify debug mode is disabled in production", "cwe": "CWE-1104", "owasp": "A06"})
    return findings


def analyze_comments(html):
    findings = []
    sensitive_patterns = [
        (r"(TODO|FIXME|HACK|XXX)", "Developer note", "LOW"),
        (r"(password|passwd|secret|api.?key|token|jwt)", "Potential secret in comment", "MEDIUM"),
        (r"(TODO|FIXME).*(security|vuln|fix|patch)", "Security-related TODO", "HIGH"),
    ]
    for m in _fi(r'<!--(.*?)-->', html, re.DOTALL):
        text = m.group(1).strip()
        if len(text) < 10:
            continue
        for pat, name, sev in sensitive_patterns:
            if _s(pat, text, re.IGNORECASE):
                findings.append({"severity": sev, "name": name, "detail": f"HTML comment contains: {pat}", "cwe": "CWE-200", "owasp": "A01", "comment": text[:150]})
                break
    return findings


def analyze_paths(base_url, session):
    checks = []
    robots_rules = []
    sitemap_urls = []
    exposed_admin = []

    for path in INTERESTING_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = fetch("GET", url, session, timeout=4, allow_redirects=False)
        except Exception:
            continue
        if r.status_code in (200, 401, 403, 301, 302):
            note = "Interesting endpoint"
            if path in ADMIN_PATHS:
                exposed_admin.append({"path": path, "status": r.status_code})
                note = "Admin panel"
            if r.status_code in (401, 403):
                note = f"Restricted (HTTP {r.status_code})"
            checks.append({"path": path, "status": r.status_code, "note": note})
            if path == "/robots.txt" and r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith(("allow:", "disallow:", "sitemap:", "user-agent:")):
                        robots_rules.append(line.strip())
            if path == "/sitemap.xml" and r.status_code == 200:
                for m in _fi(r'<loc>(.*?)</loc>', r.text):
                    sitemap_urls.append(m.group(1))
    return checks, robots_rules, sitemap_urls, exposed_admin


def analyze_api_endpoints(base_url, session):
    findings = []
    paths = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/swagger.json",
             "/openapi.json", "/api-docs/", "/docs/", "/api/v1/", "/api/v2/",
             "/graphiql", "/voyager"]
    for path in paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = fetch("GET", url, session, timeout=4, allow_redirects=False)
            if r.status_code in (200, 401, 403, 405):
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "yaml" in ct or "xml" in ct or r.status_code in (401, 403):
                    findings.append({"severity": "INFO", "name": f"API endpoint: {path}", "detail": f"{path} returned {r.status_code} — API surface detected", "cwe": "CWE-200", "owasp": "A01", "path": path, "status": r.status_code})
        except Exception:
            continue
    return findings


def analyze_backup_files(base_url, session):
    findings = []
    exts = ["/backup.zip", "/backup.sql", "/backup.tar.gz", "/db_backup.sql",
            "/database.sql", "/dump.sql", "/.env.bak", "/.env.save", "/.env.old",
            "/config.bak", "/config.bak.php"]
    for ext in exts:
        url = urljoin(base_url.rstrip("/") + "/", ext.lstrip("/"))
        try:
            r = fetch("GET", url, session, timeout=3, allow_redirects=False)
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith(("application/", "text/plain", "application/octet")):
                findings.append({"severity": "CRITICAL" if ext.endswith((".sql", ".zip", ".tar", ".gz")) else "HIGH",
                                 "name": f"Sensitive file exposed: {ext}", "detail": f"{url} returned 200", "cwe": "CWE-530", "owasp": "A05", "path": url, "status": 200})
        except Exception:
            continue
    return findings


def analyze_js_files(base_url, html, session):
    findings, js_files = [], []
    for m in _fi(r'<script[^>]*src=["\']([^"\']+)', html):
        src = m.group(1)
        if src.startswith(("data:", "blob:")):
            continue
        js_url = urljoin(base_url, src)
        js_files.append(js_url)
    for js_url in js_files[:15]:
        try:
            r = fetch("GET", js_url, session, timeout=4)
            if r.status_code == 200:
                js = r.text.lower()
                checks = [
                    ("api|apikey|token", "HIGH", "Potential secret in JS", "CWE-312"),
                    ("aws|secret|password|key=|bearer\\s+[\\w-]{20,}", "CRITICAL", "Hardcoded secret suspected", "CWE-798"),
                    ("localhost|0\\.0\\.0\\.0|127\\.0\\.0\\.1", "MEDIUM", "Internal host reference in JS", "CWE-200"),
                    ("\\.env|config", "MEDIUM", "Config reference in JS", "CWE-200"),
                ]
                for pat, sev, name, cwe in checks:
                    if _s(pat, js):
                        findings.append({"severity": sev, "name": name, "detail": f"{js_url}: found pattern", "cwe": cwe, "owasp": "A05", "js_url": js_url})
                        break
        except Exception:
            continue
    return js_files, findings


def analyze_http_methods(base_url, session):
    findings = []
    for method in ("OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"):
        try:
            r = fetch(method, base_url, session, timeout=4)
            if r.status_code not in (405, 404, 501, 400):
                sev = "CRITICAL" if method in ("PUT", "DELETE", "CONNECT") else "HIGH" if method == "TRACE" else "MEDIUM"
                findings.append({"severity": sev, "name": f"Dangerous HTTP method: {method}", "detail": f"{method} returned {r.status_code}", "cwe": "CWE-749", "owasp": "A05", "method": method, "status": r.status_code})
        except Exception:
            continue
    return findings


def analyze_ssl(hostname, port=443):
    result = grab_banner_tls(hostname, port)
    if "error" in result:
        return result
    findings, recs = [], []
    tls = result.get("tls_version", "")
    if tls in WEAK_TLS:
        findings.append({"severity": "HIGH", "name": f"Weak TLS: {tls}", "detail": f"Server uses {tls} — upgrade to TLS 1.2+", "cwe": "CWE-327", "owasp": "A02"})
        recs.append("Upgrade to TLS 1.2 or higher.")
    cipher = (result.get("cipher_name") or "").lower()
    for weak in WEAK_CIPHERS:
        if weak in cipher:
            findings.append({"severity": "HIGH", "name": f"Weak cipher: {result.get('cipher_name')}", "detail": f"Cipher uses {weak.upper()} — disable weak ciphers", "cwe": "CWE-326", "owasp": "A02"})
            recs.append(f"Disable weak cipher '{result.get('cipher_name')}'.")
            break
    bits = result.get("cipher_bits", 0)
    if bits and isinstance(bits, int) and bits < 128:
        findings.append({"severity": "HIGH", "name": f"Weak cipher strength: {bits} bits", "detail": "Below minimum 128 bits", "cwe": "CWE-326", "owasp": "A02"})
        recs.append("Use ciphers with at least 128-bit encryption.")
    if result.get("expired"):
        findings.append({"severity": "CRITICAL", "name": "SSL certificate expired", "detail": f"Expired on {result.get('not_after')}", "cwe": "CWE-295", "owasp": "A02"})
        recs.append("Renew SSL certificate immediately.")
    if result.get("expires_soon"):
        findings.append({"severity": "MEDIUM", "name": "SSL expiring soon", "detail": f"Expires in {result.get('days_left')} days", "cwe": "CWE-295", "owasp": "A02"})
        recs.append(f"Renew SSL within {result.get('days_left')} days.")
    if result.get("self_signed"):
        findings.append({"severity": "MEDIUM", "name": "Self-signed SSL certificate", "detail": "Certificate is not trusted by browsers", "cwe": "CWE-295", "owasp": "A02"})
        recs.append("Replace with a CA-trusted certificate.")
    if result.get("san"):
        result["san_count"] = len(result["san"])
    result["findings"] = findings
    result["recommendations"] = recs
    result["status"] = "secure" if not findings else "insecure" if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else "warning"
    return result


BACKUP_PATTERNS = [
    "/backup/", "/backup.zip", "/backup.sql", "/backup.tar.gz",
    "/db_backup.sql", "/database.sql", "/dump.sql",
    "/.bk", "/~", ".bak", ".old", ".swp", ".save", ".orig",
    "/.env.bak", "/.env.save", "/.env.old",
    "/config.bak", "/config.php.bak", "/config.json.bak",
]


def analyze_exposed_files(base_url, session):
    findings = []
    for ext in BACKUP_PATTERNS:
        if ext.startswith("/"):
            url = urljoin(base_url.rstrip("/") + "/", ext.lstrip("/"))
        else:
            url = f"{base_url}{ext}"
        try:
            r = fetch("GET", url, session, timeout=3, allow_redirects=False)
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith(("application/", "text/plain", "application/octet")):
                sev = "CRITICAL" if ext.endswith((".sql", ".zip", ".tar", ".gz")) else "HIGH"
                findings.append({"severity": sev, "name": f"Exposed file: {ext}", "detail": f"{url} returned 200 — may contain sensitive data", "cwe": "CWE-530", "owasp": "A05", "path": url, "status": 200})
        except Exception:
            continue
    return findings


def compute_score(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").lower()
        if sev in counts:
            counts[sev] += 1
    score = min(100, counts["critical"] * 25 + counts["high"] * 16 + counts["medium"] * 8 + counts["low"] * 3)
    level = "LOW"
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    return score, level, counts


OWASP_MAP = {
    "Broken Access Control": "A01", "Cryptographic Failures": "A02",
    "Injection": "A03", "Insecure Design": "A04",
    "Security Misconfiguration": "A05", "Vulnerable Components": "A06",
    "Auth Failures": "A07", "Data Integrity Failures": "A08",
    "Monitoring Failure": "A09", "SSRF": "A10",
}


def build_owasp(findings):
    mapping = {}
    for f in findings:
        owasp = f.get("owasp", "")
        if owasp:
            if owasp not in mapping:
                mapping[owasp] = {"count": 0, "findings": []}
            mapping[owasp]["count"] += 1
            mapping[owasp]["findings"].append(f["name"])
    for name, code in OWASP_MAP.items():
        if code not in mapping:
            mapping[code] = {"count": 0, "findings": [], "name": name}
        else:
            mapping[code]["name"] = name
    return mapping
