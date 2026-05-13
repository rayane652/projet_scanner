import re
import socket
import ssl
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from modules.nvd_client import nvd_client, epss_client
from modules.ai_remediation import generate_remediation

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"desc": "Enforces HTTPS — prevents SSL-stripping", "severity": "MEDIUM", "cwe": "CWE-319", "owasp": "M0951"},
    "Content-Security-Policy": {"desc": "Reduces XSS and content injection risk", "severity": "HIGH", "cwe": "CWE-1021", "owasp": "M0950"},
    "X-Frame-Options": {"desc": "Prevents clickjacking attacks", "severity": "MEDIUM", "cwe": "CWE-1021", "owasp": "M0950"},
    "X-Content-Type-Options": {"desc": "Prevents MIME-type sniffing", "severity": "LOW", "cwe": "CWE-261", "owasp": "M0952"},
    "Referrer-Policy": {"desc": "Controls referrer header leakage", "severity": "LOW", "cwe": "CWE-200", "owasp": "M0953"},
    "Permissions-Policy": {"desc": "Restricts browser feature access", "severity": "LOW", "cwe": "CWE-693", "owasp": "M0954"},
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
    "/package.json", "/.npmrc", "/.ssh/id_rsa.pub",
    "/test/", "/dev/", "/staging/",
]
TECH_KEYWORDS = {
    "wordpress": "WordPress", "wp-content": "WordPress", "wp-json": "WordPress",
    "jquery": "jQuery", "vue.js": "Vue.js", "vuejs": "Vue.js",
    "react": "React", "angular": "Angular", "next.js": "Next.js",
    "nuxt.js": "Nuxt.js", "laravel": "Laravel", "symfony": "Symfony",
    "django": "Django", "flask": "Flask", "express": "Express.js",
    "ruby on rails": "Ruby on Rails", "rails": "Ruby on Rails",
    "asp.net": "ASP.NET", "asp.net mvc": "ASP.NET MVC",
    "bootstrap": "Bootstrap", "tailwind": "Tailwind CSS",
    "font-awesome": "Font Awesome", "fontawesome": "Font Awesome",
    "drupal": "Drupal", "joomla": "Joomla",
    "shopify": "Shopify", "magento": "Magento",
    "cloudflare": "Cloudflare", "google analytics": "Google Analytics",
    "recaptcha": "reCAPTCHA", "hcaptcha": "hCaptcha",
    "sentry": "Sentry", "newrelic": "New Relic",
    "datadog": "Datadog", "hotjar": "Hotjar",
    "aws": "AWS", "amazon s3": "AWS S3",
    "google cloud": "Google Cloud", "azure": "Azure",
    "nginx": "Nginx", "apache": "Apache",
    "iis": "IIS", "tomcat": "Tomcat",
    "cdn": "CDN", "akamai": "Akamai",
    "fastly": "Fastly", "cloudfront": "CloudFront",
    "swagger": "Swagger", "graphql": "GraphQL",
    "websocket": "WebSocket", "sse": "Server-Sent Events",
}

OWASP_MAP = {
    "Broken Access Control": {"code": "A01", "severity": "CRITICAL", "weight": 10},
    "Cryptographic Failures": {"code": "A02", "severity": "HIGH", "weight": 9},
    "Injection": {"code": "A03", "severity": "CRITICAL", "weight": 10},
    "Insecure Design": {"code": "A04", "severity": "HIGH", "weight": 8},
    "Security Misconfiguration": {"code": "A05", "severity": "HIGH", "weight": 8},
    "Vulnerable Components": {"code": "A06", "severity": "HIGH", "weight": 7},
    "Auth Failures": {"code": "A07", "severity": "CRITICAL", "weight": 9},
    "Data Integrity Failures": {"code": "A08", "severity": "MEDIUM", "weight": 6},
    "Monitoring Failure": {"code": "A09", "severity": "LOW", "weight": 4},
    "SSRF": {"code": "A10", "severity": "MEDIUM", "weight": 7},
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def normalize_url(target):
    target = (target or "").strip()
    if not target:
        return []
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return [target]
    clean = target.lstrip("/")
    return [f"https://{clean}", f"http://{clean}"]


def _fetch_first(target, session):
    errors = []
    for url in normalize_url(target):
        try:
            r = session.get(url, timeout=6, allow_redirects=True)
            return url, r, errors
        except requests.RequestException as e:
            errors.append(f"{url}: {e}")
    return "", None, errors


def _extract_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _extract_meta(html):
    metas = {}
    for m in re.finditer(r'<meta\s+([^>]+)>', html, re.IGNORECASE):
        attrs = m.group(1)
        name = re.search(r'name=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        content = re.search(r'content=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if name and content:
            metas[name.group(1).lower()] = content.group(1)
    return metas


# ═══ CHECKERS ═══


def _find_security_headers(headers, is_https):
    findings, present, missing = [], [], []
    for hdr, info in SECURITY_HEADERS.items():
        if hdr == "Strict-Transport-Security" and not is_https:
            continue
        val = headers.get(hdr)
        if val:
            present.append(hdr)
            if hdr == "Content-Security-Policy":
                if "'unsafe-inline'" in val or "'unsafe-eval'" in val:
                    findings.append({"severity": "MEDIUM", "name": "CSP allows unsafe-inline/eval", "detail": f"CSP header contains unsafe directives that weaken XSS protection", "cwe": "CWE-1021", "owasp": "A05", "header": hdr, "value": val})
                if "default-src 'none'" in val.lower():
                    findings.append({"severity": "LOW", "name": "CSP default-src set to 'none'", "detail": "Review CSP to ensure intended resources are not blocked", "cwe": "CWE-1021", "owasp": "A05", "header": hdr, "value": val})
            if hdr == "Strict-Transport-Security":
                m = re.search(r'max-age=(\d+)', val)
                if m and int(m.group(1)) < 31536000:
                    findings.append({"severity": "LOW", "name": "HSTS max-age too short", "detail": f"HSTS max-age is {m.group(1)}s — should be at least 31536000s (1 year)", "cwe": "CWE-319", "owasp": "A02", "header": hdr, "value": val})
        else:
            missing.append(hdr)
            findings.append({"severity": info["severity"], "name": f"Missing {hdr}", "detail": info["desc"], "cwe": info["cwe"], "owasp": "A05", "header": hdr})

    if headers.get("Server"):
        findings.append({"severity": "INFO", "name": "Server header exposes software info", "detail": f"Server: {headers['Server']}", "cwe": "CWE-200", "owasp": "A01", "header": "Server", "value": headers["Server"]})
    if headers.get("X-Powered-By"):
        findings.append({"severity": "INFO", "name": "X-Powered-By exposes tech stack", "detail": f"X-Powered-By: {headers['X-Powered-By']}", "cwe": "CWE-200", "owasp": "A01", "header": "X-Powered-By", "value": headers["X-Powered-By"]})
    if headers.get("Via"):
        findings.append({"severity": "INFO", "name": "Via header reveals proxy info", "detail": f"Via: {headers['Via']}", "cwe": "CWE-200", "owasp": "A01", "header": "Via", "value": headers["Via"]})
    return present, missing, findings


def _check_cookies(response):
    findings, cookies = [], []
    for cookie in response.cookies:
        flags = {k.lower() for k in cookie._rest.keys()}
        ci = {"name": cookie.name, "secure": bool(cookie.secure), "httponly": "httponly" in flags, "samesite": cookie._rest.get("SameSite", "").lower() if hasattr(cookie, "_rest") else "", "domain": cookie.domain, "path": cookie.path}
        cookies.append(ci)

        if not cookie.secure:
            findings.append({"severity": "HIGH", "name": f"Insecure cookie: {cookie.name} (no Secure flag)", "detail": "Cookie can be transmitted over plain HTTP — session hijacking risk", "cwe": "CWE-614", "owasp": "A02", "cookie": cookie.name})
        if not ci["httponly"]:
            findings.append({"severity": "MEDIUM", "name": f"Cookie lacks HttpOnly: {cookie.name}", "detail": "JavaScript can access this cookie — XSS can steal it", "cwe": "CWE-1004", "owasp": "A05", "cookie": cookie.name})
        if ci["samesite"] not in ("lax", "strict"):
            if not ci["samesite"]:
                findings.append({"severity": "MEDIUM", "name": f"Cookie missing SameSite attribute: {cookie.name}", "detail": "Browser may send this cookie in cross-site requests — CSRF risk", "cwe": "CWE-1275", "owasp": "A01", "cookie": cookie.name})
            elif ci["samesite"] == "none":
                findings.append({"severity": "LOW", "name": f"Cookie SameSite=None: {cookie.name}", "detail": "Cookie sent in all cross-site requests — ensure Secure flag is set", "cwe": "CWE-1275", "owasp": "A01", "cookie": cookie.name})
        if cookie.secure and ci["httponly"] and ci["samesite"] in ("lax", "strict"):
            findings.append({"severity": "INFO", "name": f"Well-configured cookie: {cookie.name}", "detail": "Cookie has Secure + HttpOnly + SameSite", "cookie": cookie.name})
    return cookies, findings


def _check_paths(base_url, session, html):
    checks = []
    found_robots_rules = []
    found_sitemap_urls = []

    for path in INTERESTING_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=4, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code in (200, 401, 403, 301, 302):
            checks.append({"path": path, "status": r.status_code, "note": "Interesting endpoint detected"})
            if path == "/robots.txt" and r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith(("allow:", "disallow:", "sitemap:")):
                        found_robots_rules.append(line.strip())
        if path == "/sitemap.xml" and r.status_code == 200:
            for m in re.finditer(r'<loc>(.*?)</loc>', r.text, re.IGNORECASE):
                found_sitemap_urls.append(m.group(1))

    return checks, found_robots_rules, found_sitemap_urls


def _check_forms(html, base_url):
    findings, forms = [], []
    for m in re.finditer(r'<form\b([^>]*)>', html, re.IGNORECASE):
        attrs = m.group(1)
        method = (re.search(r'method=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE) or "").group(1) if re.search(r'method=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE) else "GET"
        action = (re.search(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE) or "").group(1) if re.search(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE) else ""
        fi = {"method": method.upper(), "action": action}
        forms.append(fi)
        if method.upper() == "GET":
            findings.append({"severity": "LOW", "name": "Form uses GET method", "detail": f"Form submits via GET — sensitive data may appear in URL logs", "cwe": "CWE-598", "owasp": "A02", "form": fi})
        inputs = re.findall(r'<input\b[^>]*type=["\']?password["\']?', attrs + html[m.end():m.end()+500], re.IGNORECASE)
        if inputs:
            findings.append({"severity": "MEDIUM", "name": "Form with password field (no CSRF token check)", "detail": "Login forms without CSRF tokens are vulnerable to cross-site request forgery", "cwe": "CWE-352", "owasp": "A01", "form": fi})
        if not re.search(r'(csrf|token|nonce|_token)', attrs + html[m.end():m.end()+1000], re.IGNORECASE):
            findings.append({"severity": "LOW", "name": "Form may lack CSRF protection", "detail": "No CSRF token detected in form or nearby context", "cwe": "CWE-352", "owasp": "A01", "form": fi})

    csrf_meta = re.search(r'<meta\s+name=["\']csrf-token["\']', html, re.IGNORECASE)
    if csrf_meta:
        findings.append({"severity": "INFO", "name": "CSRF token found in meta tag", "detail": "Application appears to use CSRF protection", "cwe": "CWE-352", "owasp": "A01"})

    return forms, findings


def _fingerprint_tech(headers, html, cookies):
    tech = []
    seen = set()
    server = (headers.get("Server") or "").lower()
    powered = (headers.get("X-Powered-By") or "").lower()
    html_lower = html.lower()
    set_cookie = str(headers.get("Set-Cookie", "")).lower()
    combined = f"{server} {powered} {html_lower} {set_cookie} {' '.join(c.name.lower() for c in (cookies or []))}"

    for keyword, label in TECH_KEYWORDS.items():
        if keyword in combined and label not in seen:
            tech.append({"name": label, "confidence": "high" if keyword in server or keyword in powered else "medium", "evidence": f"Matched keyword: {keyword}"})
            seen.add(label)

    if server:
        ver = re.search(r'[\d.]+', server)
        tech.append({"name": f"Server: {server.split('/')[0].title()}", "version": ver.group() if ver else "", "confidence": "high", "evidence": f"Server header: {server}"})

    for cookie in (cookies or []):
        if cookie.name.lower() in ("aspsessionid", ".aspxauth", "asp.net_sessionid"):
            tech.append({"name": "ASP.NET", "confidence": "high", "evidence": f"Cookie: {cookie.name}"})
            break
        if cookie.name.lower() in ("phpsessid",):
            tech.append({"name": "PHP", "confidence": "high", "evidence": f"Cookie: {cookie.name}"})
            break
        if cookie.name.lower() in ("jsessionid",):
            tech.append({"name": "Java/JSP", "confidence": "high", "evidence": f"Cookie: {cookie.name}"})
            break

    if "laravel_session" in set_cookie or "laravel" in combined:
        tech.append({"name": "Laravel", "confidence": "high", "evidence": "Laravel session cookie or fingerprint"})
    if "symfony" in combined:
        tech.append({"name": "Symfony", "confidence": "medium", "evidence": "Symfony fingerprint detected"})
    if "django" in combined:
        tech.append({"name": "Django", "confidence": "medium", "evidence": "Django fingerprint"})

    return tech


def _check_cors(headers):
    findings = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        findings.append({"severity": "HIGH", "name": "Wildcard CORS (Access-Control-Allow-Origin: *)", "detail": "Any origin can read responses — sensitive data exfiltration risk", "cwe": "CWE-942", "owasp": "A01", "header": "Access-Control-Allow-Origin", "value": acao})
    if acao and acao != "*" and acac.lower() == "true":
        findings.append({"severity": "MEDIUM", "name": "CORS with credentials on specific origin", "detail": f"ACAO: {acao} with credentials — ensure this origin is trusted", "cwe": "CWE-942", "owasp": "A01", "header": "Access-Control-Allow-Origin", "value": acao})
    if acac.lower() == "true" and acao == "*":
        findings.append({"severity": "CRITICAL", "name": "Wildcard CORS with credentials", "detail": "Access-Control-Allow-Origin: * with Allow-Credentials: true — severe data exfiltration risk", "cwe": "CWE-942", "owasp": "A01"})
    return findings


def _check_js_files(base_url, html, session):
    findings, js_files = [], []
    for m in re.finditer(r'<script[^>]*src=["\']([^"\']+)', html, re.IGNORECASE):
        src = m.group(1)
        if src.startswith("data:") or src.startswith("blob:"):
            continue
        js_url = urljoin(base_url, src)
        js_files.append(js_url)
    for js_url in js_files[:15]:
        try:
            r = session.get(js_url, timeout=4)
            if r.status_code == 200:
                js = r.text.lower()
                if "api" in js or "apikey" in js or "token" in js:
                    findings.append({"severity": "HIGH", "name": f"Potential secret in JS: {js_url}", "detail": "JS file contains references to API/token — review for hardcoded secrets", "cwe": "CWE-312", "owasp": "A05", "evidence": js_url, "js_url": js_url})
                if ".env" in js or "config" in js:
                    findings.append({"severity": "MEDIUM", "name": f"Config references in JS: {js_url}", "detail": "JS file references config or .env — may leak internal paths", "cwe": "CWE-200", "owasp": "A01", "evidence": js_url, "js_url": js_url})
                if "localhost" in js or "0.0.0.0" in js or "127.0.0.1" in js:
                    findings.append({"severity": "MEDIUM", "name": f"Internal host references in JS: {js_url}", "detail": "JS references localhost — internal topology may be exposed", "cwe": "CWE-200", "owasp": "A01", "evidence": js_url, "js_url": js_url})
                if re.search(r'(aws|secret|password|key=|bearer\s+[\w-]{20,})', js):
                    findings.append({"severity": "CRITICAL", "name": f"Hardcoded secret suspected in: {js_url}", "detail": "JS contains patterns matching API keys, tokens, or passwords", "cwe": "CWE-798", "owasp": "A05", "evidence": js_url, "js_url": js_url})
        except requests.RequestException:
            continue
    return js_files, findings


def _check_http_methods(base_url, session):
    findings = []
    for method in ("OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"):
        try:
            r = session.request(method, base_url, timeout=4)
            if r.status_code not in (405, 404, 501):
                findings.append({"severity": f"{'HIGH' if method in ('PUT', 'DELETE', 'TRACE') else 'MEDIUM'}", "name": f"HTTP method {method} enabled", "detail": f"{method} returned {r.status_code} — potentially dangerous method allowed", "cwe": "CWE-749", "owasp": "A05", "method": method, "status": r.status_code})
        except requests.RequestException:
            continue
    return findings


def _check_ssl(hostname, port=443):
    findings = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                ver = ssock.version()
                cipher = ssock.cipher()
                findings["tls_version"] = ver
                findings["cipher"] = cipher[0] if cipher else ""
                findings["cipher_bits"] = cipher[2] if cipher else 0
                if cert:
                    findings["issuer"] = dict(cert.get("issuer", [])).get("organizationName", "")
                    findings["subject"] = dict(cert.get("subject", [])).get("commonName", "")
                    findings["expiry"] = cert.get("notAfter", "")
                if ver and ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings["tls_weak"] = True
    except Exception as e:
        findings["error"] = str(e)
    return findings


def _check_xss_indicators(html, base_url, session):
    findings = []
    reflected_params = []
    parsed = urlparse(base_url)
    if parsed.query:
        for param in parsed.query.split("&"):
            key, _, val = param.partition("=")
            decoded = requests.utils.unquote(val)
            if decoded and len(decoded) > 3 and decoded in html:
                reflected_params.append({"param": key, "value": decoded[:50]})
    if reflected_params:
        findings.append({"severity": "MEDIUM", "name": "URL parameters reflected in page", "detail": f"{len(reflected_params)} parameter(s) reflected in response — potential XSS vector", "cwe": "CWE-79", "owasp": "A03", "reflected_params": reflected_params})
    script_src = re.findall(r'<script\b[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    for src in script_src:
        if src.startswith("//") or urlparse(src).netloc:
            findings.append({"severity": "INFO", "name": "External script loaded", "detail": f"Script from {src} — ensure it's trusted and uses Subresource Integrity (SRI)", "cwe": "CWE-829", "owasp": "A08", "script": src})
    inline_scripts = re.findall(r'<script\b(?!\s*src)(?:[^>]*)>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
    large_inline = [s for s in inline_scripts if len(s) > 500]
    if large_inline:
        findings.append({"severity": "LOW", "name": f"Large inline scripts detected ({len(large_inline)} found)", "detail": "Large inline scripts make CSP enforcement harder — consider moving to external files", "cwe": "CWE-1021", "owasp": "A05"})
    eval_calls = re.findall(r'eval\s*\(', html, re.IGNORECASE)
    if eval_calls:
        findings.append({"severity": "HIGH", "name": f"eval() usage detected ({len(eval_calls)} occurrence(s))", "detail": "eval() executes arbitrary code — can be abused for DOM-based XSS", "cwe": "CWE-95", "owasp": "A03"})
    document_write = re.findall(r'document\.write\s*\(', html, re.IGNORECASE)
    if document_write:
        findings.append({"severity": "MEDIUM", "name": f"document.write() usage detected ({len(document_write)} occurrence(s))", "detail": "document.write() can write attacker-controlled content — potential DOM XSS", "cwe": "CWE-79", "owasp": "A03"})
    inner_html = re.findall(r'\.innerHTML\s*=', html, re.IGNORECASE)
    if inner_html:
        findings.append({"severity": "MEDIUM", "name": f"innerHTML assignments detected ({len(inner_html)} occurrence(s))", "detail": "innerHTML doesn't escape input — XSS if attacker-controlled data is assigned", "cwe": "CWE-79", "owasp": "A03"})
    return findings


def _check_sqli_indicators(html, base_url, session):
    findings = []
    sqli_patterns = [r"'?\s*OR\s+'1'\s*=\s*'1", r"'?\s*OR\s+1\s*=\s*1", r'"\s*OR\s+"1"\s*=\s*"1']
    for pattern in sqli_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            findings.append({"severity": "HIGH", "name": "SQL injection pattern detected in response", "detail": "Response contains SQL tautology patterns — application may be vulnerable to SQLi", "cwe": "CWE-89", "owasp": "A03"})
            break
    parsed = urlparse(base_url)
    if parsed.query:
        for param in parsed.query.split("&"):
            if "id=" in param.lower() or "page=" in param.lower() or "cat=" in param.lower():
                findings.append({"severity": "LOW", "name": "SQLi-susceptible parameter in URL", "detail": f"Parameter '{param.split('=')[0]}' is commonly targeted by SQL injection", "cwe": "CWE-89", "owasp": "A03"})
    return findings


def _check_auth_detection(headers, html, base_url, session, cookies):
    findings = []
    auth_mechanisms = []
    if headers.get("WWW-Authenticate"):
        auth_mechanisms.append(f"HTTP Auth: {headers['WWW-Authenticate']}")
        findings.append({"severity": "INFO", "name": "HTTP Basic/Digest authentication detected", "detail": f"WWW-Authenticate: {headers['WWW-Authenticate']}", "cwe": "CWE-287", "owasp": "A07", "evidence": headers["WWW-Authenticate"]})
    login_patterns = ["login", "signin", "sign-in", "auth", "logon", "log-in"]
    html_lower = html.lower()
    for pat in login_patterns:
        if pat in html_lower:
            auth_mechanisms.append(f"Login form detected ({pat})")
            findings.append({"severity": "INFO", "name": "Login/authentication page detected", "detail": f"Page contains '{pat}' — authentication endpoint identified", "cwe": "CWE-287", "owasp": "A07"})
            break
    pw_match = re.search(r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE)
    if pw_match:
        if "HTTP Auth" not in str(auth_mechanisms):
            auth_mechanisms.append("Password field in form")
        findings.append({"severity": "INFO", "name": "Password input field detected", "detail": "Form contains a password field — verify HTTPS and proper autocomplete settings", "cwe": "CWE-287", "owasp": "A07"})
        if re.search(r'autocomplete\s*=\s*["\']?off["\']?', html[:pw_match.end()+200], re.IGNORECASE):
            findings.append({"severity": "LOW", "name": "Autocomplete disabled on password field", "detail": "Good practice — password autocomplete is disabled", "cwe": "CWE-200", "owasp": "A01"})
    if any(c.name.lower() in ("sessionid", "jsessionid", "phpsessid", "aspsessionid", "token", "auth") for c in cookies):
        findings.append({"severity": "INFO", "name": "Session cookie detected", "detail": "Application uses session-based authentication", "cwe": "CWE-287", "owasp": "A07"})
    oauth_patterns = re.findall(r'(google_signin|facebook_login|github_auth|oauth|openid|sso)', html, re.IGNORECASE)
    if oauth_patterns:
        findings.append({"severity": "INFO", "name": "OAuth/SSO authentication present", "detail": f"Detected: {', '.join(set(oauth_patterns))}", "cwe": "CWE-287", "owasp": "A07"})
    return auth_mechanisms, findings


def _check_misconfigs(headers, html, base_url, session, status_code):
    findings = []
    if status_code == 404:
        ct = headers.get("Content-Type", "")
        if "text/html" in ct and len(html) > 100:
            findings.append({"severity": "INFO", "name": "Custom 404 page — no info leak", "detail": "404 returns rich HTML, not raw server error", "cwe": "CWE-200", "owasp": "A05"})
    dir_listing = re.search(r'<title>Index\s+of\s+/', html, re.IGNORECASE)
    if dir_listing:
        findings.append({"severity": "HIGH", "name": "Directory listing enabled", "detail": "Server returns an index listing — sensitive files may be exposed", "cwe": "CWE-548", "owasp": "A05"})
    debug_patterns = ["debug", "trace", "test", "staging", "dev mode", "development", "application.cfm", "cfapplication"]
    html_lower = html.lower()
    for pat in debug_patterns:
        if pat in html_lower:
            findings.append({"severity": "MEDIUM", "name": f"Debug/development artifact: '{pat}'", "detail": f"Response contains '{pat}' — debug mode may be enabled", "cwe": "CWE-489", "owasp": "A05"})
            break
    if headers.get("X-Debug-Token") or headers.get("X-Debug-Token-Link"):
        findings.append({"severity": "HIGH", "name": "Symfony debug toolbar active", "detail": "X-Debug-Token header found — debug mode exposes sensitive app data", "cwe": "CWE-489", "owasp": "A05"})
    if headers.get("X-Drupal-Cache") or headers.get("X-Generator", "").lower() == "drupal":
        findings.append({"severity": "LOW", "name": "Drupal CMS detected", "detail": "Drupal — ensure latest security updates are applied", "cwe": "CWE-1104", "owasp": "A06"})
    if "wp-json" in html_lower or "/wp-content/" in html_lower:
        findings.append({"severity": "LOW", "name": "WordPress detected", "detail": "WordPress site — verify core/plugin versions and disable XML-RPC if unused", "cwe": "CWE-1104", "owasp": "A06"})
    if headers.get("X-AspNet-Version"):
        findings.append({"severity": "LOW", "name": "ASP.NET version exposed", "detail": f"X-AspNet-Version: {headers['X-AspNet-Version']}", "cwe": "CWE-200", "owasp": "A01"})
    if headers.get("X-AspNetMvc-Version"):
        findings.append({"severity": "LOW", "name": "ASP.NET MVC version exposed", "detail": f"X-AspNetMvc-Version: {headers['X-AspNetMvc-Version']}", "cwe": "CWE-200", "owasp": "A01"})
    return findings


def _detect_api_endpoints(base_url, session):
    findings = []
    api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/swagger.json", "/openapi.json", "/api-docs/", "/docs/"]
    for path in api_patterns:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=4, allow_redirects=False)
            if r.status_code in (200, 401, 403, 405):
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "yaml" in ct or r.status_code in (401, 403):
                    findings.append({"severity": "INFO", "name": f"API endpoint found: {path}", "detail": f"{path} returned {r.status_code} — API surface detected", "cwe": "CWE-200", "owasp": "A01", "path": path, "status": r.status_code})
        except requests.RequestException:
            continue
    return findings


def _check_backup_files(base_url, session):
    findings = []
    backup_patterns = [
        "/backup/", "/backup.zip", "/backup.sql", "/backup.tar.gz",
        "/db_backup.sql", "/database.sql", "/dump.sql",
        "/.bk", "/~", ".bak", ".old", ".swp", ".save", ".orig"
    ]
    base_path = urlparse(base_url).path.rstrip("/") or ""
    for ext in backup_patterns:
        if ext.startswith("/"):
            url = urljoin(base_url.rstrip("/") + "/", ext.lstrip("/"))
        else:
            url = f"{base_url}{ext}"
        try:
            r = session.get(url, timeout=3, allow_redirects=False)
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith(("application/", "text/plain", "application/octet")):
                findings.append({"severity": "CRITICAL" if ext.endswith((".sql", ".zip", ".tar", ".gz")) else "HIGH", "name": f"Backup/sensitive file exposed: {ext}", "detail": f"{url} returned 200 — file may contain sensitive data", "cwe": "CWE-530", "owasp": "A05", "path": url, "status": 200})
        except requests.RequestException:
            continue
    return findings


def _compute_web_score(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").lower()
        if sev in counts:
            counts[sev] += 1
    score = min(100, counts["critical"] * 25 + counts["high"] * 16 + counts["medium"] * 8 + counts["low"] * 3)
    if score == 0:
        level = "LOW"
    elif score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level, counts


def _build_owasp_mapping(findings):
    mapping = {}
    for f in findings:
        owasp = f.get("owasp", "")
        if owasp:
            if owasp not in mapping:
                mapping[owasp] = {"count": 0, "findings": []}
            mapping[owasp]["count"] += 1
            mapping[owasp]["findings"].append(f["name"])
    for code, info in OWASP_MAP.items():
        if info["code"] not in mapping:
            mapping[info["code"]] = {"count": 0, "findings": [], "name": code}
        else:
            mapping[info["code"]]["name"] = code
    return mapping


# ═══ MAIN ENTRY POINT ═══

def scan_website(target):
    if not target:
        return {"input": target, "error": "No target provided", "findings": []}

    session = requests.Session()
    session.headers.update({"User-Agent": "Vulnix-WebScanner/2.0", "Accept": "text/html,application/json,*/*"})

    requested_url, response, errors = _fetch_first(target, session)
    if response is None:
        return {"input": target, "error": "Could not connect to the target as a website", "errors": errors, "tested_urls": normalize_url(target), "findings": []}

    final_url = response.url
    parsed = urlparse(final_url)
    html = response.text if "text/html" in response.headers.get("Content-Type", "") else ""
    headers = dict(response.headers)
    is_https = parsed.scheme == "https"

    all_findings = []

    # 1. Security headers
    present_hdrs, missing_hdrs, hdr_findings = _find_security_headers(headers, is_https)
    all_findings.extend(hdr_findings)

    # 2. Cookies
    cookies, cookie_findings = _check_cookies(response)
    all_findings.extend(cookie_findings)

    # 3. Path discovery
    paths, robots_rules, sitemap_urls = _check_paths(final_url, session, html)
    all_findings.extend({"severity": "INFO", "name": f"Path discovered: {p['path']}", "detail": f"Status {p['status']} — {p['note']}", "cwe": "CWE-200", "owasp": "A01", "path": p["path"], "status": p["status"]} for p in paths)

    # 4. Forms
    forms, form_findings = _check_forms(html, final_url)
    all_findings.extend(form_findings)

    # 5. Technology fingerprinting
    tech = _fingerprint_tech(headers, html, cookies)

    # 5b. CVE enrichment for detected tech products (top 3)
    cve_enrichment = {}
    for t in tech[:3]:
        product = (t.get("name") or "").replace("Server: ", "").strip().lower()
        if product and product not in ("unknown", ""):
            try:
                cves = nvd_client.search_by_product(product, limit=5)
                if cves:
                    ids = [c["id"] for c in cves if c.get("id")]
                    epss = epss_client.get_scores(ids) if ids else {}
                    for c in cves:
                        epid = (c.get("id") or "").upper()
                        if epid in epss:
                            c["epss_score"] = epss[epid]["epss_score"]
                        c["cve"] = c.get("id", "")
                        c["score"] = c.get("cvss_score")
                    cve_enrichment[product] = cves
                    for c in cves[:3]:
                        all_findings.append({
                            "severity": c.get("severity", "MEDIUM"),
                            "name": f"CVE: {c['id']} in {product}",
                            "detail": (c.get("description") or "")[:200],
                            "cwe": (c.get("cwes") or ["CWE-1104"])[0],
                            "owasp": "A06",
                            "cvss_score": c.get("cvss_score"),
                            "epss": c.get("epss_score"),
                            "cve_id": c["id"],
                        })
            except Exception:
                pass

    # 6. CORS
    cors_findings = _check_cors(headers)
    all_findings.extend(cors_findings)

    # 7. JS analysis
    js_files, js_findings = _check_js_files(final_url, html, session)
    all_findings.extend(js_findings)

    # 8. HTTP methods
    method_findings = _check_http_methods(final_url, session)
    all_findings.extend(method_findings)

    # 9. SSL/TLS
    ssl_info = _check_ssl(parsed.hostname)
    if ssl_info.get("tls_weak"):
        all_findings.append({"severity": "HIGH", "name": "Weak TLS version", "detail": f"Server uses {ssl_info['tls_version']} — TLS 1.2+ required", "cwe": "CWE-327", "owasp": "A02"})
    bits = ssl_info.get("cipher_bits")
    if bits is not None and isinstance(bits, int) and bits < 128:
        all_findings.append({"severity": "HIGH", "name": "Weak cipher strength", "detail": f"Cipher uses only {ssl_info['cipher_bits']} bits", "cwe": "CWE-326", "owasp": "A02"})

    # 10. XSS indicators
    xss_findings = _check_xss_indicators(html, final_url, session)
    all_findings.extend(xss_findings)

    # 11. SQLi indicators
    sqli_findings = _check_sqli_indicators(html, final_url, session)
    all_findings.extend(sqli_findings)

    # 12. Auth detection
    auth_mechs, auth_findings = _check_auth_detection(headers, html, final_url, session, cookies)
    all_findings.extend(auth_findings)

    # 13. Misconfigs
    misconfig_findings = _check_misconfigs(headers, html, final_url, session, response.status_code)
    all_findings.extend(misconfig_findings)

    # 14. API endpoints
    api_findings = _detect_api_endpoints(final_url, session)
    all_findings.extend(api_findings)

    # 15. Backup files
    backup_findings = _check_backup_files(final_url, session)
    all_findings.extend(backup_findings)

    # Deduplicate findings by name
    seen_names = set()
    deduped = []
    for f in all_findings:
        key = f.get("name", "")
        if key not in seen_names:
            seen_names.add(key)
            deduped.append(f)
    all_findings = deduped

    # Compute risk
    web_score, web_level, sev_counts = _compute_web_score(all_findings)
    owasp = _build_owasp_mapping(all_findings)

    # Group findings by category
    grouped = {}
    for f in all_findings:
        cwe = f.get("cwe", "CWE-000")
        group = cwe
        if group not in grouped:
            grouped[group] = []
        grouped[group].append(f)

    meta = _extract_meta(html)

    # 16. AI remediation for top findings
    top_findings_for_fix = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 99))[:8]
    ai_fixes = []
    try:
        fix_inputs = [{"title": f.get("name", ""), "description": f.get("detail", ""), "severity": f.get("severity", "INFO"), "evidence": f.get("evidence", ""), "recommendation": f.get("detail", "")} for f in top_findings_for_fix]
        ai_fixes = generate_remediation(fix_inputs)
    except Exception:
        ai_fixes = []

    # Backward-compat fields
    legacy_findings = [{"severity": f.get("severity", "INFO"), "name": f.get("name", ""), "detail": f.get("detail", "")} for f in all_findings]
    legacy_missing = [f["name"].replace("Missing ", "") for f in hdr_findings if f["name"].startswith("Missing ")]

    return {
        "input": target,
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "content_type": headers.get("Content-Type", ""),
        "server": headers.get("Server", ""),
        "powered_by": headers.get("X-Powered-By", ""),
        "title": _extract_title(html),
        "headers": headers,
        "meta": meta,
        "missing_headers": legacy_missing,
        "cookies": cookies,
        "forms": forms,
        "interesting_paths": paths,
        "technologies": tech,
        "js_files": js_files,
        "robots_rules": robots_rules,
        "sitemap_urls": sitemap_urls,
        "auth_mechanisms": auth_mechs,
        "ssl_info": ssl_info,
        "owasp": owasp,
        "web_risk_score": web_score,
        "web_risk_level": web_level,
        "severity_counts": sev_counts,
        "grouped_findings": grouped,
        "attack_surface": {
            "paths_discovered": len(paths),
            "forms_detected": len(forms),
            "cookies_analyzed": len(cookies),
            "technologies_fingerprinted": len(tech),
            "js_files_analyzed": len(js_files),
            "auth_mechanisms": len(auth_mechs),
            "api_endpoints": len(api_findings),
        },
        "findings": legacy_findings,
        "raw_findings": all_findings,
        "cve_enrichment": cve_enrichment,
        "ai_fixes": ai_fixes,
    }
