import logging
import re
from urllib.parse import urljoin, urldefrag

logger = logging.getLogger(__name__)

_RE_CACHE = {}

def _safe_compile(pattern, flags=0):
    key = (pattern, flags)
    if key in _RE_CACHE:
        return _RE_CACHE[key]
    try:
        import re as _re
        c = _re.compile(pattern, flags)
        _RE_CACHE[key] = c
        return c
    except _re.error as e:
        logger.debug("Bad regex %r: %s", pattern, e)
        _RE_CACHE[key] = None
        return None

def _s(pattern, text, flags=0):
    c = _safe_compile(pattern, flags)
    if c is None or not isinstance(text, str):
        return None
    try:
        return c.search(text)
    except Exception:
        return None

def _f(pattern, text, flags=0):
    c = _safe_compile(pattern, flags)
    if c is None or not isinstance(text, str):
        return []
    try:
        return c.findall(text)
    except Exception:
        return []

def _fi(pattern, text, flags=0):
    c = _safe_compile(pattern, flags)
    if c is None or not isinstance(text, str):
        return []
    try:
        return list(c.finditer(text))
    except Exception:
        return []


def extract_title(html):
    m = _s(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def extract_meta(html):
    metas = {}
    for m in _fi(r'<meta\s+([^>]+)>', html, re.IGNORECASE):
        attrs = m.group(1)
        name = _s(r'name=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        content = _s(r'content=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if name and content:
            metas[name.group(1).lower()] = content.group(1)
        prop = _s(r'property=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if prop and content and prop.group(1).startswith("og:"):
            metas[prop.group(1)] = content.group(1)
    return metas


def extract_forms(html, base_url):
    forms = []
    for m in _fi(r'<form\b([^>]*)>', html, re.IGNORECASE):
        attrs = m.group(1)
        method = "GET"
        ma = _s(r'method=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if ma:
            method = ma.group(1).upper()
        action = ""
        aa = _s(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if aa:
            action = aa.group(1)
        fid = ""
        fi = _s(r'id=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if fi:
            fid = fi.group(1)
        fname = ""
        fn = _s(r'name=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        if fn:
            fname = fn.group(1)
        has_password = bool(_s(r'type=["\']?password["\']?', attrs + html[m.end():m.end()+500], re.IGNORECASE))
        inputs = [x.group(1) for x in _fi(r'<input\b[^>]*type=["\']?([^"\'\s>]+)', attrs + html[m.end():m.end()+500], re.IGNORECASE)]
        forms.append({
            "method": method, "action": action, "id": fid, "name": fname,
            "has_password": has_password, "input_types": list(set(inputs)),
        })
    return forms


def extract_scripts(html, base_url):
    scripts = []
    for m in _fi(r'<script\b([^>]*)>', html, re.IGNORECASE):
        attrs = m.group(1)
        src = ""
        sm = _s(r'src=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        if sm:
            src = urljoin(base_url, sm.group(1))
        integrity = ""
        im = _s(r'integrity=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        if im:
            integrity = im.group(1)
        scripts.append({
            "src": src,
            "integrity": bool(integrity),
            "integrity_value": integrity,
            "async": bool(_s(r'\basync\b', attrs, re.IGNORECASE)),
            "defer": bool(_s(r'\bdefer\b', attrs, re.IGNORECASE)),
            "inline": not src,
        })
    return scripts


def extract_links(html, base_url, max_links=100):
    links = []
    seen = set()
    for m in _fi(r'<a\b[^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        href = m.group(1)
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
            continue
        full = urljoin(base_url, href)
        full, _ = urldefrag(full)
        if full not in seen and full.startswith(("http:", "https:")):
            seen.add(full)
            links.append(full)
            if len(links) >= max_links:
                break
    return links


def extract_endpoints(html):
    endpoints = set()
    patterns = [
        r'["\'](/api/[^"\']+)["\']', r'["\'](/v[12]/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']', r'["\'](/graphql)[^"\']*["\']',
        r'["\'](/oauth/[^"\']+)["\']', r'["\'](/webhook[s]?/[^"\']+)["\']',
        r'["\'](/callback[^"\']*)["\']', r'["\'](/notify[^"\']*)["\']',
        r'["\'](/endpoint[^"\']*)["\']', r'["\'](/services?/[^"\']+)["\']',
        r'["\'](/public/[^"\']+)["\']', r'["\'](/private/[^"\']+)["\']',
        r'["\'](/internal/[^"\']+)["\']', r'["\'](/v3/[^"\']+)["\']',
        r'["\'](/ws/[^"\']+)["\']', r'["\'](/socket[^"\']*)["\']',
        r'url:\s*["\'](/[^"\']+)["\']', r'path:\s*["\'](/[^"\']+)["\']',
    ]
    for pat in patterns:
        for m in _fi(pat, html, re.IGNORECASE):
            path = m.group(1)
            if 2 < len(path) < 200:
                endpoints.add(path)
    return sorted(endpoints)[:50]


def extract_favicon_url(html, base_url):
    m = _s(r'<link[^>]*rel=["\']?icon["\']?[^>]*href=["\']?([^"\'\s>]+)', html, re.IGNORECASE)
    if not m:
        m = _s(r'<link[^>]*href=["\']?([^"\'\s>]+)["\']?[^>]*rel=["\']?icon["\']?', html, re.IGNORECASE)
    if m:
        return urljoin(base_url, m.group(1))
    return ""


def extract_comments(html):
    comments = []
    for m in _fi(r'<!--(.*?)-->', html, re.DOTALL):
        text = m.group(1).strip()
        if text and len(text) > 5:
            comments.append(text[:300])
    return comments[:20]


def is_login_page(html, forms):
    html_lower = html.lower()
    login_indicators = ["login", "signin", "sign-in", "log in", "sign in", "auth"]
    for word in login_indicators:
        if word in html_lower:
            return True
    for form in forms:
        if form.get("has_password"):
            return True
    return False
