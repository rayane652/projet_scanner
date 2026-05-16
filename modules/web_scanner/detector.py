import logging
import re

from .signatures import TECH_SIGNATURES, WAF_SIGNATURES, KNOWN_FAVICON_HASHES

logger = logging.getLogger(__name__)

_CONF_MAP = {100: 100, 80: 80, 70: 70, 60: 60, 50: 50, 0: 0}


def _extract_version(pattern, text):
    try:
        m = re.search(pattern, text, re.IGNORECASE)
        if m and m.lastindex and m.group(1):
            return m.group(1).strip()
    except Exception:
        pass
    return ""


def detect_technologies(headers, html, cookies, url="", scripts=None, favicon_known=""):
    techs = []
    seen = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html.lower() if html else ""
    all_cookies = " ".join(c.name.lower() for c in cookies) if cookies else ""
    script_srcs = " ".join(scripts or [])
    html_meta = {}
    if html:
        from .parsers import extract_meta
        try:
            html_meta = extract_meta(html)
        except Exception:
            pass

    for key, sig in TECH_SIGNATURES.items():
        if key in seen:
            continue
        best_conf = 0
        evidence = ""
        version = ""

        for hdr_name, pattern, conf in sig.get("h", []):
            val = headers_lower.get(hdr_name.lower(), "")
            if val:
                try:
                    if re.search(pattern, val, re.IGNORECASE):
                        c = _CONF_MAP.get(conf, conf)
                        if c > best_conf:
                            best_conf = c
                            ver = _extract_version(pattern, val)
                            if ver:
                                version = ver
                        evidence = f"Header {hdr_name}"
                except re.error:
                    continue

        for meta_name, (meta_pattern, conf) in sig.get("m", {}).items():
            val = html_meta.get(meta_name, "")
            if val:
                try:
                    if re.search(meta_pattern, val, re.IGNORECASE):
                        c = _CONF_MAP.get(conf, conf)
                        if c > best_conf:
                            best_conf = c
                            ver = _extract_version(meta_pattern, val)
                            if ver:
                                version = ver
                        evidence = f"Meta {meta_name}"
                except re.error:
                    continue

        for pattern, conf in sig.get("t", []):
            try:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    c = _CONF_MAP.get(conf, conf)
                    if c > best_conf:
                        best_conf = c
                    if not evidence:
                        evidence = f"HTML: {pattern}"
            except re.error:
                continue

        for pattern, conf in sig.get("u", []):
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    c = _CONF_MAP.get(conf, conf)
                    if c > best_conf:
                        best_conf = c
                    if not evidence:
                        evidence = f"URL: {pattern}"
            except re.error:
                continue

        for pattern, conf in sig.get("k", []):
            try:
                if re.search(pattern, all_cookies, re.IGNORECASE):
                    c = _CONF_MAP.get(conf, conf)
                    if c > best_conf:
                        best_conf = c
                    if not evidence:
                        evidence = f"Cookie: {pattern}"
            except re.error:
                continue

        for pattern, conf in sig.get("s", []):
            try:
                if re.search(pattern, script_srcs, re.IGNORECASE):
                    c = _CONF_MAP.get(conf, conf)
                    if c > best_conf:
                        best_conf = c
                    if not evidence:
                        evidence = f"Script: {pattern}"
            except re.error:
                continue

        if best_conf >= 50:
            seen.add(key)
            conf_label = "100" if best_conf >= 100 else "high" if best_conf >= 80 else "medium" if best_conf >= 70 else "low"
            techs.append({
                "name": sig["n"],
                "category": sig.get("c", ""),
                "confidence": conf_label,
                "version": version,
                "evidence": evidence,
            })

    if favicon_known and favicon_known not in seen:
        techs.append({
            "name": favicon_known,
            "category": "CMS",
            "confidence": "medium",
            "version": "",
            "evidence": "Favicon hash match",
        })
        seen.add(favicon_known)

    techs.sort(key=lambda t: {"100": 0, "high": 1, "medium": 2, "low": 3}.get(t["confidence"], 99))
    return techs


def detect_waf(headers, html, cookies):
    detected = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html.lower() if html else ""
    cookie_names = {c.name.lower() for c in cookies} if cookies else set()

    for sig in WAF_SIGNATURES:
        score = 0
        evidence = ""
        for hdr, pattern in sig.get("h", {}).items():
            val = headers_lower.get(hdr.lower(), "")
            if val:
                try:
                    if re.search(pattern, val, re.IGNORECASE):
                        score += 2
                        evidence = f"Header {hdr}"
                except re.error:
                    continue
        for pattern in sig.get("t", []):
            try:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    score += 1
                    if not evidence:
                        evidence = f"HTML: {pattern}"
            except re.error:
                continue
        for cookie_pat in sig.get("k", []):
            if any(cookie_pat.lower() in c for c in cookie_names):
                score += 2
                if not evidence:
                    evidence = f"Cookie: {cookie_pat}"
        if score >= 2:
            detected.append({
                "name": sig["n"],
                "id": sig["id"],
                "confidence": "high" if score >= 3 else "medium",
                "evidence": evidence,
            })
    return detected


def compute_favicon(base_url, session):
    import hashlib
    from .parsers import extract_favicon_url

    favicon_url = ""
    favicon_md5 = ""
    favicon_mmh3 = ""
    favicon_known = ""

    candidates = ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]
    try:
        r = session.get(base_url, timeout=4)
        meta_url = extract_favicon_url(r.text, base_url)
        if meta_url:
            candidates.insert(0, meta_url)
    except Exception:
        pass

    for candidate in candidates:
        url = candidate if candidate.startswith("http") else base_url.rstrip("/") + "/" + candidate.lstrip("/")
        try:
            r = session.get(url, timeout=4)
            if r.status_code == 200 and len(r.content) > 50:
                favicon_url = url
                favicon_md5 = hashlib.md5(r.content).hexdigest()
                try:
                    import mmh3, struct
                    favicon_mmh3 = str(struct.unpack(">i", mmh3.hash_bytes(r.content))[0])
                    favicon_known = KNOWN_FAVICON_HASHES.get(favicon_mmh3, "")
                except ImportError:
                    pass
                break
        except Exception:
            continue

    return {"url": favicon_url, "md5": favicon_md5, "mmh3": favicon_mmh3, "known": favicon_known}
