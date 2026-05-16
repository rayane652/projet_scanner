import logging
from urllib.parse import urlparse

from .fetcher import create_session, fetch_first, normalize_url
from .parsers import (
    extract_title, extract_meta, extract_forms, extract_scripts,
    extract_links, extract_endpoints, extract_comments, is_login_page,
)
from .detector import detect_technologies, detect_waf, compute_favicon
from .security import (
    analyze_headers, analyze_cookies, analyze_cors, analyze_xss,
    analyze_sqli, analyze_auth, analyze_misconfigs, analyze_comments as analyze_html_comments,
    analyze_paths, analyze_api_endpoints, analyze_backup_files,
    analyze_js_files, analyze_http_methods, analyze_ssl,
    analyze_exposed_files, compute_score, build_owasp,
)
from modules.nvd_client import nvd_client, epss_client
from modules.ai_remediation import generate_remediation

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
OWASP_MAP_LABELS = {
    "A01": "Broken Access Control", "A02": "Cryptographic Failures",
    "A03": "Injection", "A04": "Insecure Design",
    "A05": "Security Misconfiguration", "A06": "Vulnerable Components",
    "A07": "Auth Failures", "A08": "Data Integrity Failures",
    "A09": "Monitoring Failure", "A10": "SSRF",
}


def _counts(all_findings):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = (f.get("severity") or "info").lower()
        if sev in c:
            c[sev] += 1
    return c


def _categorize(findings):
    cats = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = (f.get("severity") or "INFO").lower()
        if sev in cats:
            cats[sev].append(f)
    return cats


def scan_website(target):
    if not target:
        return {"input": target, "error": "No target provided", "findings": []}

    session = create_session()
    try:
        requested_url, response, errors = fetch_first(target, session)
    except Exception as e:
        session.close()
        return {"input": target, "error": f"Connection error: {e}", "findings": []}

    if response is None:
        session.close()
        return {
            "input": target, "error": "Could not connect as a website",
            "errors": errors, "tested_urls": normalize_url(target), "findings": [],
        }

    final_url = response.url
    parsed = urlparse(final_url)
    html = response.text if "text/html" in response.headers.get("Content-Type", "") else ""
    headers = dict(response.headers)
    is_https = parsed.scheme == "https"

    all_findings = []

    # ── 1. Security headers ──
    present_hdrs, missing_hdrs, hdr_findings = analyze_headers(headers, is_https)
    all_findings.extend(hdr_findings)

    # ── 2. Cookies ──
    cookies, cookie_findings = analyze_cookies(response)
    all_findings.extend(cookie_findings)

    # ── 3. HTML parsing ──
    meta = extract_meta(html)
    forms = extract_forms(html, final_url)
    scripts = extract_scripts(html, final_url)
    links = extract_links(html, final_url)
    endpoints = extract_endpoints(html)
    comments = extract_comments(html)

    # ── 4. Path discovery ──
    paths, robots_rules, sitemap_urls, exposed_admin = analyze_paths(final_url, session)
    all_findings.extend({"severity": "INFO", "name": f"Path discovered: {p['path']}", "detail": f"Status {p['status']} — {p['note']}", "cwe": "CWE-200", "owasp": "A01", "path": p["path"], "status": p["status"]} for p in paths)
    for panel in exposed_admin:
        all_findings.append({"severity": "HIGH", "name": f"Exposed admin panel: {panel['path']}", "detail": f"Admin interface at {panel['path']} (HTTP {panel['status']})", "cwe": "CWE-200", "owasp": "A01", "path": panel["path"], "status": panel["status"]})

    # ── 5. Form analysis ──
    for form in forms:
        if form["method"] == "GET":
            all_findings.append({"severity": "LOW", "name": "Form uses GET method", "detail": "Form submits via GET — sensitive data may appear in URL logs", "cwe": "CWE-598", "owasp": "A02", "form": form})
        if form["has_password"]:
            context = form.get("action", "")
            if not _csrf_check(form, html):
                all_findings.append({"severity": "MEDIUM", "name": "Password form without CSRF token", "detail": "Login form may lack CSRF protection", "cwe": "CWE-352", "owasp": "A01", "form": form})
        action = form.get("action", "")
        if action and action.startswith("http"):
            from urllib.parse import urlparse as _up
            if _up(action).scheme != "https":
                all_findings.append({"severity": "MEDIUM", "name": "Form submits over insecure HTTP", "detail": f"Form action '{action}' uses HTTP instead of HTTPS", "cwe": "CWE-319", "owasp": "A02", "form": form})

    # ── 6. Technology fingerprinting ──
    script_srcs = [s["src"] for s in scripts if s["src"]]
    favicon = compute_favicon(final_url, session)
    tech = detect_technologies(headers, html, cookies, final_url, script_srcs, favicon.get("known", ""))
    if favicon.get("known"):
        all_findings.append({"severity": "INFO", "name": f"CMS via favicon: {favicon['known']}", "detail": "Favicon hash matches known CMS", "cwe": "CWE-200", "owasp": "A01"})

    # ── 7. CVE enrichment ──
    cve_enrichment = {}
    for t in tech[:5]:
        product = (t.get("name") or "").strip().lower()
        version = (t.get("version") or "").strip()
        if product and product not in ("unknown", ""):
            try:
                cves = nvd_client.search_by_product(product, version or None, limit=5)
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
                            "published_date": c.get("published_date"),
                            "affected_versions": c.get("affected_versions") or [],
                        })
            except Exception:
                pass

    # ── 8. CORS ──
    all_findings.extend(analyze_cors(headers))

    # ── 9. JS analysis ──
    js_files, js_findings = analyze_js_files(final_url, html, session)
    all_findings.extend(js_findings)

    # ── 10. HTTP methods ──
    all_findings.extend(analyze_http_methods(final_url, session))

    # ── 11. SSL/TLS ──
    ssl_info = analyze_ssl(parsed.hostname)
    if "error" not in ssl_info:
        all_findings.extend(ssl_info.get("findings", []))

    # ── 12. XSS ──
    all_findings.extend(analyze_xss(html, final_url))

    # ── 13. SQLi ──
    all_findings.extend(analyze_sqli(html, final_url))

    # ── 14. Auth ──
    auth_mechs, auth_findings = analyze_auth(headers, html, cookies)
    all_findings.extend(auth_findings)

    # ── 15. Misconfigs ──
    all_findings.extend(analyze_misconfigs(headers, html, response.status_code))

    # ── 16. API endpoints ──
    api_findings = analyze_api_endpoints(final_url, session)
    all_findings.extend(api_findings)

    # ── 17. Backup/exposed files ──
    all_findings.extend(analyze_exposed_files(final_url, session))

    # ── 18. WAF detection ──
    from .detector import detect_waf
    waf_detected = detect_waf(headers, html, cookies)
    for waf in waf_detected:
        all_findings.append({"severity": "INFO", "name": f"WAF: {waf['name']}", "detail": f"Web application firewall identified", "cwe": "CWE-693", "owasp": "A05", "waf": waf})

    # ── 19. HTML comment analysis ──
    all_findings.extend(analyze_html_comments(html))

    # ── 20. Script SRI check ──
    parsed_netloc = parsed.netloc
    for script in scripts:
        if script["src"] and not script["integrity"] and not script["inline"]:
            try:
                src_host = urlparse(script["src"]).netloc
                if src_host and src_host != parsed_netloc:
                    all_findings.append({"severity": "LOW", "name": "External script without SRI", "detail": f"No Subresource Integrity on {script['src'][:80]}", "cwe": "CWE-829", "owasp": "A08", "script": script["src"]})
            except Exception:
                pass

    # ── Deduplicate ──
    seen = set()
    deduped = []
    for f in all_findings:
        key = f.get("name", "")
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    # ── Score ──
    web_score, web_level, sev_counts = compute_score(all_findings)
    owasp = build_owasp(all_findings)

    # Group by CWE
    grouped = {}
    for f in all_findings:
        cwe = f.get("cwe", "CWE-000")
        grouped.setdefault(cwe, []).append(f)

    security_issues = _categorize(all_findings)

    # ── AI fixes ──
    top_findings = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 99))[:8]
    ai_fixes = []
    try:
        fix_inputs = [{"title": f.get("name", ""), "description": f.get("detail", ""), "severity": f.get("severity", "INFO"), "evidence": "", "recommendation": f.get("detail", "")} for f in top_findings]
        ai_fixes = generate_remediation(fix_inputs)
    except Exception:
        ai_fixes = []

    # ── Backward compat ──
    legacy_findings = [{"severity": f.get("severity", "INFO"), "name": f.get("name", ""), "detail": f.get("detail", "")} for f in all_findings]
    legacy_missing = [f["name"].replace("Missing ", "") for f in hdr_findings if f["name"].startswith("Missing ")]
    is_login = is_login_page(html, forms)

    session.close()

    return {
        "input": target,
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "content_type": headers.get("Content-Type", ""),
        "server": headers.get("Server", ""),
        "powered_by": headers.get("X-Powered-By", ""),
        "title": extract_title(html),
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
        "ssl_security": ssl_info if "error" not in ssl_info else None,
        "exposed_admin_panels": exposed_admin,
        "owasp": owasp,
        "web_risk_score": web_score,
        "web_risk_level": web_level,
        "severity_counts": sev_counts,
        "severity_breakdown": [{"key": k, "label": k.title(), "count": sev_counts.get(k, 0)} for k in ["critical", "high", "medium", "low", "info"]],
        "grouped_findings": grouped,
        "attack_surface": {
            "paths_discovered": len(paths),
            "forms_detected": len(forms),
            "cookies_analyzed": len(cookies),
            "technologies_fingerprinted": len(tech),
            "js_files_analyzed": len(js_files),
            "auth_mechanisms": len(auth_mechs),
            "api_endpoints": len(api_findings),
            "exposed_admin_panels": len(exposed_admin),
            "endpoints_extracted": len(endpoints),
            "links_extracted": len(links),
            "scripts_analyzed": len(scripts),
            "waf_detected": len(waf_detected),
        },
        "findings": legacy_findings,
        "raw_findings": all_findings,
        "cve_enrichment": cve_enrichment,
        "ai_fixes": ai_fixes,
        "waf": waf_detected,
        "favicon": favicon,
        "links": links[:50],
        "endpoints": endpoints,
        "scripts": scripts,
        "comments": comments,
        "is_login_page": is_login,
        "security_issues": security_issues,
    }


def _csrf_check(form, html):
    attrs = f"{form.get('action', '')} {form.get('id', '')} {form.get('name', '')}".lower()
    if re_search(r'(csrf|token|nonce|_token)', attrs):
        return True
    idx = html.lower().find(form.get("action", "").lower())
    if idx >= 0:
        if re_search(r'(csrf|token|nonce|_token)', html[idx:idx+1000]):
            return True
    return False


import re as _re

def re_search(pattern, text):
    try:
        return _re.search(pattern, text, _re.IGNORECASE)
    except _re.error:
        return None
