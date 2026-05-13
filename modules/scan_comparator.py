import json
from datetime import datetime
from collections import defaultdict

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEVERITY_POINTS = {"CRITICAL": 25, "HIGH": 16, "MEDIUM": 8, "LOW": 3, "INFO": 1}


def _extract_vulns(payload):
    vulns = {}
    for item in (payload.get("scanned_items") or payload.get("findings") or []):
        title = item.get("title") or item.get("name") or ""
        sev = (item.get("severity") or "INFO").upper()
        if not title or sev == "INFO":
            continue
        key = title.lower().strip()
        cve_id = None
        cvss_score = None
        for cve in (item.get("cves") or []):
            c_id = cve.get("id") or cve.get("cve") or ""
            if c_id.lower().startswith("cve-"):
                cve_id = c_id
                cvss_score = cve.get("score") or cve.get("cvss_score")
                break
        vulns[key] = {
            "title": title,
            "severity": sev,
            "category": item.get("category", "Finding"),
            "description": item.get("description") or item.get("detail", ""),
            "recommendation": item.get("recommendation", ""),
            "port": None,
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "evidence": item.get("evidence", ""),
        }
        if item.get("metadata") and isinstance(item.get("metadata"), dict):
            vulns[key]["port"] = item["metadata"].get("port")
    for port in (payload.get("open_ports") or []):
        for cve in (port.get("cves") or []):
            cid = cve.get("id") or cve.get("cve") or ""
            sev = (cve.get("severity") or "INFO").upper()
            if not cid or sev == "INFO":
                continue
            key = cid.lower().strip()
            vulns[key] = {
                "title": cid,
                "severity": sev,
                "category": "CVE",
                "description": cve.get("description", ""),
                "recommendation": port.get("recommendation", ""),
                "port": port.get("port"),
                "cve_id": cid,
                "cvss_score": cve.get("score") or cve.get("cvss_score"),
                "evidence": f"Port {port.get('port')} - {port.get('service', '?')}",
            }
    for cve in (payload.get("vulnerabilities") or []):
        cid = cve.get("id") or cve.get("cve") or ""
        sev = (cve.get("severity") or "INFO").upper()
        if not cid or sev == "INFO":
            continue
        key = cid.lower().strip()
        cvss_score = cve.get("score") or cve.get("cvss_score")
        vulns[key] = {
                "title": cid,
                "severity": sev,
                "category": "CVE",
                "description": cve.get("description", ""),
                "recommendation": cve.get("recommendation", ""),
                "port": cve.get("port"),
                "cve_id": cid,
                "cvss_score": cvss_score,
                "evidence": f"Asset: {cve.get('asset', '?')}",
            }
    return vulns


def _extract_ports(payload):
    ports = {}
    for p in (payload.get("open_ports") or payload.get("ports") or []):
        n = p.get("port")
        if n:
            ports[n] = {"port": n, "service": p.get("service", "unknown"), "product": p.get("product", ""), "version": p.get("version", ""), "cve_count": p.get("cve_count", 0)}
    return ports


def _severity_counts(vulns_dict):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns_dict.values():
        s = v.get("severity", "INFO").upper()
        if s in c:
            c[s] += 1
    return c


def _score_with_breakdown(vulns):
    """Security Score: 0 = clean (best), 100 = max risk (worst)."""
    if not vulns:
        return 0, {"n": 0, "penalty": 0, "max_penalty": 0, "crit": 0, "high": 0, "med": 0, "low": 0, "info": 0}
    crit = sum(1 for v in vulns.values() if v.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for v in vulns.values() if v.get("severity", "").upper() == "HIGH")
    med = sum(1 for v in vulns.values() if v.get("severity", "").upper() == "MEDIUM")
    low = sum(1 for v in vulns.values() if v.get("severity", "").upper() == "LOW")
    info = sum(1 for v in vulns.values() if v.get("severity", "").upper() == "INFO")
    penalty = crit * 25 + high * 16 + med * 8 + low * 3 + info * 1
    max_penalty = len(vulns) * 25
    raw = (penalty / max_penalty * 100) if max_penalty else 0
    score = max(0, min(100, int(raw)))
    return score, {"n": len(vulns), "penalty": penalty, "max_penalty": max_penalty, "crit": crit, "high": high, "med": med, "low": low, "info": info}


def _compare_scan_pair(old_scan, new_scan):
    """Compare older scan_a → newer scan_b. Returns old→new deltas."""
    old_payload, old_err = _load(old_scan)
    new_payload, new_err = _load(new_scan)
    if old_err or new_err or not old_payload or not new_payload:
        return None

    if old_payload.get("type") == "network" or new_payload.get("type") == "network":
        return None

    vulns_old = _extract_vulns(old_payload)
    vulns_new = _extract_vulns(new_payload)
    ports_old = _extract_ports(old_payload)
    ports_new = _extract_ports(new_payload)

    keys_old, keys_new = set(vulns_old), set(vulns_new)
    fixed_keys = keys_old - keys_new        # present in old, gone in new
    new_keys = keys_new - keys_old           # appeared in new
    persistent_keys = keys_old & keys_new    # in both

    def _build_vuln_list(keys, source):
        return [dict(source[k]) for k in sorted(keys)]

    fixed_details = _build_vuln_list(fixed_keys, vulns_old)
    new_details = _build_vuln_list(new_keys, vulns_new)
    persistent_details = _build_vuln_list(persistent_keys, vulns_new)

    for v in persistent_details:
        key = v.get("title", "").lower().strip()
        if key in vulns_old:
            v["severity_before"] = vulns_old[key].get("severity", "INFO")
            v["severity_after"] = v.get("severity", "INFO")
            v["cvss_before"] = vulns_old[key].get("cvss_score")
            v["cvss_after"] = v.get("cvss_score")

    regressions = []
    improvements = []
    for k in persistent_keys:
        sa = SEVERITY_ORDER.get(vulns_old[k].get("severity", "INFO").upper(), 5)
        sb = SEVERITY_ORDER.get(vulns_new[k].get("severity", "INFO").upper(), 5)
        if sb < sa:
            regressions.append({"title": vulns_new[k]["title"], "before": vulns_old[k].get("severity"), "after": vulns_new[k].get("severity"), "cve_id": vulns_new[k].get("cve_id"), "cvss_before": vulns_old[k].get("cvss_score"), "cvss_after": vulns_new[k].get("cvss_score")})
        elif sb > sa:
            improvements.append({"title": vulns_new[k]["title"], "before": vulns_old[k].get("severity"), "after": vulns_new[k].get("severity"), "cve_id": vulns_new[k].get("cve_id"), "cvss_before": vulns_old[k].get("cvss_score"), "cvss_after": vulns_new[k].get("cvss_score")})

    score_old = old_payload.get("risk_score", 50)
    score_new = new_payload.get("risk_score", 50)
    _, brk_old = _score_with_breakdown(vulns_old)
    _, brk_new = _score_with_breakdown(vulns_new)
    score_delta = score_new - score_old
    pct_fixed = round(len(fixed_keys) / max(len(keys_old), 1) * 100, 1)

    ports_old_set = set(ports_old)
    ports_new_set = set(ports_new)
    ports_added = [ports_new[p] for p in (ports_new_set - ports_old_set)]
    ports_removed = [ports_old[p] for p in (ports_old_set - ports_new_set)]

    trend, trend_msg, trend_icon = _trend(pct_fixed, len(new_keys), score_delta)

    ai_summary = _generate_ai_summary(len(fixed_keys), len(new_keys), len(persistent_keys), score_delta, pct_fixed, len(regressions), len(improvements), len(ports_added), len(ports_removed))

    return {
        "scan_a_id": old_scan["id"], "scan_b_id": new_scan["id"],
        "scan_a_date": (old_scan.get("created_at") or "")[:16],
        "scan_b_date": (new_scan.get("created_at") or "")[:16],
        "asset_name": old_scan.get("machine_name") or old_scan.get("target", ""),
        "fixed": len(fixed_keys), "new": len(new_keys), "persistent": len(persistent_keys),
        "total_before": len(keys_old), "total_after": len(keys_new),
        "score_before": score_old, "score_after": score_new,
        "pct_fixed": pct_fixed,
        "fixed_by_severity": _severity_counts({k: vulns_old[k] for k in fixed_keys}),
        "new_by_severity": _severity_counts({k: vulns_new[k] for k in new_keys}),
        "persistent_by_severity": _severity_counts({k: vulns_new[k] for k in persistent_keys}),
        "regressions": regressions, "improvements": improvements,
        "ports_added": len(ports_added), "ports_removed": len(ports_removed),
        "ports_added_list": ports_added[:10], "ports_removed_list": ports_removed[:10],
        "trend": trend, "trend_message": trend_msg, "trend_icon": trend_icon,
        "fixed_details": fixed_details[:50],
        "new_details": new_details[:50],
        "persistent_details": persistent_details[:50],
        "score_breakdown_before": brk_old,
        "score_breakdown_after": brk_new,
        "ai_summary": ai_summary,
    }


def _load(scan):
    try:
        raw = scan.get("result_json")
        if not raw:
            return None, "no result"
        return json.loads(raw), None
    except Exception as e:
        return None, str(e)


def _trend(pct_fixed, new_count, score_delta):
    """score_delta = new - old. Negative delta = score decreased = improvement."""
    if pct_fixed >= 80 and score_delta <= 0:
        return "IMPROVING_RAPID", "Security posture improving rapidly", "🚀"
    if pct_fixed >= 50 and score_delta <= 0:
        return "IMPROVING", "Security posture is improving", "📈"
    if new_count > 0 and score_delta >= 0:
        return "DEGRADING", "Security posture is degrading", "📉"
    if pct_fixed > 0 and new_count == 0:
        return "STABLE_IMPROVING", "Steady improvement with no regressions", "✅"
    return "STABLE", "Security posture is stable", "➡️"


def _generate_ai_summary(fixed, new, persistent, score_delta, pct_fixed, regs, imps, ports_added, ports_removed):
    """score_delta = new - old. Negative = improved (score went down)."""
    parts = []
    if fixed > 0:
        parts.append(f"**{fixed}** vulnerability(ies) were fixed ({pct_fixed}% fix rate)")
    if new > 0:
        parts.append(f"**{new}** new vulnerability(ies) appeared since last scan")
    if persistent > 0:
        parts.append(f"**{persistent}** vulnerability(ies) remain unresolved")
    if regs > 0:
        parts.append(f"**{regs}** finding(s) increased in severity — investigate immediately")
    if imps > 0:
        parts.append(f"**{imps}** finding(s) decreased in severity")
    if ports_added > 0:
        parts.append(f"**{ports_added}** new port(s) exposed — review firewall rules")
    if ports_removed > 0:
        parts.append(f"**{ports_removed}** port(s) were closed — good")
    if score_delta < 0:
        parts.append(f"Security score **improved by {score_delta}** points (lower = better)")
    elif score_delta > 0:
        parts.append(f"Security score **worsened by +{score_delta}** points — review changes")
    else:
        parts.append("Security score remained unchanged")
    return ". ".join(parts)


def build_comparisons_for_user(light_scans, fetch_fn=None):
    if not light_scans:
        return []

    groups = defaultdict(list)
    for s in light_scans:
        if s.get("status") != "done" or s.get("scan_type") not in ("security",):
            continue
        mn = (s.get("machine_name") or "").strip().lower()
        tg = (s.get("target") or "").strip().lower().rstrip("/")
        if not mn or not tg:
            continue
        key = mn + "||" + tg
        groups[key].append(s)

    results = []
    for key, group in groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda x: x.get("created_at") or "")
        oldest, newest = group[0], group[-1]
        if fetch_fn:
            oldest = fetch_fn(oldest["id"]) or oldest
            newest = fetch_fn(newest["id"]) or newest
        comp = _compare_scan_pair(oldest, newest)
        if comp:
            comp["comparisons"] = []
            for i in range(len(group) - 1):
                older = group[i]
                newer = group[i + 1]
                if fetch_fn:
                    older = fetch_fn(older["id"]) or older
                    newer = fetch_fn(newer["id"]) or newer
                pair = _compare_scan_pair(older, newer)
                if pair:
                    comp["comparisons"].append(pair)
            results.append(comp)

    results.sort(key=lambda x: abs(x.get("score_before", 0) - x.get("score_after", 0)), reverse=True)
    return results
