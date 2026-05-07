SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}


def _severity(value):
    value = (value or "UNKNOWN").upper()
    return value if value in SEVERITY_ORDER else "UNKNOWN"


def _top_items(items, limit=5):
    return sorted(
        items or [],
        key=lambda item: SEVERITY_ORDER[_severity(item.get("severity"))],
    )[:limit]


def _tag_for_item(item):
    category = (item.get("category") or "").lower()
    title = (item.get("title") or "").lower()
    subtitle = (item.get("subtitle") or "").lower()
    tags = []

    if "port" in category:
        tags.append("Exposure")
    if "vulnerability" in category or title.startswith("cve"):
        tags.append("Patch Required")
    if "update" in category:
        tags.append("Missing Update")
    if "web" in category:
        tags.append("Web Risk")
    if "auth" in category:
        tags.append("Credentialed Insight")
    if any(word in title + subtitle for word in ("ftp", "telnet", "ssh", "rdp", "vnc", "smb", "winrm")):
        tags.append("Remote Access")
    if any(word in title + subtitle for word in ("mysql", "postgres", "mongodb", "redis", "mssql", "oracle")):
        tags.append("Database")
    if any(word in title + subtitle for word in ("apache", "nginx", "http", "web", "cookie", "header")):
        tags.append("Web Service")

    return tags or ["Finding"]


def _explain_item(item):
    severity = _severity(item.get("severity"))
    category = item.get("category") or "Finding"
    title = item.get("title") or "This item"
    recommendation = item.get("recommendation") or "Review and remediate this finding."

    if category == "Port":
        explanation = f"{title} is reachable from the scanner. Exposed services increase the attack surface."
        impact = "An attacker may fingerprint the service, attempt brute force, or exploit known service flaws."
    elif category == "Vulnerability":
        explanation = f"{title} matched known CVE intelligence for this target."
        impact = "If the affected product and version are confirmed, exploitation may lead to compromise or service abuse."
    elif category == "Missing Update":
        explanation = f"{title} indicates a component that likely needs a security update."
        impact = "Missing security patches leave the host exposed to known attacks."
    elif "Web" in category:
        explanation = f"{title} was identified during web checks."
        impact = "Web exposure can leak information or weaken browser/application protections."
    elif "Authentication" in category:
        explanation = f"{title} came from credentialed checks."
        impact = "Authenticated findings are usually more reliable because they inspect the target from inside."
    else:
        explanation = item.get("description") or f"{title} needs review."
        impact = "The impact depends on exposure, access controls, and the affected component."

    false_positive = "Low"
    false_positive_reason = "Evidence is directly tied to an exposed service or authenticated check."
    if category in ("Vulnerability", "Missing Update") and not item.get("evidence"):
        false_positive = "Medium"
        false_positive_reason = "CVE matching may be version-based or banner-based; confirm the installed version."
    if severity == "INFO":
        false_positive = "Low"
        false_positive_reason = "Informational items are observations, not confirmed vulnerabilities."

    return {
        "explanation": explanation,
        "impact": impact,
        "fix": recommendation,
        "tags": _tag_for_item(item),
        "false_positive": false_positive,
        "false_positive_reason": false_positive_reason,
    }


def enrich_scanned_items(items):
    for item in items or []:
        item["ai"] = _explain_item(item)
    return items


def _executive_summary(report):
    summary = report.get("summary") or {}
    system = report.get("system_profile") or {}
    counts = report.get("severity_counts") or {}
    target = report.get("target") or "target"
    risk_level = report.get("risk_level") or "INFO"

    return (
        f"{target} is assessed as {risk_level}. "
        f"The scanner identified {summary.get('open_ports', 0)} open port(s), "
        f"{summary.get('vulnerabilities', 0)} CVE-backed vulnerability item(s), "
        f"and {summary.get('missing_updates', 0)} missing update indicator(s). "
        f"System profile: {system.get('name', 'Unknown system')} "
        f"({system.get('confidence', 'Low')} confidence). "
        f"Severity distribution is Critical {counts.get('critical', 0)}, "
        f"High {counts.get('high', 0)}, Medium {counts.get('medium', 0)}, "
        f"Low {counts.get('low', 0)}, Info {counts.get('info', 0)}."
    )


def _remediation_plan(items):
    plan = []

    for item in _top_items(items, limit=8):
        plan.append({
            "severity": _severity(item.get("severity")),
            "title": item.get("title") or "Finding",
            "action": item.get("recommendation") or "Review and remediate this finding.",
            "why": (item.get("ai") or {}).get("impact") or item.get("description") or "",
        })

    if not plan:
        plan.append({
            "severity": "INFO",
            "title": "No urgent remediation",
            "action": "Keep monitoring this asset and rerun scans after changes.",
            "why": "No actionable findings were detected in the current scan.",
        })

    return plan


def _attack_paths(items):
    categories = {item.get("category") for item in items or []}
    titles = " ".join((item.get("title") or "").lower() for item in items or [])
    paths = []

    if "Port" in categories and "Vulnerability" in categories:
        paths.append({
            "name": "Public service to known exploit",
            "path": "Open service -> version/CVE match -> exploit attempt -> host compromise",
            "priority": "High",
        })
    if any(word in titles for word in ("telnet", "ftp", "vnc", "rdp", "ssh", "smb", "winrm")):
        paths.append({
            "name": "Remote access abuse",
            "path": "Remote access port -> credential guessing or reuse -> privileged access",
            "priority": "High",
        })
    if any(word in titles for word in ("admin", "login", "server-status", "phpinfo")):
        paths.append({
            "name": "Web information exposure",
            "path": "Interesting path -> information disclosure -> targeted exploit",
            "priority": "Medium",
        })

    return paths or [{
        "name": "No clear attack path",
        "path": "The current findings do not form an obvious exploit chain.",
        "priority": "Info",
    }]


def _tag_summary(items):
    counts = {}

    for item in items or []:
        for tag in (item.get("ai") or {}).get("tags") or _tag_for_item(item):
            counts[tag] = counts.get(tag, 0) + 1

    return [
        {"tag": tag, "count": count}
        for tag, count in sorted(counts.items(), key=lambda entry: (-entry[1], entry[0]))
    ]


def _false_positive_review(items):
    review = []

    for item in items or []:
        ai = item.get("ai") or {}
        if ai.get("false_positive") == "Medium":
            review.append({
                "title": item.get("title"),
                "reason": ai.get("false_positive_reason"),
                "check": "Confirm exact product and version on the target before closing the finding.",
            })

    return review or [{
        "title": "No major false-positive signals",
        "reason": "Current findings have direct evidence or are informational observations.",
        "check": "Still validate critical and high findings before production remediation.",
    }]


def build_ai_analysis(report):
    items = enrich_scanned_items(report.get("scanned_items") or [])

    return {
        "summary": _executive_summary(report),
        "system_guess": report.get("system_profile") or {},
        "remediation_plan": _remediation_plan(items),
        "attack_paths": _attack_paths(items),
        "tags": _tag_summary(items),
        "false_positive_review": _false_positive_review(items),
        "suggested_questions": [
            "What should I fix first?",
            "Why is this target risky?",
            "Which findings may be false positives?",
            "What is the likely attack path?",
            "Give me a short report summary.",
        ],
    }


def answer_scan_question(report, question):
    question = (question or "").strip().lower()
    ai = report.get("ai") or build_ai_analysis(report)
    items = report.get("scanned_items") or []

    if not question:
        return "Ask about remediation, risk, false positives, attack paths, ports, CVEs, or the system profile."

    if any(word in question for word in ("fix", "first", "remed", "repair", "priorit")):
        actions = ai.get("remediation_plan") or []
        return "Fix first: " + " | ".join(
            f"{item.get('severity')}: {item.get('title')} - {item.get('action')}"
            for item in actions[:3]
        )

    if any(word in question for word in ("false", "positive", "fp")):
        review = ai.get("false_positive_review") or []
        return "False-positive review: " + " | ".join(
            f"{item.get('title')}: {item.get('reason')}"
            for item in review[:4]
        )

    if any(word in question for word in ("attack", "path", "scenario", "exploit")):
        paths = ai.get("attack_paths") or []
        return "Possible attack paths: " + " | ".join(
            f"{item.get('name')}: {item.get('path')}"
            for item in paths[:3]
        )

    if any(word in question for word in ("system", "os", "windows", "linux", "ubuntu", "kali", "android")):
        system = ai.get("system_guess") or {}
        evidence = ", ".join(system.get("evidence") or []) or "No strong evidence."
        return (
            f"System guess: {system.get('name', 'Unknown system')} "
            f"({system.get('family', 'Unknown')}, {system.get('confidence', 'Low')} confidence). "
            f"Evidence: {evidence}"
        )

    if any(word in question for word in ("port", "service", "open")):
        ports = [item for item in items if item.get("category") == "Port"]
        if not ports:
            return "No open ports were found in this scan."
        return "Open ports: " + " | ".join(
            f"{item.get('title')} ({item.get('severity')})"
            for item in ports[:10]
        )

    if any(word in question for word in ("cve", "vuln", "vulnerability")):
        vulns = [item for item in items if item.get("category") == "Vulnerability"]
        if not vulns:
            return "No CVE-backed vulnerabilities were matched in this scan."
        return "Vulnerabilities: " + " | ".join(
            f"{item.get('title')} on {item.get('subtitle')} ({item.get('severity')})"
            for item in vulns[:8]
        )

    if any(word in question for word in ("summary", "short", "report", "resume")):
        return ai.get("summary") or _executive_summary(report)

    return ai.get("summary") or _executive_summary(report)
