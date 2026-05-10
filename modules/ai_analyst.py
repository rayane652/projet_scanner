"""
ai_analyst.py — VulniX AI Analyst
Provides both a fast static analysis layer (for initial page render)
and a live Gemini-powered chat layer (for interactive Q&A).
"""

import os
import requests

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

MAX_HISTORY_TURNS = 10   # keep last N user+assistant pairs


# ──────────────────────────────────────────────────────────────────────────────
# LOW-LEVEL HELPERS (no API, used for static enrichment on page load)
# ──────────────────────────────────────────────────────────────────────────────

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
    title    = (item.get("title") or "").lower()
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
    if any(w in title + subtitle for w in ("ftp", "telnet", "ssh", "rdp", "vnc", "smb", "winrm")):
        tags.append("Remote Access")
    if any(w in title + subtitle for w in ("mysql", "postgres", "mongodb", "redis", "mssql", "oracle")):
        tags.append("Database")
    if any(w in title + subtitle for w in ("apache", "nginx", "http", "web", "cookie", "header")):
        tags.append("Web Service")

    return tags or ["Finding"]


def _explain_item(item):
    severity     = _severity(item.get("severity"))
    category     = item.get("category") or "Finding"
    title        = item.get("title") or "This item"
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


# ──────────────────────────────────────────────────────────────────────────────
# STATIC ANALYSIS (fast, no API — used for initial page render)
# ──────────────────────────────────────────────────────────────────────────────

def _executive_summary(report):
    summary    = report.get("summary") or {}
    system     = report.get("system_profile") or {}
    counts     = report.get("severity_counts") or {}
    target     = report.get("target") or "target"
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
            "title":    item.get("title") or "Finding",
            "action":   item.get("recommendation") or "Review and remediate this finding.",
            "why":      (item.get("ai") or {}).get("impact") or item.get("description") or "",
        })

    if not plan:
        plan.append({
            "severity": "INFO",
            "title":    "No urgent remediation",
            "action":   "Keep monitoring this asset and rerun scans after changes.",
            "why":      "No actionable findings were detected in the current scan.",
        })

    return plan


def _attack_paths(items):
    categories = {item.get("category") for item in items or []}
    titles = " ".join((item.get("title") or "").lower() for item in items or [])
    paths = []

    if "Port" in categories and "Vulnerability" in categories:
        paths.append({
            "name":     "Public service to known exploit",
            "path":     "Open service → version/CVE match → exploit attempt → host compromise",
            "priority": "High",
        })
    if any(w in titles for w in ("telnet", "ftp", "vnc", "rdp", "ssh", "smb", "winrm")):
        paths.append({
            "name":     "Remote access abuse",
            "path":     "Remote access port → credential guessing or reuse → privileged access",
            "priority": "High",
        })
    if any(w in titles for w in ("admin", "login", "server-status", "phpinfo")):
        paths.append({
            "name":     "Web information exposure",
            "path":     "Interesting path → information disclosure → targeted exploit",
            "priority": "Medium",
        })

    return paths or [{
        "name":     "No clear attack path",
        "path":     "The current findings do not form an obvious exploit chain.",
        "priority": "Info",
    }]


def _tag_summary(items):
    counts = {}
    for item in items or []:
        for tag in (item.get("ai") or {}).get("tags") or _tag_for_item(item):
            counts[tag] = counts.get(tag, 0) + 1

    return [
        {"tag": tag, "count": count}
        for tag, count in sorted(counts.items(), key=lambda e: (-e[1], e[0]))
    ]


def _false_positive_review(items):
    review = []
    for item in items or []:
        ai = item.get("ai") or {}
        if ai.get("false_positive") == "Medium":
            review.append({
                "title":  item.get("title"),
                "reason": ai.get("false_positive_reason"),
                "check":  "Confirm exact product and version on the target before closing the finding.",
            })

    return review or [{
        "title":  "No major false-positive signals",
        "reason": "Current findings have direct evidence or are informational observations.",
        "check":  "Still validate critical and high findings before production remediation.",
    }]


def build_ai_analysis(report):
    items = enrich_scanned_items(report.get("scanned_items") or [])

    return {
        "summary":               _executive_summary(report),
        "system_guess":          report.get("system_profile") or {},
        "remediation_plan":      _remediation_plan(items),
        "attack_paths":          _attack_paths(items),
        "tags":                  _tag_summary(items),
        "false_positive_review": _false_positive_review(items),
        "suggested_questions": [
            "What should I fix first?",
            "Explain the CVEs in simple terms",
            "Generate a remediation script",
            "Walk me through the attack path",
            "Which findings might be false positives?",
            "Give me an executive summary",
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# AI-POWERED CHAT (Claude API)
# ──────────────────────────────────────────────────────────────────────────────

def _build_system_prompt(report):
    """Build a rich security-context system prompt from the scan report."""
    target     = report.get("target") or "unknown target"
    risk_level = report.get("risk_level") or "UNKNOWN"
    summary    = report.get("summary") or {}
    counts     = report.get("severity_counts") or {}
    system     = report.get("system_profile") or {}
    items      = report.get("scanned_items") or []

    top_items = _top_items(items, limit=20)
    findings_lines = []
    for it in top_items:
        sev  = _severity(it.get("severity"))
        cat  = it.get("category") or "?"
        ttl  = it.get("title") or "?"
        sub  = it.get("subtitle") or ""
        desc = it.get("description") or ""
        rec  = it.get("recommendation") or ""
        line = f"  [{sev}] {cat}: {ttl}"
        if sub:  line += f" on {sub}"
        if desc: line += f" — {desc}"
        if rec:  line += f" | Fix: {rec}"
        findings_lines.append(line)
    findings_block = "\n".join(findings_lines) or "  (no findings)"

    ports   = [i for i in items if i.get("category") == "Port"]
    vulns   = [i for i in items if i.get("category") == "Vulnerability"]
    updates = [i for i in items if i.get("category") == "Missing Update"]

    port_list   = ", ".join(i.get("title", "") for i in ports[:15])  or "none"
    vuln_list   = ", ".join(i.get("title", "") for i in vulns[:10])  or "none"
    update_list = ", ".join(i.get("title", "") for i in updates[:10]) or "none"

    return f"""You are VulniX AI, an expert offensive/defensive cybersecurity analyst embedded in a network vulnerability scanner.

===========================  SCAN CONTEXT  ===========================
Target      : {target}
Risk Level  : {risk_level}
OS Guess    : {system.get('name', 'Unknown')} ({system.get('confidence', '?')} confidence)
OS Evidence : {', '.join(system.get('evidence', []) or ['none'])}

Open Ports  : {summary.get('open_ports', 0)} found -> {port_list}
CVE Vulns   : {summary.get('vulnerabilities', 0)} found -> {vuln_list}
Missing Upd : {summary.get('missing_updates', 0)} found -> {update_list}

Severity    : Critical={counts.get('critical', 0)}  High={counts.get('high', 0)}  Medium={counts.get('medium', 0)}  Low={counts.get('low', 0)}  Info={counts.get('info', 0)}

TOP FINDINGS (sorted by severity):
{findings_block}
======================================================================

YOUR CAPABILITIES — use them proactively:

1. ATTACK PATH ANALYSIS
   Trace a realistic step-by-step exploitation chain.
   Format as: Step 1 -> Step 2 -> ... -> Impact
   Explain WHY each step is possible from the actual findings.

2. PRIORITIZATION
   Rank by: exploitability x impact x ease-of-fix.
   Give a numbered list with one-line reasoning per item.

3. REMEDIATION SCRIPTS
   Write ready-to-run Bash or Python scripts when asked.
   Use proper code fences (```bash or ```python).
   Make scripts safe, idempotent, and well-commented.

4. CVE EXPLANATION (plain language)
   Explain CVEs as if talking to a smart non-security person.
   Use analogies. Cover: what it is, who exploits it, what they gain, difficulty.
   Example style: "This is like leaving your front door unlocked because..."

5. FALSE POSITIVE ANALYSIS
   Assess whether findings are real or noise.
   Consider: banner-based vs version-confirmed, auth context, evidence.
   Give confidence: "Likely Real" / "Needs Verification" / "Likely FP"

RULES:
- Be direct and actionable. No filler text.
- Respond in the SAME language the user writes in (French, Arabic/Darija, English).
- For scripts, ALWAYS use markdown code fences.
- If a question contains a CVE ID, always explain it even if not explicitly asked.
- When uncertain, say so clearly — never invent patch versions or exploit details.
- Keep answers focused and under 400 words unless a script is needed.
"""


def _call_gemini(system_prompt, messages, max_tokens=1500):

    import time

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        return None

    formatted_messages = [
        {
            "role": "system",
            "content": system_prompt
        }
    ]

    for msg in messages:
        formatted_messages.append({
            "role": msg["role"],
            "content": msg["content"]
        })

    model = "openai/gpt-oss-20b:free"

    for attempt in range(3):

        try:

            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": formatted_messages,
                    "max_tokens": 500
                },
                timeout=25
            )

            print("MODEL:", model)
            print("STATUS:", response.status_code)

            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]

            if response.status_code == 429:
                print("Rate limited, retrying...")
                time.sleep(3)

        except Exception as e:
            print("ERROR:", e)

    return None


def _fallback_answer(report, question):
    """Keyword-based fallback when no API key is configured."""
    question = (question or "").strip().lower()
    items    = report.get("scanned_items") or []
    ai_data  = build_ai_analysis(report)

    if any(w in question for w in ("fix", "first", "remed", "repair", "priorit")):
        actions = ai_data.get("remediation_plan") or []
        return "**Fix first:**\n" + "\n".join(
            f"- **{a.get('severity')}**: {a.get('title')} — {a.get('action')}"
            for a in actions[:3]
        )

    if any(w in question for w in ("false", "positive", "fp", "noise")):
        review = ai_data.get("false_positive_review") or []
        return "**False-positive review:**\n" + "\n".join(
            f"- **{r.get('title')}**: {r.get('reason')}"
            for r in review[:4]
        )

    if any(w in question for w in ("attack", "path", "exploit", "chain")):
        paths = ai_data.get("attack_paths") or []
        return "**Possible attack paths:**\n" + "\n".join(
            f"- **{p.get('name')}** ({p.get('priority')}): {p.get('path')}"
            for p in paths[:3]
        )

    if any(w in question for w in ("script", "bash", "command", "how to fix")):
        top = _top_items(items, limit=1)
        if top:
            t = top[0]
            return (
                f"**Remediation for {t.get('title')}:**\n\n"
                f"```bash\n# Fix: {t.get('recommendation', 'Review this finding.')}\n"
                f"# Run on target host as root/sudo\necho 'Apply fix for {t.get('title')}'\n```\n\n"
                f"> Set `GEMINI_API_KEY` in `.env` for AI-generated scripts."
            )
        return "No findings to generate a script for."

    if any(w in question for w in ("cve", "vuln", "vulnerability", "explain")):
        vulns = [i for i in items if i.get("category") == "Vulnerability"]
        if not vulns:
            return "No CVE-backed vulnerabilities were matched in this scan."
        lines = [
            f"- **{v.get('title')}** on `{v.get('subtitle', '')}` ({v.get('severity')})"
            for v in vulns[:6]
        ]
        return (
            "**CVEs found:**\n" + "\n".join(lines) +
            "\n\n> Set `GEMINI_API_KEY` in `.env` for detailed plain-language explanations."
        )

    if any(w in question for w in ("port", "service", "open")):
        ports = [i for i in items if i.get("category") == "Port"]
        if not ports:
            return "No open ports were found in this scan."
        lines = [f"- {p.get('title')} ({p.get('severity')})" for p in ports[:10]]
        return "**Open ports:**\n" + "\n".join(lines)

    return ai_data.get("summary") or _executive_summary(report)


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def answer_scan_question(report, question, history=None):
    """
    Answer a question about a scan result using Claude AI.

    Parameters
    ----------
    report   : dict  — parsed scan result JSON
    question : str   — the user's current message
    history  : list  — previous turns [{role, content}, ...] (optional)
    """
    question = (question or "").strip()
    if not question:
        return "Ask me about risk, CVEs, ports, false positives, attack paths, or ask for a remediation script."

    # Trim history to last N turns to avoid oversized prompts
    raw_history = (history or [])[-MAX_HISTORY_TURNS * 2:]
    messages    = raw_history + [{"role": "user", "content": question}]

    system_prompt = _build_system_prompt(report)
    answer        = _call_gemini(system_prompt, messages)

    if answer is None:
        answer = _fallback_answer(report, question)

    return answer
