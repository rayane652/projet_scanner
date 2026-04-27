SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

SEVERITY_POINTS = {
    "CRITICAL": 25,
    "HIGH": 16,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 1,
    "UNKNOWN": 1,
}

SENSITIVE_PORTS = {
    21: ("MEDIUM", "FTP service exposed", "Use SFTP/FTPS and restrict access to trusted IPs."),
    23: ("HIGH", "Telnet service exposed", "Disable Telnet and use SSH instead."),
    445: ("HIGH", "SMB service exposed", "Restrict SMB to internal trusted networks only."),
    1433: ("HIGH", "MSSQL service exposed", "Restrict database access with firewall rules."),
    1521: ("HIGH", "Oracle database exposed", "Restrict database access with firewall rules."),
    2049: ("HIGH", "NFS service exposed", "Restrict NFS exports and network access."),
    3306: ("HIGH", "MySQL service exposed", "Restrict database access with firewall rules."),
    3389: ("HIGH", "Remote Desktop exposed", "Restrict RDP, require MFA, and use a VPN."),
    5432: ("HIGH", "PostgreSQL service exposed", "Restrict database access with firewall rules."),
    5900: ("HIGH", "VNC service exposed", "Disable public VNC or place it behind a VPN."),
    6379: ("HIGH", "Redis service exposed", "Bind Redis to localhost/private networks and require auth."),
    9200: ("HIGH", "Elasticsearch service exposed", "Restrict access and enable authentication."),
    27017: ("HIGH", "MongoDB service exposed", "Restrict access and enable authentication."),
}


def _severity(value):
    value = (value or "UNKNOWN").upper()
    return value if value in SEVERITY_POINTS else "UNKNOWN"


def _empty_counts():
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }


def _add_count(counts, severity):
    counts[_severity(severity).lower()] += 1


def _risk_level(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def _dedupe(items):
    output = []
    seen = set()

    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)

    return output


def _finding(severity, name, asset, detail, recommendation, evidence=""):
    return {
        "severity": _severity(severity),
        "name": name,
        "asset": asset,
        "detail": detail,
        "recommendation": recommendation,
        "evidence": evidence,
    }


def _port_findings(port_results):
    findings = []

    for result in port_results or []:
        port = result.get("port")
        service = result.get("service") or "unknown"
        product = result.get("product") or service
        version = result.get("version") or ""
        banner = result.get("banner") or ""
        asset = f"{service}:{port}"

        if port in SENSITIVE_PORTS:
            severity, name, recommendation = SENSITIVE_PORTS[port]
            findings.append(_finding(
                severity,
                name,
                asset,
                f"Port {port}/{service} is open.",
                recommendation,
                banner,
            ))

        if banner:
            findings.append(_finding(
                "INFO",
                "Service banner exposed",
                asset,
                "The service returns version or product information.",
                "Hide unnecessary banners where possible and keep the service updated.",
                banner[:180],
            ))

        for cve in result.get("cves") or []:
            cve_id = cve.get("cve") or "CVE"
            severity = _severity(cve.get("severity"))
            score = cve.get("score")
            detail = cve.get("description") or "Known vulnerability matched this service."
            product_name = f"{product} {version}".strip()

            if score:
                detail = f"{detail} CVSS {score}."

            findings.append(_finding(
                severity,
                f"{cve_id} on {product_name or service}",
                asset,
                detail,
                "Patch or upgrade the affected service and rescan after remediation.",
                banner[:180],
            ))

    return findings


def _web_findings(web_result):
    if not web_result or web_result.get("error"):
        return []

    final_url = web_result.get("final_url") or web_result.get("input") or "website"
    findings = []

    for finding in web_result.get("findings") or []:
        severity = _severity(finding.get("severity"))
        name = finding.get("name") or "Web finding"
        detail = finding.get("detail") or ""
        recommendation = "Review the web configuration and apply the missing hardening control."

        if "Missing" in name:
            recommendation = "Add the missing security header in the web server or application."
        elif "Cookie" in name:
            recommendation = "Set Secure and HttpOnly attributes for sensitive cookies."

        findings.append(_finding(
            severity,
            name,
            final_url,
            detail,
            recommendation,
        ))

    for path in web_result.get("interesting_paths") or []:
        findings.append(_finding(
            "INFO",
            "Interesting web path found",
            final_url,
            f"{path.get('path')} returned HTTP {path.get('status')}.",
            "Review the endpoint and ensure it does not expose sensitive information.",
        ))

    return findings


def _direct_cve_findings(cve_results, target):
    findings = []

    for cve in cve_results or []:
        cve_id = cve.get("cve") or "CVE"
        severity = _severity(cve.get("severity"))
        score = cve.get("score")
        detail = cve.get("description") or "Known vulnerability matched the search."

        if score:
            detail = f"{detail} CVSS {score}."

        findings.append(_finding(
            severity,
            cve_id,
            target,
            detail,
            "Confirm the affected product/version, patch it, and rescan.",
        ))

    return findings


def _auth_findings(auth_result):
    if not auth_result:
        return []

    status = auth_result.get("status")
    auth_type = auth_result.get("type_label") or auth_result.get("type") or "credentials"

    if status == "success":
        return [_finding(
            "INFO",
            "Authenticated checks completed",
            auth_type,
            auth_result.get("message") or "Credentials were accepted.",
            "Use authenticated results to prioritize patching and configuration fixes.",
        )]

    if status == "unavailable":
        severity = "LOW"
        name = "Authenticated checks unavailable"
    else:
        severity = "LOW"
        name = "Authenticated checks failed"

    return [_finding(
        severity,
        name,
        auth_type,
        auth_result.get("message") or "The scanner could not complete credentialed checks.",
        "Verify the credential type, username, password, and network access, then rescan.",
    )]


def build_security_report(
    target,
    port_results=None,
    web_result=None,
    cve_results=None,
    scan_mode="unauthenticated",
    auth_result=None,
):
    port_results = port_results or []
    cve_results = cve_results or []
    scan_mode = scan_mode if scan_mode == "authenticated" else "unauthenticated"
    counts = _empty_counts()

    findings = (
        _port_findings(port_results)
        + _web_findings(web_result)
        + _direct_cve_findings(cve_results, target)
        + _auth_findings(auth_result)
    )

    for finding in findings:
        _add_count(counts, finding["severity"])

    score = min(
        100,
        sum(SEVERITY_POINTS[_severity(finding["severity"])] for finding in findings),
    )

    services = [
        {
            "port": result.get("port"),
            "service": result.get("service") or "unknown",
            "product": result.get("product") or "",
            "version": result.get("version") or "",
        }
        for result in port_results
    ]

    findings.sort(key=lambda item: SEVERITY_ORDER[_severity(item["severity"])])

    recommendations = _dedupe([
        finding["recommendation"]
        for finding in findings
        if finding.get("recommendation")
    ])[:6]

    return {
        "target": target,
        "scan_mode": scan_mode,
        "scan_mode_label": (
            "Authenticated Scan"
            if scan_mode == "authenticated"
            else "Non-authenticated Scan"
        ),
        "authentication": auth_result,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "severity_counts": counts,
        "summary": {
            "open_ports": len(port_results),
            "services": len({result.get("service") for result in port_results if result.get("service")}),
            "cves": sum(len(result.get("cves") or []) for result in port_results) + len(cve_results),
            "findings": len(findings),
            "web_findings": len(_web_findings(web_result)),
        },
        "services": services,
        "findings": findings,
        "recommendations": recommendations,
        "raw": {
            "ports": port_results,
            "web": web_result,
            "cves": cve_results,
        },
    }
