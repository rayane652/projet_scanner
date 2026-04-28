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

SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}

SEVERITY_COLORS = {
    "CRITICAL": "#8f1d1d",
    "HIGH": "#ef2525",
    "MEDIUM": "#e07a00",
    "LOW": "#2563eb",
    "INFO": "#66758a",
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
    5985: ("HIGH", "WinRM service exposed", "Restrict WinRM to trusted admin networks."),
    5986: ("HIGH", "WinRM over HTTPS exposed", "Restrict WinRM to trusted admin networks."),
    6379: ("HIGH", "Redis service exposed", "Bind Redis to localhost/private networks and require auth."),
    9200: ("HIGH", "Elasticsearch service exposed", "Restrict access and enable authentication."),
    5555: ("CRITICAL", "Android Debug Bridge exposed", "Disable ADB over network or restrict it immediately."),
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


def _risk_level_from_counts(counts):
    if counts["critical"] > 0:
        return "CRITICAL"
    if counts["high"] > 0:
        return "HIGH"
    if counts["medium"] > 0:
        return "MEDIUM"
    if counts["low"] > 0:
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


def _finding(
    severity,
    name,
    asset,
    detail,
    recommendation,
    evidence="",
    category="Finding",
    cves=None,
    metadata=None,
):
    return {
        "severity": _severity(severity),
        "category": category,
        "name": name,
        "asset": asset,
        "detail": detail,
        "recommendation": recommendation,
        "evidence": evidence,
        "cves": cves or [],
        "metadata": metadata or {},
        "status": "Open",
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
                "Exposed Service",
                metadata={
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                },
            ))

        if banner:
            findings.append(_finding(
                "INFO",
                "Service banner exposed",
                asset,
                "The service returns version or product information.",
                "Hide unnecessary banners where possible and keep the service updated.",
                banner[:180],
                "Service Inventory",
                metadata={
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                },
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
                "Vulnerability",
                cves=[{
                    "id": cve_id,
                    "severity": severity,
                    "score": score,
                    "description": cve.get("description") or "",
                }],
                metadata={
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                },
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
            category="Web Hardening",
            metadata={
                "url": final_url,
            },
        ))

    for path in web_result.get("interesting_paths") or []:
        findings.append(_finding(
            "INFO",
            "Interesting web path found",
            final_url,
            f"{path.get('path')} returned HTTP {path.get('status')}.",
            "Review the endpoint and ensure it does not expose sensitive information.",
            category="Web Path",
            metadata={
                "path": path.get("path"),
                "status": path.get("status"),
                "url": final_url,
            },
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
            category="Vulnerability",
            cves=[{
                "id": cve_id,
                "severity": severity,
                "score": score,
                "description": cve.get("description") or "",
            }],
        ))

    return findings


def _auth_findings(auth_result):
    if not auth_result:
        return []

    status = auth_result.get("status")
    auth_type = auth_result.get("type_label") or auth_result.get("type") or "credentials"
    checks = auth_result.get("checks") or []
    inventory = auth_result.get("inventory") or {}

    deep_findings = []

    for check in checks:
        check_status = (check.get("status") or "info").lower()
        severity = "INFO"
        if check_status == "failed":
            severity = "MEDIUM"
        elif check_status == "success":
            severity = "INFO"

        deep_findings.append(_finding(
            severity,
            f"Auth check: {check.get('name') or 'Check'}",
            auth_type,
            check.get("detail") or "",
            "Review authenticated scan evidence and remediate weak configurations.",
            category="Authentication",
        ))

    if inventory.get("world_writable"):
        deep_findings.append(_finding(
            "HIGH",
            "World-writable files in sensitive paths",
            auth_type,
            "Authenticated SSH checks discovered world-writable files under /etc, /var/www, or /opt.",
            "Restrict file permissions to least privilege and audit ownership.",
            evidence=", ".join((inventory.get("world_writable") or [])[:3]),
            category="Authentication",
        ))

    if inventory.get("sudo_rights"):
        deep_findings.append(_finding(
            "MEDIUM",
            "Privileged sudo rights detected",
            auth_type,
            "Authenticated account appears to have sudo capabilities.",
            "Review sudoers configuration and remove unnecessary elevated access.",
            evidence=", ".join((inventory.get("sudo_rights") or [])[:2]),
            category="Authentication",
        ))

    if inventory.get("protected_paths"):
        deep_findings.append(_finding(
            "INFO",
            "Credential-protected paths enumerated",
            auth_type,
            f"{len(inventory.get('protected_paths') or [])} protected web path(s) were accessible with credentials.",
            "Review access controls and validate role-based restrictions.",
            category="Authentication",
        ))

    if status == "success":
        return [_finding(
            "INFO",
            "Authenticated checks completed",
            auth_type,
            auth_result.get("message") or "Credentials were accepted.",
            "Use authenticated results to prioritize patching and configuration fixes.",
            category="Authentication",
        )] + deep_findings

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
        category="Authentication",
    )] + deep_findings


def _highest_severity(values, default="INFO"):
    severities = [_severity(value) for value in values if value]

    if not severities:
        return default

    return sorted(severities, key=lambda item: SEVERITY_ORDER[item])[0]


def _severity_breakdown(counts):
    visible_counts = {
        "CRITICAL": counts["critical"],
        "HIGH": counts["high"],
        "MEDIUM": counts["medium"],
        "LOW": counts["low"],
        "INFO": counts["info"] + counts["unknown"],
    }
    total = sum(visible_counts.values()) or 1

    return [
        {
            "key": key.lower(),
            "label": SEVERITY_LABELS[key],
            "count": count,
            "percent": int((count / total) * 100),
            "color": SEVERITY_COLORS[key],
        }
        for key, count in visible_counts.items()
    ]


def _severity_ring_style(counts):
    visible_counts = [
        ("CRITICAL", counts["critical"]),
        ("HIGH", counts["high"]),
        ("MEDIUM", counts["medium"]),
        ("LOW", counts["low"]),
        ("INFO", counts["info"] + counts["unknown"]),
    ]
    total = sum(count for _, count in visible_counts)

    if total == 0:
        return "conic-gradient(#e2e8f0 0% 100%)"

    current = 0
    parts = []

    for severity, count in visible_counts:
        if count == 0:
            continue

        start = current
        current += (count / total) * 100
        parts.append(
            f"{SEVERITY_COLORS[severity]} {start:.2f}% {current:.2f}%"
        )

    return f"conic-gradient({', '.join(parts)})"


def _counts_from_items(items):
    counts = _empty_counts()

    for item in items:
        _add_count(counts, item.get("severity"))

    return counts


def _parse_os_release(text):
    values = {}

    for line in (text or "").splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')

    return values.get("PRETTY_NAME") or values.get("NAME") or ""


def _system_profile(target, open_ports, web_result=None, auth_result=None):
    evidence = []
    os_name = ""
    family = "Unknown"
    confidence = "Low"

    auth_inventory = (auth_result or {}).get("inventory", {})
    auth_os = _parse_os_release(auth_inventory.get("os", ""))

    if auth_os:
        os_name = auth_os
        family = "Linux"
        confidence = "High"
        evidence.append("Authenticated SSH /etc/os-release")

        lower_os = auth_os.lower()
        if "metasploitable" in lower_os:
            family = "Metasploitable"
        elif "kali" in lower_os:
            family = "Kali Linux"
        elif "ubuntu" in lower_os:
            family = "Ubuntu Linux"
        elif "debian" in lower_os:
            family = "Debian Linux"
        elif "metasploitable" in lower_os:
            family = "Metasploitable"

    banners = " ".join(port.get("banner", "") for port in open_ports).lower()
    services = {port.get("service") for port in open_ports}
    ports = {port.get("port") for port in open_ports}

    if not os_name:
        if 5555 in ports or "android" in banners or "adb" in services:
            family = "Android"
            os_name = "Android / ADB exposed"
            confidence = "Medium"
            evidence.append("ADB service or Android banner")
        elif {135, 139, 445, 3389, 5985, 5986} & ports:
            family = "Windows"
            os_name = "Windows host likely"
            confidence = "Medium"
            evidence.append("Windows administration ports detected")
        elif (
            {"ssh", "ftp", "smtp", "nfs", "postgresql", "redis"} & services
            or "openssh" in banners
            or "ubuntu" in banners
            or "debian" in banners
            or "kali" in banners
            or "metasploitable" in banners
        ):
            family = "Linux/Unix"
            os_name = "Linux/Unix host likely"
            confidence = "Medium"
            evidence.append("Unix-like services or banners detected")

    if "metasploitable" in banners and "Metasploitable" not in os_name:
        os_name = "Metasploitable likely"
        family = "Metasploitable"
        evidence.append("Metasploitable banner")
    elif "ubuntu" in banners and "Ubuntu" not in os_name:
        os_name = "Ubuntu Linux likely"
        family = "Ubuntu Linux"
        evidence.append("Ubuntu banner")
    elif "kali" in banners and "Kali" not in os_name:
        os_name = "Kali Linux likely"
        family = "Kali Linux"
        evidence.append("Kali banner")
    elif "debian" in banners and "Debian" not in os_name:
        os_name = "Debian Linux likely"
        family = "Debian Linux"
        evidence.append("Debian banner")
    web_headers = (web_result or {}).get("headers", {})
    server = web_headers.get("Server") or (web_result or {}).get("server") or ""

    if server:
        evidence.append(f"Server header: {server}")

    return {
        "target": target,
        "name": os_name or "Unknown system",
        "family": family,
        "confidence": confidence,
        "evidence": _dedupe(evidence),
    }


def _open_ports(port_results):
    ports = []

    for result in port_results or []:
        port = result.get("port")
        service = result.get("service") or "unknown"
        product = result.get("product") or ""
        version = result.get("version") or ""
        cves = result.get("cves") or []
        cve_severity = _highest_severity([cve.get("severity") for cve in cves])
        sensitive_severity = SENSITIVE_PORTS.get(port, ("INFO", "", ""))[0]
        severity = _highest_severity([cve_severity, sensitive_severity])

        ports.append({
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "banner": result.get("banner") or "",
            "severity": severity,
            "cve_count": len(cves),
            "cves": cves,
            "description": f"TCP port {port} is open and mapped to {service}.",
            "recommendation": (
                SENSITIVE_PORTS.get(port, ("", "", ""))[2]
                or "Keep this service patched and restrict access when possible."
            ),
        })

    return ports


def _vulnerabilities(port_results, cve_results, target):
    vulnerabilities = []

    for result in port_results or []:
        port = result.get("port")
        service = result.get("service") or "unknown"
        product = result.get("product") or service
        version = result.get("version") or ""

        for cve in result.get("cves") or []:
            cve_id = cve.get("cve") or "CVE"
            severity = _severity(cve.get("severity"))
            vulnerabilities.append({
                "id": cve_id,
                "severity": severity,
                "score": cve.get("score"),
                "asset": f"{service}:{port}",
                "product": product,
                "version": version,
                "port": port,
                "description": cve.get("description") or "Known vulnerability matched this service.",
                "recommendation": "Patch or upgrade the affected service and rescan.",
            })

    for cve in cve_results or []:
        cve_id = cve.get("cve") or "CVE"
        vulnerabilities.append({
            "id": cve_id,
            "severity": _severity(cve.get("severity")),
            "score": cve.get("score"),
            "asset": target,
            "product": target,
            "version": "",
            "port": "",
            "description": cve.get("description") or "Known vulnerability matched the search.",
            "recommendation": "Confirm the affected product/version, patch it, and rescan.",
        })

    vulnerabilities.sort(key=lambda item: SEVERITY_ORDER[_severity(item["severity"])])
    return vulnerabilities


def _web_paths(web_result):
    if not web_result or web_result.get("error"):
        return []

    final_url = web_result.get("final_url") or web_result.get("input") or "website"

    return [
        {
            "path": path.get("path") or "",
            "status": path.get("status"),
            "url": final_url,
            "severity": "INFO",
            "description": (
                f"{path.get('path')} returned HTTP {path.get('status')} during the path check."
            ),
            "recommendation": "Review the endpoint and remove or protect sensitive paths.",
        }
        for path in web_result.get("interesting_paths") or []
    ]


def _missing_updates(vulnerabilities, auth_result=None):
    updates_by_key = {}

    for vulnerability in vulnerabilities:
        key = (
            vulnerability.get("asset"),
            vulnerability.get("product"),
            vulnerability.get("version"),
        )
        product = vulnerability.get("product") or vulnerability.get("asset")
        version = vulnerability.get("version") or "detected version"

        update = updates_by_key.setdefault(key, {
            "severity": vulnerability.get("severity") or "UNKNOWN",
            "asset": vulnerability.get("asset"),
            "product": product,
            "version": version,
            "cves": [],
            "description": (
                f"{product} has matched CVE results. Treat this as a missing update "
                "until the exact installed version is confirmed."
            ),
            "recommendation": "Install the vendor security update or upgrade to a fixed version.",
        })

        update["severity"] = _highest_severity([
            update.get("severity"),
            vulnerability.get("severity"),
        ])
        update["cves"].append({
            "id": vulnerability.get("id"),
            "severity": vulnerability.get("severity"),
            "score": vulnerability.get("score"),
            "description": vulnerability.get("description") or "",
        })

    updates = list(updates_by_key.values())

    package_updates = (
        (auth_result or {})
        .get("inventory", {})
        .get("package_updates", [])
    )

    for package in package_updates:
        updates.append({
            "severity": "MEDIUM",
            "asset": (auth_result or {}).get("type_label") or "Authenticated host",
            "product": package,
            "version": "package manager update",
            "cves": [],
            "description": (
                "Authenticated package manager output reported this package as upgradable."
            ),
            "recommendation": "Review and install the package update on the authenticated host.",
        })

    updates.sort(key=lambda item: SEVERITY_ORDER[_severity(item["severity"])])
    return updates


def _scanned_items(
    open_ports,
    vulnerabilities,
    web_paths,
    missing_updates,
    web_findings,
    auth_result,
):
    items = []

    for port in open_ports:
        items.append({
            "category": "Port",
            "severity": port["severity"],
            "title": f"Port {port['port']} / {port['service']}",
            "subtitle": f"{port.get('product') or 'Unknown product'} {port.get('version') or ''}".strip(),
            "description": port["description"],
            "evidence": port.get("banner") or "No banner received.",
            "recommendation": port["recommendation"],
            "cves": [
                {
                    "id": cve.get("cve") or "CVE",
                    "severity": _severity(cve.get("severity")),
                    "score": cve.get("score"),
                    "description": cve.get("description") or "",
                }
                for cve in port.get("cves") or []
            ],
            "details": [
                ("Port", port.get("port")),
                ("Service", port.get("service")),
                ("Product", port.get("product") or "Unknown"),
                ("Version", port.get("version") or "Unknown"),
                ("CVEs", port.get("cve_count")),
            ],
        })

    for vulnerability in vulnerabilities:
        items.append({
            "category": "Vulnerability",
            "severity": vulnerability["severity"],
            "title": vulnerability["id"],
            "subtitle": vulnerability.get("asset") or "",
            "description": vulnerability.get("description") or "",
            "evidence": (
                f"Matched product: {vulnerability.get('product') or 'Unknown'} "
                f"{vulnerability.get('version') or ''}".strip()
            ),
            "recommendation": vulnerability["recommendation"],
            "cves": [{
                "id": vulnerability["id"],
                "severity": vulnerability["severity"],
                "score": vulnerability.get("score"),
                "description": vulnerability.get("description") or "",
            }],
            "details": [
                ("CVSS", vulnerability.get("score") or "Unknown"),
                ("Product", vulnerability.get("product") or "Unknown"),
                ("Version", vulnerability.get("version") or "Unknown"),
                ("Port", vulnerability.get("port") or "N/A"),
            ],
        })

    for path in web_paths:
        items.append({
            "category": "Web Path",
            "severity": path["severity"],
            "title": path["path"],
            "subtitle": f"HTTP {path.get('status')}",
            "description": path["description"],
            "evidence": path.get("url") or "",
            "recommendation": path["recommendation"],
            "cves": [],
            "details": [
                ("Path", path.get("path")),
                ("HTTP status", path.get("status")),
                ("Base URL", path.get("url")),
            ],
        })

    for finding in web_findings:
        items.append({
            "category": finding.get("category") or "Web Finding",
            "severity": finding.get("severity") or "INFO",
            "title": finding.get("name") or "Web finding",
            "subtitle": finding.get("asset") or "",
            "description": finding.get("detail") or "",
            "evidence": finding.get("evidence") or "",
            "recommendation": finding.get("recommendation") or "Review the web configuration.",
            "cves": finding.get("cves") or [],
            "details": [
                ("Asset", finding.get("asset")),
                ("Category", finding.get("category")),
                ("Status", finding.get("status")),
            ],
        })

    for update in missing_updates:
        items.append({
            "category": "Missing Update",
            "severity": update["severity"],
            "title": f"Update required: {update['product']}",
            "subtitle": update.get("asset") or "",
            "description": update["description"],
            "evidence": f"Version: {update.get('version') or 'Unknown'}",
            "recommendation": update["recommendation"],
            "cves": update.get("cves") or [],
            "details": [
                ("Asset", update.get("asset")),
                ("Product", update.get("product")),
                ("Version", update.get("version")),
                ("Related CVEs", len(update.get("cves") or [])),
            ],
        })

    if auth_result:
        items.append({
            "category": "Authentication",
            "severity": "INFO" if auth_result.get("status") == "success" else "LOW",
            "title": auth_result.get("type_label") or "Authenticated checks",
            "subtitle": auth_result.get("status") or "",
            "description": auth_result.get("message") or "",
            "evidence": f"Username: {auth_result.get('username') or 'N/A'}",
            "recommendation": "Use valid credentials for deeper host checks.",
            "cves": [],
            "details": [
                ("Credential type", auth_result.get("type_label")),
                ("Status", auth_result.get("status")),
                ("Username", auth_result.get("username")),
            ],
        })

        for check in auth_result.get("checks") or []:
            check_status = (check.get("status") or "info").lower()
            check_severity = "INFO"
            if check_status == "failed":
                check_severity = "MEDIUM"

            items.append({
                "category": "Authentication Check",
                "severity": check_severity,
                "title": check.get("name") or "Authenticated check",
                "subtitle": auth_result.get("type_label") or "",
                "description": check.get("detail") or "",
                "evidence": f"Status: {check_status}",
                "recommendation": "Review this authenticated check and harden the affected host/application.",
                "cves": [],
                "details": [
                    ("Credential type", auth_result.get("type_label")),
                    ("Check status", check_status),
                    ("Username", auth_result.get("username")),
                ],
            })

        inventory = auth_result.get("inventory") or {}

        if inventory.get("world_writable"):
            items.append({
                "category": "Authentication Exposure",
                "severity": "HIGH",
                "title": "World-writable files found",
                "subtitle": auth_result.get("type_label") or "",
                "description": (
                    "Authenticated checks found world-writable files in sensitive system/application paths."
                ),
                "evidence": ", ".join((inventory.get("world_writable") or [])[:3]),
                "recommendation": "Fix permissions and ownership, then rerun an authenticated scan.",
                "cves": [],
                "details": [
                    ("Affected files", len(inventory.get("world_writable") or [])),
                    ("Credential type", auth_result.get("type_label")),
                    ("Username", auth_result.get("username")),
                ],
            })

        if inventory.get("sudo_rights"):
            items.append({
                "category": "Authentication Exposure",
                "severity": "MEDIUM",
                "title": "Sudo privileges detected",
                "subtitle": auth_result.get("type_label") or "",
                "description": "Authenticated account appears to have sudo privileges.",
                "evidence": ", ".join((inventory.get("sudo_rights") or [])[:2]),
                "recommendation": "Limit sudo rules to minimum required commands and users.",
                "cves": [],
                "details": [
                    ("Sudo entries", len(inventory.get("sudo_rights") or [])),
                    ("Credential type", auth_result.get("type_label")),
                    ("Username", auth_result.get("username")),
                ],
            })

    items.sort(key=lambda item: SEVERITY_ORDER[_severity(item["severity"])])
    return items


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
    web_findings = _web_findings(web_result)

    findings = (
        _port_findings(port_results)
        + web_findings
        + _direct_cve_findings(cve_results, target)
        + _auth_findings(auth_result)
    )

    open_ports = _open_ports(port_results)
    vulnerabilities = _vulnerabilities(port_results, cve_results, target)
    web_paths = _web_paths(web_result)
    web_item_findings = [
        finding
        for finding in web_findings
        if finding.get("category") != "Web Path"
    ]
    missing_updates = _missing_updates(vulnerabilities, auth_result)
    scanned_items = _scanned_items(
        open_ports,
        vulnerabilities,
        web_paths,
        missing_updates,
        web_item_findings,
        auth_result,
    )
    counts = _counts_from_items(scanned_items)
    score = min(
        100,
        sum(SEVERITY_POINTS[_severity(item["severity"])] for item in scanned_items),
    )
    services = [
        {
            "port": port.get("port"),
            "service": port.get("service") or "unknown",
            "product": port.get("product") or "",
            "version": port.get("version") or "",
            "severity": port.get("severity") or "INFO",
            "cve_count": port.get("cve_count") or 0,
        }
        for port in open_ports
    ]
    system_profile = _system_profile(target, open_ports, web_result, auth_result)

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
        "system_profile": system_profile,
        "authentication": auth_result,
        "risk_score": score,
        "risk_level": _risk_level_from_counts(counts),
        "severity_counts": counts,
        "severity_breakdown": _severity_breakdown(counts),
        "severity_ring_style": _severity_ring_style(counts),
        "summary": {
            "open_ports": len(port_results),
            "services": len({result.get("service") for result in port_results if result.get("service")}),
            "cves": sum(len(result.get("cves") or []) for result in port_results) + len(cve_results),
            "vulnerabilities": len(vulnerabilities),
            "web_paths": len(web_paths),
            "missing_updates": len(missing_updates),
            "findings": len(scanned_items),
            "web_findings": len(web_findings),
            "scanned_items": len(scanned_items),
        },
        "services": services,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "web_paths": web_paths,
        "missing_updates": missing_updates,
        "scanned_items": scanned_items,
        "findings": findings,
        "recommendations": recommendations,
        "raw": {
            "ports": port_results,
            "web": web_result,
            "cves": cve_results,
        },
    }
