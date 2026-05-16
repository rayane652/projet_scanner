import logging
import re
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

REMEDIATION_MAP = {
    "ssh": [
        "Disable SSH password authentication, use key-based authentication only",
        "Change default SSH port (22) to a non-standard port",
        "Restrict SSH access by IP using firewall rules or hosts.allow",
        "Keep OpenSSH updated to the latest version",
        "Disable root login over SSH (PermitRootLogin no)",
    ],
    "telnet": [
        "Replace Telnet with SSH immediately",
        "Disable Telnet service on all interfaces",
        "Block Telnet port (23) at the firewall",
    ],
    "ftp": [
        "Replace FTP with SFTP or FTPS",
        "Disable anonymous FTP login",
        "Restrict FTP access to specific IP addresses",
        "Use strong passwords for FTP accounts",
    ],
    "http": [
        "Enforce HTTPS with a valid TLS certificate",
        "Remove Server version header information",
        "Implement security headers: HSTS, X-Frame-Options, X-Content-Type-Options",
        "Run a web vulnerability scanner against the web server",
        "Keep web server software updated",
    ],
    "https": [
        "Ensure TLS 1.2 or 1.3 is enforced",
        "Disable weak cipher suites",
        "Keep TLS certificates valid and not expired",
        "Implement HTTP Strict Transport Security (HSTS)",
    ],
    "smb": [
        "Disable SMBv1 protocol",
        "Restrict SMB access to trusted IPs only",
        "Apply latest Windows security patches for SMB",
        "Use SMB signing if possible",
    ],
    "rdp": [
        "Restrict RDP access via VPN or jump box",
        "Enable Network Level Authentication (NLA)",
        "Use strong passwords for RDP accounts",
        "Keep Windows updated with latest RDP patches",
        "Consider using RD Gateway for external access",
    ],
    "mysql": [
        "Ensure MySQL is not exposed to the public internet",
        "Use strong passwords for MySQL accounts",
        "Disable default MySQL root remote access",
        "Keep MySQL updated to latest version",
        "Run MySQL behind a firewall",
    ],
    "postgresql": [
        "Ensure PostgreSQL is not exposed to public internet",
        "Use strong authentication methods (scram-sha-256)",
        "Restrict pg_hba.conf to trusted networks only",
        "Keep PostgreSQL updated",
    ],
    "redis": [
        "Ensure Redis is not exposed to public internet",
        "Enable Redis authentication (requirepass)",
        "Run Redis in protected mode",
        "Bind Redis to localhost only if possible",
        "Keep Redis updated",
    ],
    "mongodb": [
        "Enable MongoDB authentication",
        "Do not expose MongoDB to public internet",
        "Restrict MongoDB access to trusted IPs",
        "Keep MongoDB updated",
    ],
    "elasticsearch": [
        "Enable Elasticsearch security features",
        "Do not expose Elasticsearch to public internet",
        "Use strong passwords and role-based access",
        "Keep Elasticsearch updated",
    ],
    "vnc": [
        "Use SSH tunneling for VNC connections",
        "Use strong VNC passwords",
        "Restrict VNC access to localhost and tunnel via SSH",
        "Consider using a VPN instead of direct VNC",
    ],
    "dns": [
        "Restrict DNS zone transfers to authorized servers only",
        "Keep BIND or DNS software updated",
        "Use DNSSEC if possible",
        "Run DNS server as non-root user",
    ],
    "snmp": [
        "Use SNMPv3 with strong authentication and encryption",
        "Disable SNMPv1 and SNMPv2c",
        "Restrict SNMP access to management IPs only",
        "Change default community strings",
    ],
    "smtp": [
        "Disable open relay on SMTP server",
        "Use STARTTLS for SMTP connections",
        "Implement SPF, DKIM, and DMARC",
        "Restrict SMTP access to authorized senders",
    ],
    "ftp-data": [
        "Replace with SFTP or HTTPS file transfer",
        "Disable FTP if not needed",
        "Use firewall to restrict FTP data ports",
    ],
    "winrm": [
        "Use HTTPS for WinRM (port 5986) instead of HTTP",
        "Restrict WinRM access to trusted admin IPs",
        "Use strong authentication for WinRM",
    ],
    "rpcbind": [
        "Restrict RPC services with firewall rules",
        "Disable unnecessary RPC services",
        "Use TCP wrappers to limit access",
    ],
    "nfs": [
        "Restrict NFS exports to specific IPs/subnets",
        "Use NFSv4 with Kerberos authentication",
        "Export filesystems as read-only where possible",
    ],
    "adb": [
        "Disable ADB debugging on production devices",
        "Restrict ADB to authorized USB connections only",
    ],
    "mqtt": [
        "Enable MQTT authentication",
        "Use MQTT over TLS (port 8883)",
        "Restrict MQTT topic access with ACLs",
    ],
    "coap": [
        "Use CoAP over DTLS for encryption",
        "Restrict CoAP access to trusted clients",
    ],
}

DEFAULT_REMEDIATION = [
    "Apply latest security patches and updates",
    "Review firewall rules to minimize exposed services",
    "Conduct regular vulnerability assessments",
    "Implement network segmentation for critical assets",
    "Enable logging and monitoring for security events",
]


def _log_with_timestamp(msg, *args):
    logger.info("[%s] " + msg, datetime.utcnow().isoformat(), *args)


def enrich_network_results(raw_result):
    if not isinstance(raw_result, dict) or raw_result.get("error"):
        return raw_result

    _log_with_timestamp("Enriching network scan results with intelligence layer")

    raw_result.setdefault("intel", {})
    hosts = raw_result.get("hosts", [])

    enriched_hosts = []
    for host in hosts:
        enriched = _enrich_host(host)
        enriched_hosts.append(enriched)
    raw_result["hosts"] = enriched_hosts

    attack_surface = _compute_attack_surface(enriched_hosts)
    raw_result["intel"]["attack_surface"] = attack_surface

    risk_analytics = _compute_risk_analytics(enriched_hosts, raw_result.get("aggregated", {}))
    raw_result["intel"]["risk_analytics"] = risk_analytics

    remediation_plan = _build_remediation_plan(enriched_hosts)
    raw_result["intel"]["remediation_plan"] = remediation_plan

    asset_inventory = _build_asset_inventory(enriched_hosts)
    raw_result["intel"]["asset_inventory"] = asset_inventory

    _log_with_timestamp("Enrichment complete: %d hosts enriched, %d vulns mapped, attack surface: %d exposed services, risk score: %d",
        len(enriched_hosts), sum(len(h.get("cves", [])) for h in enriched_hosts),
        attack_surface.get("total_exposed_services", 0), raw_result.get("risk_score", 0))

    return raw_result


def _enrich_host(host):
    host = dict(host)
    host.setdefault("cves", [])
    host.setdefault("ports", [])
    host.setdefault("remediation", [])

    enriched_cves = []
    for cve in host.get("cves", []):
        enriched = _enrich_cve(cve, host)
        enriched_cves.append(enriched)
    host["cves"] = enriched_cves

    enriched_ports = []
    for port in host.get("ports", []):
        enriched_port = dict(port)
        enriched_port["remediation"] = _get_port_remediation(enriched_port)
        enriched_ports.append(enriched_port)
    host["ports"] = enriched_ports

    host["vulnerability_count"] = len([c for c in enriched_cves if c.get("severity", "").upper() != "INFO"])
    host["critical_vulns"] = len([c for c in enriched_cves if c.get("severity", "").upper() == "CRITICAL"])
    host["high_vulns"] = len([c for c in enriched_cves if c.get("severity", "").upper() == "HIGH"])
    host["medium_vulns"] = len([c for c in enriched_cves if c.get("severity", "").upper() == "MEDIUM"])
    host["low_vulns"] = len([c for c in enriched_cves if c.get("severity", "").upper() == "LOW"])

    services = [p.get("service", "unknown") for p in host.get("ports", []) if p.get("service")]
    host["technology_stack"] = list(set(filter(None, services)))
    host["total_technologies"] = len(host["technology_stack"])

    remediations = []
    for p in host.get("ports", []):
        remediations.extend(p.get("remediation", []))
    host["remediation"] = list(set(remediations))

    _log_with_timestamp("Enriched host %s: %d ports, %d CVEs, %d remediations",
        host.get("ip", "?"), len(host["ports"]), host["vulnerability_count"], len(host["remediation"]))

    return host


def _enrich_cve(cve, host):
    cve = dict(cve)
    severity = (cve.get("severity") or "INFO").upper()
    cvss_score = cve.get("cvss_score") or cve.get("score")

    cve["cvss_label"] = _cvss_label(severity)
    cve["cvss_color"] = _cvss_color(severity)
    cve["risk_urgency"] = _risk_urgency(severity, cvss_score)
    cve["remediation"] = _get_cve_remediation(cve)
    cve["affected_host"] = host.get("ip", "")
    cve["affected_service"] = _match_cve_to_service(cve, host)

    _log_with_timestamp("  Mapped CVE %s (%s, CVSS: %s) on %s -> %s",
        cve.get("id", "N/A"), severity, cvss_score or "N/A",
        host.get("ip", "?"), cve.get("affected_service", "unknown"))

    return cve


def _cvss_label(severity):
    return {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
    }.get(severity, "UNKNOWN")


def _cvss_color(severity):
    return {
        "CRITICAL": "#7f1d1d",
        "HIGH": "#dc2626",
        "MEDIUM": "#ea580c",
        "LOW": "#16a34a",
        "INFO": "#64748b",
    }.get(severity, "#64748b")


def _risk_urgency(severity, cvss_score):
    if severity == "CRITICAL":
        return "Immediate"
    if severity == "HIGH":
        return "Urgent"
    if severity == "MEDIUM":
        return "Important"
    if severity == "LOW":
        return "Monitor"
    return "Informational"


def _get_cve_remediation(cve):
    severity = (cve.get("severity") or "INFO").upper()
    cve_id = cve.get("id", "")

    base = [
        f"Apply vendor patch for {cve_id}",
        "Update affected software to latest version",
    ]

    if severity == "CRITICAL":
        base.insert(0, f"CRITICAL: {cve_id} requires immediate patching")
        base.append("Consider temporary mitigation if patch is not available")
    elif severity == "HIGH":
        base.insert(0, f"Schedule patching for {cve_id} as high priority")

    return base


def _match_cve_to_service(cve, host):
    cve_text = (cve.get("description") or "").lower()
    for port in host.get("ports", []):
        svc = (port.get("service") or "").lower()
        prod = (port.get("product") or "").lower()
        if svc and svc in cve_text:
            return port.get("service")
        if prod and prod in cve_text:
            return port.get("product")
    return "unknown"


REMEDIATION_MAP_LOWER = {k.lower(): v for k, v in REMEDIATION_MAP.items()}


def _get_port_remediation(port):
    service = (port.get("service") or "").lower().strip()
    product = (port.get("product") or "").lower().strip()

    for key, remediations in REMEDIATION_MAP_LOWER.items():
        if key in service or key in product:
            return remediations

    return DEFAULT_REMEDIATION


def _compute_attack_surface(hosts):
    total_exposed = 0
    high_risk_services = []
    service_inventory = defaultdict(list)
    protocol_counts = defaultdict(int)
    risky_port_ranges = {
        "database": {1433, 1521, 3306, 5432, 6379, 9200, 27017, 11211},
        "remote_access": {22, 23, 3389, 5900, 5985, 5986, 5555},
        "file_sharing": {21, 139, 445, 2049, 111},
        "web": {80, 443, 8080, 8443},
        "mail": {25, 110, 143, 465, 587, 993, 995},
    }
    risk_counts = defaultdict(int)

    for host in hosts:
        for port in host.get("ports", []):
            pnum = port.get("port")
            svc = port.get("service", "unknown")
            total_exposed += 1
            service_inventory[svc].append(host.get("ip", ""))

            for category, ports_set in risky_port_ranges.items():
                if pnum in ports_set:
                    risk_counts[category] += 1
                    if category == "remote_access":
                        high_risk_services.append({
                            "ip": host.get("ip", ""),
                            "port": pnum,
                            "service": svc,
                            "category": category,
                        })
                    break

    _log_with_timestamp(
        "Attack surface: %d total exposed services, %d high-risk access points, "
        "categories: %s",
        total_exposed,
        len(high_risk_services),
        dict(risk_counts),
    )

    attack_surface_score = min(100, total_exposed * 2 + len(high_risk_services) * 5)

    return {
        "total_exposed_services": total_exposed,
        "unique_services": len(service_inventory),
        "high_risk_access_points": len(high_risk_services),
        "attack_surface_score": attack_surface_score,
        "attack_surface_level": _risk_level_from_score(attack_surface_score),
        "risk_breakdown": dict(risk_counts),
        "high_risk_details": high_risk_services[:20],
    }


def _risk_level_from_score(score):
    score = max(0, min(100, score))
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _compute_risk_analytics(hosts, aggregated):
    analytics = {}

    total_hosts = len(hosts)
    total_cves = sum(len(h.get("cves", [])) for h in hosts)
    total_vulns = sum(h.get("vulnerability_count", 0) for h in hosts)

    hosts_with_critical = sum(1 for h in hosts if h.get("critical_vulns", 0) > 0)
    hosts_with_high = sum(1 for h in hosts if h.get("high_vulns", 0) > 0)

    most_vulnerable = sorted(hosts, key=lambda h: h.get("vulnerability_count", 0), reverse=True)[:5]
    analytics["most_vulnerable_assets"] = [
        {
            "ip": h.get("ip", ""),
            "hostname": h.get("hostname", ""),
            "vulnerability_count": h.get("vulnerability_count", 0),
            "critical_count": h.get("critical_vulns", 0),
            "high_count": h.get("high_vulns", 0),
            "risk_score": h.get("risk_score", 0),
            "risk_level": h.get("risk_level", "LOW"),
        }
        for h in most_vulnerable
    ]

    vulns_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for h in hosts:
        for cve in h.get("cves", []):
            sev = (cve.get("severity") or "info").lower()
            if sev in vulns_by_severity:
                vulns_by_severity[sev] += 1

    analytics["vulnerability_summary"] = vulns_by_severity
    analytics["total_unique_cves"] = total_cves
    analytics["total_vulnerabilities"] = total_vulns
    analytics["hosts_with_critical"] = hosts_with_critical
    analytics["hosts_with_high"] = hosts_with_high
    analytics["vulnerability_density"] = round(total_vulns / total_hosts, 1) if total_hosts else 0
    analytics["affected_hosts_ratio"] = round(
        (hosts_with_critical + hosts_with_high) / total_hosts * 100, 1
    ) if total_hosts else 0

    _log_with_timestamp(
        "Risk analytics: %d total vulns, %d critical, %d high, "
        "density: %.1f/host, affected ratio: %.1f%%",
        total_vulns,
        vulns_by_severity.get("critical", 0),
        vulns_by_severity.get("high", 0),
        analytics["vulnerability_density"],
        analytics["affected_hosts_ratio"],
    )

    return analytics


def _build_remediation_plan(hosts):
    all_remediations = defaultdict(list)

    for host in hosts:
        for cve in host.get("cves", []):
            severity = (cve.get("severity") or "INFO").upper()
            cve_id = cve.get("id", "N/A")
            for rec in cve.get("remediation", []):
                all_remediations[severity].append({
                    "cve_id": cve_id,
                    "host": host.get("ip", ""),
                    "action": rec,
                    "severity": severity,
                })

    plan = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = all_remediations.get(severity, [])
        if items:
            unique_actions = list(set(item["action"] for item in items))
            plan.append({
                "severity": severity,
                "count": len(items),
                "unique_actions_count": len(unique_actions),
                "affected_hosts": list(set(item["host"] for item in items)),
                "priority_actions": unique_actions[:5],
            })

    plan.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4))

    _log_with_timestamp("Remediation plan: %d severity levels with actions", len(plan))
    return plan


def _build_asset_inventory(hosts):
    inventory = []

    for host in hosts:
        asset = {
            "ip": host.get("ip", ""),
            "hostname": host.get("hostname", ""),
            "mac": host.get("mac", ""),
            "vendor": host.get("vendor", ""),
            "device_type": host.get("device_type", "unknown"),
            "os": host.get("os", "Unknown"),
            "os_confidence": host.get("os_confidence", "low"),
            "risk_score": host.get("risk_score", 0),
            "risk_level": host.get("risk_level", "LOW"),
            "open_port_count": len(host.get("ports", [])),
            "vulnerability_count": host.get("vulnerability_count", 0),
            "critical_vulns": host.get("critical_vulns", 0),
            "high_vulns": host.get("high_vulns", 0),
            "medium_vulns": host.get("medium_vulns", 0),
            "low_vulns": host.get("low_vulns", 0),
            "technology_stack": host.get("technology_stack", []),
            "services": list(set(
                p.get("service", "unknown") for p in host.get("ports", [])
            )),
            "last_seen": datetime.utcnow().isoformat(),
            "status": "online",
        }
        inventory.append(asset)

    _log_with_timestamp("Asset inventory: %d assets cataloged", len(inventory))
    for asset in inventory:
        _log_with_timestamp(
            "  Asset %s | OS: %s | Type: %s | Ports: %d | Vulns: %d | Risk: %s",
            asset["ip"],
            asset["os"],
            asset["device_type"],
            asset["open_port_count"],
            asset["vulnerability_count"],
            asset["risk_level"],
        )

    return inventory
