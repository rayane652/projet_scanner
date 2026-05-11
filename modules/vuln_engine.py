from modules.port_scanner import scan_ports
from modules.cve_scanner import search_cves
from modules.service_detector import detect_service_and_version


def run_vuln_scan(target, scan_method="connect", include_udp=False):
    ports = scan_ports(
        target,
        scan_method=scan_method,
        include_udp=include_udp,
    )

    final_results = []

    if not ports:
        return []

    for p in ports:
        port = p["port"]
        protocol = p.get("protocol") or "tcp"
        banner = p.get("banner", "")

        service, version, product = detect_service_and_version(port, banner, protocol)

        cves = []

        if product:
            cves = search_cves(product, version)

        final_results.append({
            "port": port,
            "protocol": protocol,
            "state": p.get("state") or "open",
            "service": service,
            "version": version,
            "product": product,
            "banner": banner,
            "scan_method": p.get("scan_method") or "tcp_connect",
            "reason": p.get("reason") or "",
            "ttl": p.get("ttl"),
            "tcp_window": p.get("tcp_window"),
            "os_hint": p.get("os_hint") or "",
            "cves": cves
        })

    return final_results

from modules.cve_scanner import search_cves

# Quand tu détectes un service
service_name = "nginx"  # exemple
service_version = "1.18.0"

cves = search_cves(service_name, service_version)
if cves:
    print(f"Found {len(cves)} CVEs for {service_name}")
    for cve in cves:
        print(f"  - {cve['id']}: {cve['severity']}")