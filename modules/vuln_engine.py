from modules.cve_scanner import search_cves
from modules.port_scanner import scan_ports
from modules.service_detector import detect_service_and_version


def run_vuln_scan(target, scan_method="connect", include_udp=False):
    ports = scan_ports(
        target,
        scan_method=scan_method,
        include_udp=include_udp,
    )

    final_results = []
    if not ports:
        return final_results

    for port_result in ports:
        port = port_result["port"]
        protocol = port_result.get("protocol") or "tcp"
        banner = port_result.get("banner", "")
        state = port_result.get("state") or "open"

        service, version, product, confidence = detect_service_and_version(port, banner, protocol)
        cves = search_cves(product, version) if product else []

        final_results.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version,
            "product": product,
            "product_confidence": confidence,
            "banner": banner,
            "scan_method": port_result.get("scan_method") or "tcp_connect",
            "reason": port_result.get("reason") or "",
            "ttl": port_result.get("ttl"),
            "tcp_window": port_result.get("tcp_window"),
            "os_hint": port_result.get("os_hint") or "",
            "cves": cves,
        })

    return final_results
