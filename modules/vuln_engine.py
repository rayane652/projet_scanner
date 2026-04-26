from modules.port_scanner import scan_ports
from modules.cve_scanner import search_cves
from modules.service_detector import detect_service_and_version


def run_vuln_scan(target):
    ports = scan_ports(target)

    final_results = []

    if not ports:
        return []

    for p in ports:
        port = p["port"]
        banner = p.get("banner", "")

        service, version, product = detect_service_and_version(port, banner)

        print("BANNER:", banner)

        cves = []

        if product:
            cves = search_cves(product, version)

        final_results.append({
            "port": port,
            "service": service,
            "version": version,
            "product": product,
            "banner": banner,
            "cves": cves
        })

    return final_results
