from modules.nvd_client import nvd_client, epss_client

LOCAL_CVE_DB = {
    "nginx": [
        {"id": "CVE-2021-23017", "severity": "HIGH", "cvss_score": 7.5,
         "description": "HTTP request smuggling vulnerability in nginx"},
        {"id": "CVE-2020-11724", "severity": "MEDIUM", "cvss_score": 5.3,
         "description": "Information disclosure in nginx"},
    ],
    "openssh": [
        {"id": "CVE-2023-38408", "severity": "CRITICAL", "cvss_score": 9.8,
         "description": "Remote code execution in OpenSSH agent"},
    ],
    "mysql": [
        {"id": "CVE-2022-21407", "severity": "HIGH", "cvss_score": 7.1,
         "description": "MySQL Server vulnerability"},
    ],
    "redis": [
        {"id": "CVE-2022-0543", "severity": "CRITICAL", "cvss_score": 9.8,
         "description": "Lua sandbox escape in Redis"},
    ],
    "apache": [
        {"id": "CVE-2022-31813", "severity": "HIGH", "cvss_score": 7.5,
         "description": "HTTP request smuggling in Apache HTTP Server"},
    ],
}


def _normalize(cve):
    cve["cve"] = cve.get("id", "")
    cve["score"] = cve.get("cvss_score")
    return cve


def search_cves(product: str, version: str = "") -> list:
    if not product:
        return []

    try:
        results = nvd_client.search_by_product(product, version or None, limit=10)
        if results:
            cve_ids = [c["id"] for c in results if c.get("id")]
            if cve_ids:
                epss_map = epss_client.get_scores(cve_ids)
                for cve in results:
                    epid = (cve.get("id") or "").upper()
                    if epid in epss_map:
                        cve["epss_score"] = epss_map[epid]["epss_score"]
                        cve["epss_percentile"] = epss_map[epid]["epss_percentile"]
                    cve["source"] = "NVD"
                    _normalize(cve)
            return results
    except Exception:
        pass

    return search_cves_local(product, version)


def search_cves_local(product: str, version: str = "") -> list:
    product_lower = product.lower()
    for key, cves in LOCAL_CVE_DB.items():
        if key in product_lower or product_lower in key:
            return [
                {
                    "id": cve["id"],
                    "cve": cve["id"],
                    "description": cve["description"],
                    "severity": cve["severity"],
                    "cvss_score": cve.get("cvss_score"),
                    "score": cve.get("cvss_score"),
                    "source": "Local DB",
                }
                for cve in cves
            ]
    return []


def _matches_product(text, product, query):
    return product in text or query in text


def get_severity(score, severity):
    if severity:
        return severity.upper()
    if score is not None:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0: return "LOW"
    return "UNKNOWN"


if __name__ == "__main__":
    print("Testing CVE search via nvd_client...")
    cves = search_cves("nginx")
    for cve in cves:
        print(f"  {cve['id']} - {cve['severity']} ({cve.get('source', '?')})")
        if cve.get("cwes"):
            print(f"    CWE: {', '.join(cve['cwes'])}")
        if cve.get("epss_score") is not None:
            print(f"    EPSS: {cve['epss_score']}")
        if cve.get("is_kev"):
            print(f"    CISA KEV: YES")
        if cve.get("references"):
            print(f"    References: {len(cve['references'])} URLs")
