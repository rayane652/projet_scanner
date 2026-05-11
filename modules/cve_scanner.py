"""
CVE Scanner - Hybride: API NVD d'abord, puis base locale
"""

import requests
import os
from dotenv import load_dotenv

# Charge .env
load_dotenv()

# Ta clé API depuis .env
NVD_API_KEY = os.environ.get("NVD_API_KEY")

# Base locale de secours
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


def search_cves(product: str, version: str = "") -> list:
    # Force API d'abord
    cves = search_cves_api(product, version)
    if cves:
        return cves
    return search_cves_local(product, version)


def search_cves_api(product: str, version: str = "") -> list:
    """Search CVEs using REAL NVD API with your API key from .env"""
    query = f"{product} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    headers = {"apiKey": NVD_API_KEY}
    params = {
        "keywordSearch": query,
        "resultsPerPage": 10,
    }
    
    response = requests.get(url, headers=headers, params=params, timeout=15)
    
    if response.status_code != 200:
        return []
    
    data = response.json()
    results = []
    
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        
        # Get description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:200]
                break
        
        # Get CVSS score
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        
        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = metric_list[0].get("baseSeverity", "UNKNOWN")
                if cvss_score:
                    break
        
        if cvss_score is None:
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                cvss_score = cvss_v2[0].get("cvssData", {}).get("baseScore")
        
        if severity == "UNKNOWN" and cvss_score:
            if cvss_score >= 9.0: severity = "CRITICAL"
            elif cvss_score >= 7.0: severity = "HIGH"
            elif cvss_score >= 4.0: severity = "MEDIUM"
            elif cvss_score > 0: severity = "LOW"
        
        results.append({
            "id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "source": "NVD API"
        })
    
    return results[:10]


def search_cves_local(product: str, version: str = "") -> list:
    """Fallback: search in local database"""
    product_lower = product.lower()
    
    for key, cves in LOCAL_CVE_DB.items():
        if key in product_lower or product_lower in key:
            result = []
            for cve in cves:
                result.append({
                    "id": cve["id"],
                    "description": cve["description"],
                    "severity": cve["severity"],
                    "cvss_score": cve.get("cvss_score"),
                    "source": "Local DB"
                })
            return result
    
    return []


if __name__ == "__main__":
    print("Testing CVE search...")
    print(f"NVD_API_KEY from .env: {'✅ Loaded' if NVD_API_KEY else '❌ Not found'}")
    
    cves = search_cves("nginx")
    for cve in cves:
        print(f"{cve['id']} - {cve['severity']} ({cve['source']})")