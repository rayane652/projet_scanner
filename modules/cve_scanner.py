import requests


PRODUCT_ALIASES = {
    "apache": ("apache", "apache http server", "httpd"),
    "nginx": ("nginx",),
    "openssh": ("openssh", "openbsd openssh"),
    "vsftpd": ("vsftpd", "vsftp"),
    "postfix": ("postfix",),
    "mysql": ("mysql",),
    "mariadb": ("mariadb",),
    "microsoft iis": ("microsoft iis", "internet information services", "iis"),
    "microsoft sql server": ("microsoft sql server", "sql server", "mssql"),
    "postgresql": ("postgresql", "postgres"),
    "redis": ("redis",),
    "mongodb": ("mongodb",),
    "elasticsearch": ("elasticsearch", "elastic search"),
    "vnc": ("vnc", "virtual network computing"),
}


def get_severity(score=None, severity=None):
    if severity:
        return str(severity).upper()

    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _english_description(descriptions):
    if not descriptions:
        return ""

    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")

    return descriptions[0].get("value", "")


def _best_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue

        metric = values[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity")
        return score, severity

    return None, None


def _matches_product(text, product, query):
    aliases = PRODUCT_ALIASES.get(product.lower(), (product.lower(),))

    if any(alias and alias in text for alias in aliases):
        return True

    return query.lower() in text


def search_cves(product, version=""):
    product = (product or "").strip()
    version = (version or "").strip()

    if not product:
        return []

    query = f"{product} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 20,
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        results = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve = cve_data.get("id", "")
            desc = _english_description(cve_data.get("descriptions", []))

            try:
                year = int(cve.split("-")[1])
                if year < 2005:
                    continue
            except (IndexError, ValueError):
                continue

            desc_lower = desc.lower()
            if not _matches_product(desc_lower, product, query):
                continue

            score, severity = _best_cvss(cve_data.get("metrics", {}))

            results.append({
                "cve": cve,
                "description": desc[:120],
                "severity": get_severity(score, severity),
                "score": score,
            })

        return results[:5]

    except (requests.RequestException, ValueError):
        return []
