import requests

def get_severity(score):
    try:
        score = float(score)
    except:
        return "UNKNOWN"

    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def search_cves(product, version):
    query = f"{product} {version}"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=10"

    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        results = []

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]

            # 🔥 فلترة السنة
            try:
                year = int(cve.split("-")[1])
                if year < 2005:
                    continue
            except:
                continue

            # 🔥 فلترة بالـ product
            if product.lower() not in desc.lower():
                continue

            # 🔥 CVSS
            metrics = item["cve"].get("metrics", {})
            score = 0

            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            results.append({
                "cve": cve,
                "description": desc[:120],
                "severity": get_severity(score)
            })

        return results[:5]

    except:
        return []
