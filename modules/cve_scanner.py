import requests

def search_cves(keyword):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        results = []

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]

            results.append({
                "cve": cve,
                "description": desc[:150]
            })

        return results

    except:
        return []
