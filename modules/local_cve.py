import os
import json

CVE_PATH = "cvelistV5/cves"


def search_local_cves(product, version):
    results = []

    for root, dirs, files in os.walk(CVE_PATH):
        for file in files:
            if not file.endswith(".json"):
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                desc = data.get("containers", {}).get("cna", {}).get("descriptions", [])

                if not desc:
                    continue

                text = desc[0]["value"].lower()

                # 🎯 فلترة product + version
                if product in text and version in text:
                    results.append({
                        "cve": data.get("cveMetadata", {}).get("cveId"),
                        "description": text[:120],
                        "severity": "UNKNOWN"
                    })

                if len(results) >= 5:
                    return results

            except:
                continue

    return results
