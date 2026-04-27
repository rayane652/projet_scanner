import json
import os

from modules.cve_scanner import _matches_product, get_severity


CVE_PATH = "cvelistV5/cves"


def _description(data):
    descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])

    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")

    if descriptions:
        return descriptions[0].get("value", "")

    return ""


def _severity(data):
    metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])

    for metric in metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss = metric.get(key)
            if not cvss:
                continue

            return get_severity(
                cvss.get("baseScore"),
                cvss.get("baseSeverity"),
            )

    return "UNKNOWN"


def search_local_cves(product, version=""):
    product = (product or "").strip().lower()
    version = (version or "").strip().lower()

    if not product:
        return []

    results = []

    for root, dirs, files in os.walk(CVE_PATH):
        for file in files:
            if not file.endswith(".json"):
                continue

            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                text = _description(data).lower()
                query = f"{product} {version}".strip()
                if not _matches_product(text, product, query):
                    continue
                if version and version not in text:
                    continue

                results.append({
                    "cve": data.get("cveMetadata", {}).get("cveId"),
                    "description": text[:120],
                    "severity": _severity(data),
                })

                if len(results) >= 5:
                    return results

            except (OSError, json.JSONDecodeError, KeyError, TypeError):
                continue

    return results
