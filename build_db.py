import os
import json
import sqlite3

conn = sqlite3.connect("cve.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS cves (
    id TEXT,
    description TEXT
)
""")

BASE = "cvelistV5/cves"

for root, dirs, files in os.walk(BASE):
    for file in files:
        if not file.endswith(".json"):
            continue

        path = os.path.join(root, file)

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            cve_id = data.get("cveMetadata", {}).get("cveId")

            descs = data.get("containers", {}).get("cna", {}).get("descriptions", [])

            if not descs:
                continue

            desc = descs[0]["value"].lower()

            cursor.execute(
                "INSERT INTO cves VALUES (?, ?)",
                (cve_id, desc)
            )

        except:
            pass

conn.commit()
conn.close()
