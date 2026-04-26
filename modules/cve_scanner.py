import sqlite3

def search_cves(product, version):
    conn = sqlite3.connect("cve.db")
    cursor = conn.cursor()

    query = f"%{product}%{version}%"

    cursor.execute(
        "SELECT id, description FROM cves WHERE description LIKE ? LIMIT 5",
        (query,)
    )

    results = []

    for row in cursor.fetchall():
        results.append({
            "cve": row[0],
            "description": row[1][:120],
            "severity": "UNKNOWN"
        })

    conn.close()

    return results
