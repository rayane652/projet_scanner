"""
NVD (National Vulnerability Database) Client for Vulnix
Fetches CVEs, CVSS scores, and vulnerability details
"""

import requests
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import os
import time

# ==================== NVD CLIENT ====================

class NVDClient:
    """Client for NVD API v2.0"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.last_request_time = 0
        self.request_count = 0
        
    def _rate_limit(self):
        """Rate limiting to avoid blocking"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if not self.api_key and elapsed < 6:
            time.sleep(6 - elapsed)
        elif self.api_key and self.request_count >= 45:
            time.sleep(30)
            self.request_count = 0
            
        self.last_request_time = time.time()
        self.request_count += 1
    
    def search_cves(self, keyword: str = None, cpe_name: str = None, limit: int = 20) -> List[Dict]:
        """Search CVEs in NVD database"""
        params = {"resultsPerPage": min(limit, 2000)}
        
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        
        self._rate_limit()
        
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_cves(data.get("vulnerabilities", []))
            else:
                print(f"NVD API error: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information for a specific CVE"""
        params = {"cveId": cve_id}
        
        self._rate_limit()
        
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    return self._parse_cve(vulns[0].get("cve", {}))
            return None
            
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
            return None
    
    def get_cves_by_product(self, product: str, version: str = None, limit: int = 20) -> List[Dict]:
        """Get CVEs for a specific product"""
        query = f"{product} {version}".strip()
        return self.search_cves(keyword=query, limit=limit)
    
    def _parse_cves(self, vulns: List[Dict]) -> List[Dict]:
        return [self._parse_cve(v.get("cve", {})) for v in vulns]
    
    def _parse_cve(self, cve_data: Dict) -> Dict:
        cve_id = cve_data.get("id", "")
        
        # Get description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:500]
                break
        
        # Get CVSS score
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = metric_list[0].get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                if cvss_score:
                    break
        
        # Fallback severity from score
        if not cvss_score:
            cvss_score = 0
        if severity == "UNKNOWN" and cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        
        # Get references
        references = [ref.get("url") for ref in cve_data.get("references", [])[:3]]
        
        # Get published date
        published = cve_data.get("published", "")[:10]
        
        return {
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published_date": published,
            "references": references,
            "source": "NVD"
        }


# ==================== LOCAL CACHE ====================

class LocalCVEDatabase:
    """Local SQLite cache for CVEs"""
    
    def __init__(self, db_path: str = "cve_cache.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                product TEXT,
                version TEXT,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                published_date TEXT,
                references TEXT,
                last_updated TEXT
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_product ON cve_cache(product)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON cve_cache(severity)")
        
        conn.commit()
        conn.close()
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "id": row[0],
                "product": row[1],
                "version": row[2],
                "cvss_score": row[3],
                "severity": row[4],
                "description": row[5],
                "published_date": row[6],
                "references": json.loads(row[7]) if row[7] else [],
            }
        return None
    
    def save_cve(self, cve: Dict, product: str = None, version: str = None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO cve_cache 
            (cve_id, product, version, cvss_score, severity, description, published_date, references, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve.get("id"),
            product or "",
            version or "",
            cve.get("cvss_score"),
            cve.get("severity"),
            cve.get("description"),
            cve.get("published_date"),
            json.dumps(cve.get("references", [])),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def get_cves_for_product(self, product: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM cve_cache WHERE product LIKE ? ORDER BY cvss_score DESC",
            (f"%{product}%",)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            "id": row[0],
            "cvss_score": row[3],
            "severity": row[4],
            "description": row[5],
        } for row in rows]


# ==================== MAIN FUNCTIONS ====================

# Initialize global instances
nvd_client = NVDClient(api_key=os.environ.get("NVD_API_KEY"))
local_cache = LocalCVEDatabase()


def search_cves_with_nvd(product: str, version: str = None, limit: int = 10) -> List[Dict]:
    """
    Search CVEs using NVD database with local cache
    
    Args:
        product: Product name (e.g., "nginx", "openssh")
        version: Optional version number
        limit: Max results to return
    
    Returns:
        List of CVEs with scores and descriptions
    """
    if not product:
        return []
    
    # Check local cache first
    cached_cves = local_cache.get_cves_for_product(product)
    
    if cached_cves and len(cached_cves) >= limit:
        return cached_cves[:limit]
    
    # Fetch from NVD API
    try:
        cves = nvd_client.get_cves_by_product(product, version, limit=limit)
        
        # Save to cache
        for cve in cves:
            local_cache.save_cve(cve, product, version)
        
        return cves
    except Exception as e:
        print(f"Error fetching from NVD: {e}")
        return []


def enrich_vulnerabilities_with_nvd(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Enrich existing vulnerabilities with NVD data
    """
    enriched = []
    
    for vuln in vulnerabilities:
        cve_id = vuln.get("id") or vuln.get("cve")
        
        if cve_id and cve_id.startswith("CVE"):
            cve_details = local_cache.get_cve(cve_id)
            
            if not cve_details:
                cve_details = nvd_client.get_cve_details(cve_id)
                if cve_details:
                    local_cache.save_cve(cve_details)
            
            if cve_details:
                vuln["cvss_score"] = cve_details.get("cvss_score")
                vuln["severity"] = cve_details.get("severity", vuln.get("severity", "UNKNOWN"))
                vuln["description"] = cve_details.get("description", vuln.get("description", ""))
                vuln["references"] = cve_details.get("references", [])
        
        enriched.append(vuln)
    
    return enriched


# ==================== TEST FUNCTION ====================

def test_nvd():
    """Simple test function to verify NVD integration"""
    print("Testing NVD integration...")
    
    # Test search
    cves = search_cves_with_nvd("nginx", limit=5)
    
    if cves:
        print(f"\n✅ Found {len(cves)} CVEs for nginx:")
        for cve in cves:
            print(f"  - {cve['id']}: {cve.get('severity', 'UNKNOWN')} (CVSS: {cve.get('cvss_score', 'N/A')})")
    else:
        print("\n⚠️ No CVEs found. Check API key or network connection.")
    
    return cves


if __name__ == "__main__":
    test_nvd()