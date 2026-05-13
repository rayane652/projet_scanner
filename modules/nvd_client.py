"""
nvd_client.py — VulniX NVD Integration
National Vulnerability Database API v2.0

Features:
  - CVE search by keyword, product, CPE
  - Full CVSS v3.1 / v3.0 / v2.0 data (score, vector, exploitability, impact)
  - CWE extraction
  - EPSS score (FIRST.org) — probability of exploitation
  - CISA KEV flag — known exploited in the wild
  - SQLite cache with TTL
  - Proper rate limiting
"""

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_KEY   = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"

# Rate limits (NVD): 50 req/30s with key, 5 req/30s without
RATE_WINDOW        = 30       # seconds
RATE_LIMIT_KEY     = 45       # requests per window with API key
RATE_LIMIT_NO_KEY  = 4        # requests per window without key

# Cache TTL
CACHE_TTL_HOURS    = 24 * 7   # 7 days for CVE data
CACHE_DB_PATH      = os.path.join(os.path.dirname(__file__), "..", "cve_cache.db")


# ─────────────────────────────────────────────────────────────────────────────
#  Local SQLite cache
# ─────────────────────────────────────────────────────────────────────────────

class _Cache:
    """Thread-safe SQLite cache with TTL."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id          TEXT PRIMARY KEY,
        data            TEXT NOT NULL,
        cached_at       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cached_at ON cve_cache(cached_at);

    CREATE TABLE IF NOT EXISTS search_cache (
        cache_key       TEXT PRIMARY KEY,
        results         TEXT NOT NULL,
        cached_at       TEXT NOT NULL
    );
    """

    def __init__(self, db_path: str = CACHE_DB_PATH):
        self.db_path = db_path
        self._init()

    def _init(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executescript(self.SCHEMA)
        except Exception as e:
            logger.warning("Cache init failed: %s", e)

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=5)

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT data, cached_at FROM cve_cache WHERE cve_id = ?",
                    (cve_id,)
                ).fetchone()
            if not row:
                return None
            cached_at = datetime.fromisoformat(row[1])
            if datetime.utcnow() - cached_at > timedelta(hours=CACHE_TTL_HOURS):
                return None  # Expired
            return json.loads(row[0])
        except Exception:
            return None

    def set_cve(self, cve_id: str, data: Dict):
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at) VALUES (?, ?, ?)",
                    (cve_id, json.dumps(data), datetime.utcnow().isoformat())
                )
        except Exception as e:
            logger.debug("Cache write failed: %s", e)

    def get_search(self, key: str) -> Optional[List]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT results, cached_at FROM search_cache WHERE cache_key = ?",
                    (key,)
                ).fetchone()
            if not row:
                return None
            cached_at = datetime.fromisoformat(row[1])
            if datetime.utcnow() - cached_at > timedelta(hours=CACHE_TTL_HOURS):
                return None
            return json.loads(row[0])
        except Exception:
            return None

    def set_search(self, key: str, results: List):
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO search_cache (cache_key, results, cached_at) VALUES (?, ?, ?)",
                    (key, json.dumps(results), datetime.utcnow().isoformat())
                )
        except Exception as e:
            logger.debug("Cache write failed: %s", e)

    def purge_expired(self):
        """Remove entries older than TTL."""
        cutoff = (datetime.utcnow() - timedelta(hours=CACHE_TTL_HOURS)).isoformat()
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM cve_cache    WHERE cached_at < ?", (cutoff,))
                conn.execute("DELETE FROM search_cache WHERE cached_at < ?", (cutoff,))
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  NVD API client
# ─────────────────────────────────────────────────────────────────────────────

class NVDClient:
    """NVD API v2.0 client with rate limiting and full data extraction."""

    def __init__(self, api_key: str = NVD_API_KEY):
        self.api_key      = api_key or ""
        self._window_start = time.time()
        self._req_count    = 0
        self._cache        = _Cache()

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _rate_limit(self):
        now     = time.time()
        elapsed = now - self._window_start
        limit   = RATE_LIMIT_KEY if self.api_key else RATE_LIMIT_NO_KEY

        if elapsed >= RATE_WINDOW:
            self._window_start = now
            self._req_count    = 0

        if self._req_count >= limit:
            sleep_for = RATE_WINDOW - elapsed + 0.5
            if sleep_for > 0:
                logger.debug("NVD rate limit — sleeping %.1fs", sleep_for)
                time.sleep(sleep_for)
            self._window_start = time.time()
            self._req_count    = 0

        self._req_count += 1

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _get(self, params: Dict, retries: int = 2) -> Optional[Dict]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        self._rate_limit()

        for attempt in range(retries + 1):
            try:
                resp = requests.get(NVD_BASE_URL, params=params,
                                    headers=headers, timeout=30)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 403:
                    logger.error("NVD API key invalid or rate-limited (403)")
                    return None
                if resp.status_code == 429:
                    wait = 30 * (attempt + 1)
                    logger.warning("NVD 429 — waiting %ds", wait)
                    time.sleep(wait)
                    continue
                logger.warning("NVD HTTP %s", resp.status_code)
                return None
            except requests.Timeout:
                if attempt < retries:
                    time.sleep(5)
            except Exception as e:
                logger.error("NVD request error: %s", e)
                return None
        return None

    # ── CVE parsing ───────────────────────────────────────────────────────────

    def _parse_cve(self, cve_data: Dict) -> Dict:
        cve_id = cve_data.get("id", "")

        # ── Description ──
        description = next(
            (d["value"] for d in cve_data.get("descriptions", [])
             if d.get("lang") == "en"),
            ""
        )[:600]

        # ── CWE ──
        cwes = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-") and val not in cwes:
                    cwes.append(val)

        # ── CVSS metrics ──
        metrics = cve_data.get("metrics", {})
        cvss    = self._extract_cvss(metrics)

        # ── CISA KEV (Known Exploited) ──
        cisa_exploit_date = cve_data.get("cisaExploitAdd")
        cisa_required_by  = cve_data.get("cisaActionDue")
        cisa_description  = cve_data.get("cisaVulnerabilityName", "")
        is_kev            = bool(cisa_exploit_date)

        # ── References ──
        references = [
            {"url": r.get("url", ""), "tags": r.get("tags", [])}
            for r in cve_data.get("references", [])[:5]
        ]
        ref_urls = [r["url"] for r in references]

        # ── Dates ──
        published = cve_data.get("published", "")[:10]
        modified  = cve_data.get("lastModified", "")[:10]

        return {
            "id":                  cve_id,
            "description":         description,
            "published_date":      published,
            "modified_date":       modified,
            "cwes":                cwes,
            "references":          ref_urls,
            # CVSS
            "cvss_version":        cvss["version"],
            "cvss_score":          cvss["base_score"],
            "cvss_vector":         cvss["vector_string"],
            "severity":            cvss["severity"],
            "exploitability_score":cvss["exploitability_score"],
            "impact_score":        cvss["impact_score"],
            # CVSS vector components
            "attack_vector":       cvss["attack_vector"],
            "attack_complexity":   cvss["attack_complexity"],
            "privileges_required": cvss["privileges_required"],
            "user_interaction":    cvss["user_interaction"],
            "scope":               cvss["scope"],
            "confidentiality":     cvss["confidentiality"],
            "integrity":           cvss["integrity"],
            "availability":        cvss["availability"],
            # CISA KEV
            "is_kev":              is_kev,
            "cisa_exploit_date":   cisa_exploit_date,
            "cisa_required_by":    cisa_required_by,
            "cisa_description":    cisa_description,
            # EPSS filled separately
            "epss_score":          None,
            "epss_percentile":     None,
            "source":              "NVD",
        }

    def _extract_cvss(self, metrics: Dict) -> Dict:
        """Extract full CVSS details trying v3.1 → v3.0 → v2."""
        empty = {
            "version": None, "base_score": None, "vector_string": None,
            "severity": "UNKNOWN", "exploitability_score": None, "impact_score": None,
            "attack_vector": None, "attack_complexity": None,
            "privileges_required": None, "user_interaction": None,
            "scope": None, "confidentiality": None, "integrity": None, "availability": None,
        }

        for key, version in [("cvssMetricV31", "3.1"),
                              ("cvssMetricV30", "3.0"),
                              ("cvssMetricV2",  "2.0")]:
            entries = metrics.get(key, [])
            if not entries:
                continue
            entry     = entries[0]
            cvss_data = entry.get("cvssData", {})
            score     = cvss_data.get("baseScore")
            if not score:
                continue

            severity = entry.get("baseSeverity") or cvss_data.get("baseSeverity") or ""
            if not severity and score:
                severity = (
                    "CRITICAL" if score >= 9.0 else
                    "HIGH"     if score >= 7.0 else
                    "MEDIUM"   if score >= 4.0 else
                    "LOW"
                )

            return {
                "version":              version,
                "base_score":           score,
                "vector_string":        cvss_data.get("vectorString"),
                "severity":             severity.upper(),
                "exploitability_score": entry.get("exploitabilityScore"),
                "impact_score":         entry.get("impactScore"),
                "attack_vector":        cvss_data.get("attackVector"),
                "attack_complexity":    cvss_data.get("attackComplexity"),
                "privileges_required":  cvss_data.get("privilegesRequired"),
                "user_interaction":     cvss_data.get("userInteraction"),
                "scope":                cvss_data.get("scope"),
                "confidentiality":      cvss_data.get("confidentialityImpact"),
                "integrity":            cvss_data.get("integrityImpact"),
                "availability":         cvss_data.get("availabilityImpact"),
            }

        return empty

    # ── Public methods ────────────────────────────────────────────────────────

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch a single CVE by ID. Uses cache."""
        cached = self._cache.get_cve(cve_id)
        if cached:
            return cached

        data = self._get({"cveId": cve_id})
        if not data:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        result = self._parse_cve(vulns[0].get("cve", {}))
        self._cache.set_cve(cve_id, result)
        return result

    def search(self, keyword: str = None, cpe_name: str = None,
               severity: str = None, limit: int = 20,
               keyword_exact: bool = False) -> List[Dict]:
        """
        Search CVEs.

        Parameters
        ----------
        keyword      : free-text search (e.g. "nginx 1.18")
        cpe_name     : CPE v2.3 string (e.g. "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
        severity     : filter by severity (CRITICAL / HIGH / MEDIUM / LOW)
        limit        : max results (1–2000)
        keyword_exact: require all keywords to appear
        """
        cache_key = f"{keyword}|{cpe_name}|{severity}|{limit}|{keyword_exact}"
        cached    = self._cache.get_search(cache_key)
        if cached is not None:
            return cached

        params: Dict[str, Any] = {"resultsPerPage": min(limit, 2000)}
        if keyword:
            params["keywordSearch"] = keyword
            if keyword_exact:
                params["keywordExactMatch"] = ""
        if cpe_name:
            params["cpeName"] = cpe_name
        if severity:
            params["cvssV3Severity"] = severity.upper()

        data = self._get(params)
        if not data:
            return []

        results = [self._parse_cve(v.get("cve", {}))
                   for v in data.get("vulnerabilities", [])]
        self._cache.set_search(cache_key, results)
        return results

    def search_by_product(self, product: str, version: str = None,
                          limit: int = 15) -> List[Dict]:
        """Search CVEs for a specific product and optional version."""
        query = f"{product} {version}".strip() if version else product
        return self.search(keyword=query, limit=limit)

    def get_recent_critical(self, days: int = 30, limit: int = 20) -> List[Dict]:
        """Fetch recently published CRITICAL CVEs."""
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
        now   = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
        params = {
            "pubStartDate":  since,
            "pubEndDate":    now,
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": min(limit, 2000),
        }
        data = self._get(params)
        if not data:
            return []
        return [self._parse_cve(v.get("cve", {}))
                for v in data.get("vulnerabilities", [])]

    def enrich_with_cve_details(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch full details for a list of CVE IDs.
        Returns {cve_id: cve_dict}.
        """
        results = {}
        for cve_id in cve_ids:
            if not cve_id or not cve_id.upper().startswith("CVE-"):
                continue
            detail = self.get_cve(cve_id.upper())
            if detail:
                results[cve_id] = detail
            time.sleep(0.1)  # be polite
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  EPSS client (FIRST.org)
# ─────────────────────────────────────────────────────────────────────────────

class EPSSClient:
    """
    Exploit Prediction Scoring System — FIRST.org API.
    Returns probability (0–1) that a CVE will be exploited in the next 30 days.
    """

    def get_scores(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Fetch EPSS scores for a list of CVE IDs.
        Returns {cve_id: {"epss": float, "percentile": float}}.
        """
        if not cve_ids:
            return {}

        # API supports up to 100 CVEs per request
        results: Dict[str, Dict] = {}
        batch_size = 100

        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            try:
                resp = requests.get(
                    EPSS_BASE_URL,
                    params={"cve": ",".join(batch)},
                    timeout=15,
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
                for item in data.get("data", []):
                    cve = item.get("cve", "").upper()
                    results[cve] = {
                        "epss_score":      round(float(item.get("epss", 0)), 4),
                        "epss_percentile": round(float(item.get("percentile", 0)), 4),
                    }
            except Exception as e:
                logger.warning("EPSS fetch error: %s", e)

        return results

    def get_score(self, cve_id: str) -> Optional[Dict]:
        scores = self.get_scores([cve_id])
        return scores.get(cve_id.upper())


# ─────────────────────────────────────────────────────────────────────────────
#  Global singletons
# ─────────────────────────────────────────────────────────────────────────────

nvd_client  = NVDClient(api_key=NVD_API_KEY)
epss_client = EPSSClient()
_cache      = _Cache()


# ─────────────────────────────────────────────────────────────────────────────
#  Public API — used by the rest of the app
# ─────────────────────────────────────────────────────────────────────────────

def search_cves_with_nvd(product: str, version: str = None,
                         limit: int = 10) -> List[Dict]:
    """Search NVD for CVEs related to a product/version."""
    if not product:
        return []
    return nvd_client.search_by_product(product, version, limit=limit)


def get_cve_full(cve_id: str, include_epss: bool = True) -> Optional[Dict]:
    """
    Fetch a single CVE with all available data including EPSS.

    Returns a rich dict with:
      id, description, cwes, severity, cvss_score, cvss_vector,
      exploitability_score, impact_score, attack_vector, attack_complexity,
      privileges_required, user_interaction, scope,
      confidentiality/integrity/availability impact,
      is_kev (CISA known exploited), epss_score, epss_percentile,
      published_date, modified_date, references
    """
    cve = nvd_client.get_cve(cve_id)
    if not cve:
        return None

    if include_epss:
        epss = epss_client.get_score(cve_id)
        if epss:
            cve["epss_score"]      = epss["epss_score"]
            cve["epss_percentile"] = epss["epss_percentile"]

    return cve


def enrich_vulnerabilities_with_nvd(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Enrich a list of finding dicts with full NVD + EPSS data.
    Each finding must have at least an 'id' or 'cve' key containing a CVE ID.
    """
    enriched = []
    cve_ids  = []

    for vuln in vulnerabilities:
        cve_id = (vuln.get("id") or vuln.get("cve") or "").upper()
        if cve_id.startswith("CVE-"):
            cve_ids.append(cve_id)

    # Batch fetch EPSS scores
    epss_map = epss_client.get_scores(cve_ids) if cve_ids else {}

    for vuln in vulnerabilities:
        cve_id = (vuln.get("id") or vuln.get("cve") or "").upper()
        if not cve_id.startswith("CVE-"):
            enriched.append(vuln)
            continue

        detail = nvd_client.get_cve(cve_id)
        if detail:
            # Merge EPSS
            if cve_id in epss_map:
                detail["epss_score"]      = epss_map[cve_id]["epss_score"]
                detail["epss_percentile"] = epss_map[cve_id]["epss_percentile"]
            # Overlay on original finding (don't overwrite user data)
            merged = {**detail, **{k: v for k, v in vuln.items() if v}}
            enriched.append(merged)
        else:
            enriched.append(vuln)

    return enriched


def get_recent_critical_cves(days: int = 30, limit: int = 20) -> List[Dict]:
    """Fetch recently published CRITICAL CVEs from NVD."""
    return nvd_client.get_recent_critical(days=days, limit=limit)


def format_cve_summary(cve: Dict) -> str:
    """
    Return a one-line human-readable summary of a CVE.
    Example: CVE-2024-1234 [CRITICAL 9.8] AV:N/AC:L — RCE in OpenSSH ≤ 9.2
    """
    cve_id   = cve.get("id", "?")
    severity = cve.get("severity", "?")
    score    = cve.get("cvss_score") or "?"
    av       = cve.get("attack_vector", "?")[:1] if cve.get("attack_vector") else "?"
    ac       = cve.get("attack_complexity", "?")[:1] if cve.get("attack_complexity") else "?"
    desc     = (cve.get("description") or "")[:80]
    kev      = " 🔴KEV" if cve.get("is_kev") else ""
    epss_s   = cve.get("epss_score")
    epss_str = f" EPSS:{epss_s:.0%}" if epss_s is not None else ""
    return f"{cve_id} [{severity} {score}] AV:{av}/AC:{ac}{kev}{epss_str} — {desc}"


# ─────────────────────────────────────────────────────────────────────────────
#  Test / demo
# ─────────────────────────────────────────────────────────────────────────────

def test_nvd():
    """Quick integration test — run directly: python nvd_client.py"""
    print("=" * 60)
    print("VulniX NVD Integration Test")
    print(f"API key: {'✅ set' if NVD_API_KEY else '⚠️  not set (rate-limited)'}")
    print("=" * 60)

    # 1. Search by product
    print("\n[1] CVEs for 'openssh 8.9'")
    cves = search_cves_with_nvd("openssh", "8.9", limit=3)
    for c in cves:
        print(f"   {format_cve_summary(c)}")
        if c.get("cwes"):
            print(f"   CWE: {', '.join(c['cwes'])}")
        if c.get("is_kev"):
            print(f"   ⚠️  CISA KEV — exploited in the wild!")

    # 2. Full CVE details + EPSS
    print("\n[2] Full details for CVE-2023-38408 (OpenSSH RCE)")
    cve = get_cve_full("CVE-2023-38408")
    if cve:
        print(f"   Severity:        {cve['severity']} (CVSS {cve['cvss_score']})")
        print(f"   CVSS Vector:     {cve['cvss_vector']}")
        print(f"   Exploitability:  {cve['exploitability_score']}")
        print(f"   Impact score:    {cve['impact_score']}")
        print(f"   Attack vector:   {cve['attack_vector']}")
        print(f"   Privileges req:  {cve['privileges_required']}")
        print(f"   CWE:             {', '.join(cve['cwes'] or ['—'])}")
        print(f"   EPSS score:      {cve['epss_score']} ({cve['epss_percentile']:.0%} percentile)" if cve.get('epss_score') else "   EPSS:  —")
        print(f"   CISA KEV:        {'YES 🔴' if cve['is_kev'] else 'No'}")

    # 3. Recent critical CVEs
    print("\n[3] Recent CRITICAL CVEs (last 7 days)")
    recent = get_recent_critical_cves(days=7, limit=3)
    for c in recent:
        print(f"   {format_cve_summary(c)}")

    print("\n✅ Test complete")


if __name__ == "__main__":
    test_nvd()