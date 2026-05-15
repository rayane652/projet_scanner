"""
NVD API v2 integration for VulniX.

This module owns all NVD-specific behavior: authenticated API requests,
SQLite caching, CVSS extraction, CPE/version matching, recency filtering,
and graceful fallback to cached results when the upstream API is unavailable.
"""

import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"

CACHE_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "cve_cache.db")
)
CACHE_TTL_HOURS = int(os.getenv("NVD_CACHE_TTL_HOURS", str(24 * 7)))
REQUEST_TIMEOUT = int(os.getenv("NVD_REQUEST_TIMEOUT", "20"))
MAX_RETRIES = int(os.getenv("NVD_MAX_RETRIES", "3"))

# NVD's public guidance is 50 requests/30s with a key and much lower without.
# The client keeps a small safety margin so scans do not trip rate limits.
RATE_WINDOW_SECONDS = 30
RATE_LIMIT_WITH_KEY = 45
RATE_LIMIT_WITHOUT_KEY = 4

MIN_MODERN_YEAR = 2018
MAX_PRODUCT_RESULTS = 2000

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "NONE": 4,
    "UNKNOWN": 5,
}


PRODUCT_CPE_ALIASES: Dict[str, List[Dict[str, str]]] = {
    "apache": [{"part": "a", "vendor": "apache", "product": "http_server", "name": "Apache HTTP Server"}],
    "apache http server": [{"part": "a", "vendor": "apache", "product": "http_server", "name": "Apache HTTP Server"}],
    "httpd": [{"part": "a", "vendor": "apache", "product": "http_server", "name": "Apache HTTP Server"}],
    "apache tomcat": [{"part": "a", "vendor": "apache", "product": "tomcat", "name": "Apache Tomcat"}],
    "tomcat": [{"part": "a", "vendor": "apache", "product": "tomcat", "name": "Apache Tomcat"}],
    "nginx": [{"part": "a", "vendor": "nginx", "product": "nginx", "name": "nginx"}],
    "openssh": [{"part": "a", "vendor": "openbsd", "product": "openssh", "name": "OpenSSH"}],
    "ssh": [{"part": "a", "vendor": "openbsd", "product": "openssh", "name": "OpenSSH"}],
    "mysql": [
        {"part": "a", "vendor": "oracle", "product": "mysql", "name": "MySQL"},
        {"part": "a", "vendor": "oracle", "product": "mysql_server", "name": "MySQL Server"},
    ],
    "mysql server": [{"part": "a", "vendor": "oracle", "product": "mysql_server", "name": "MySQL Server"}],
    "mariadb": [{"part": "a", "vendor": "mariadb", "product": "mariadb", "name": "MariaDB"}],
    "php": [{"part": "a", "vendor": "php", "product": "php", "name": "PHP"}],
    "postgresql": [{"part": "a", "vendor": "postgresql", "product": "postgresql", "name": "PostgreSQL"}],
    "postgres": [{"part": "a", "vendor": "postgresql", "product": "postgresql", "name": "PostgreSQL"}],
    "redis": [{"part": "a", "vendor": "redis", "product": "redis", "name": "Redis"}],
    "mongodb": [{"part": "a", "vendor": "mongodb", "product": "mongodb", "name": "MongoDB"}],
    "elasticsearch": [{"part": "a", "vendor": "elastic", "product": "elasticsearch", "name": "Elasticsearch"}],
    "microsoft iis": [{"part": "a", "vendor": "microsoft", "product": "internet_information_services", "name": "Microsoft IIS"}],
    "iis": [{"part": "a", "vendor": "microsoft", "product": "internet_information_services", "name": "Microsoft IIS"}],
    "bind": [{"part": "a", "vendor": "isc", "product": "bind", "name": "BIND"}],
    "postfix": [{"part": "a", "vendor": "postfix", "product": "postfix", "name": "Postfix"}],
    "exim": [{"part": "a", "vendor": "exim", "product": "exim", "name": "Exim"}],
    "proftpd": [{"part": "a", "vendor": "proftpd", "product": "proftpd", "name": "ProFTPD"}],
    "vsftpd": [{"part": "a", "vendor": "vsftpd_project", "product": "vsftpd", "name": "vsftpd"}],
}


class _Cache:
    """Small SQLite cache used for both individual CVEs and search results."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        cached_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS search_cache (
        cache_key TEXT PRIMARY KEY,
        results TEXT NOT NULL,
        cached_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cve_cached_at ON cve_cache(cached_at);
    CREATE INDEX IF NOT EXISTS idx_search_cached_at ON search_cache(cached_at);
    """

    def __init__(self, db_path: str = CACHE_DB_PATH):
        self.db_path = db_path
        self._init()

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def _init(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(self.SCHEMA)
        except Exception as exc:
            logger.warning("NVD cache initialization failed: %s", exc)

    def _is_fresh(self, cached_at: str) -> bool:
        try:
            age = datetime.utcnow() - datetime.fromisoformat(cached_at)
        except ValueError:
            return False
        return age <= timedelta(hours=CACHE_TTL_HOURS)

    def get_cve(self, cve_id: str, allow_expired: bool = False) -> Optional[Dict]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT data, cached_at FROM cve_cache WHERE cve_id = ?",
                    (cve_id.upper(),),
                ).fetchone()
            if not row:
                return None
            if not allow_expired and not self._is_fresh(row[1]):
                return None
            return json.loads(row[0])
        except Exception:
            return None

    def set_cve(self, cve_id: str, data: Dict) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at) VALUES (?, ?, ?)",
                    (cve_id.upper(), json.dumps(data), datetime.utcnow().isoformat()),
                )
        except Exception as exc:
            logger.debug("NVD CVE cache write failed: %s", exc)

    def get_search(self, key: str, allow_expired: bool = False) -> Optional[List[Dict]]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT results, cached_at FROM search_cache WHERE cache_key = ?",
                    (key,),
                ).fetchone()
            if not row:
                return None
            if not allow_expired and not self._is_fresh(row[1]):
                return None
            return json.loads(row[0])
        except Exception:
            return None

    def set_search(self, key: str, results: List[Dict]) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO search_cache (cache_key, results, cached_at) VALUES (?, ?, ?)",
                    (key, json.dumps(results), datetime.utcnow().isoformat()),
                )
        except Exception as exc:
            logger.debug("NVD search cache write failed: %s", exc)

    def purge_expired(self) -> None:
        cutoff = (datetime.utcnow() - timedelta(hours=CACHE_TTL_HOURS * 4)).isoformat()
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM cve_cache WHERE cached_at < ?", (cutoff,))
                conn.execute("DELETE FROM search_cache WHERE cached_at < ?", (cutoff,))
        except Exception:
            pass


def _clean_product(product: str) -> str:
    value = (product or "").lower().strip()
    value = value.replace("server:", "").replace("_", " ")
    value = re.sub(r"\s+", " ", value)
    value = re.sub(r"[^a-z0-9.+\- ]", "", value)
    return value.strip()


def _clean_version(version: Optional[str]) -> str:
    if not version:
        return ""
    text = str(version).strip()
    match = re.search(r"\d+(?:\.\d+){0,5}(?:[a-z]\d*)?", text, re.IGNORECASE)
    return match.group(0) if match else text.strip(" /;,_-()[]")


def _norm_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def _cpe_value(value: str) -> str:
    value = (value or "*").lower().strip().replace(" ", "_")
    return re.sub(r"[^a-z0-9._+\-]", "_", value) or "*"


def _version_tokens(version: str) -> List[Any]:
    tokens: List[Any] = []
    for token in re.split(r"[.\-_:~+]", (version or "").lower()):
        if token == "":
            continue
        parts = re.findall(r"\d+|[a-z]+", token)
        for part in parts:
            tokens.append(int(part) if part.isdigit() else part)
    return tokens


def _compare_versions(left: str, right: str) -> int:
    a = _version_tokens(left)
    b = _version_tokens(right)
    max_len = max(len(a), len(b))
    for index in range(max_len):
        av = a[index] if index < len(a) else 0
        bv = b[index] if index < len(b) else 0
        if av == bv:
            continue
        if isinstance(av, int) and isinstance(bv, str):
            return 1
        if isinstance(av, str) and isinstance(bv, int):
            return -1
        return 1 if av > bv else -1
    return 0


def _date_value(value: str) -> float:
    if not value:
        return 0
    try:
        return datetime.fromisoformat(value[:19]).timestamp()
    except ValueError:
        return 0


def _published_year(cve: Dict) -> int:
    value = cve.get("published_date") or cve.get("published") or ""
    try:
        return int(str(value)[:4])
    except (TypeError, ValueError):
        return 0


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _cache_key(prefix: str, payload: Dict[str, Any]) -> str:
    return prefix + ":" + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _parse_cpe23(criteria: str) -> Dict[str, str]:
    parts = (criteria or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return {}
    return {
        "criteria": criteria,
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
    }


def _version_range_label(match: Dict) -> str:
    version = match.get("version")
    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    if version and version not in ("*", "-"):
        return version
    if start or end:
        pieces = []
        if start:
            mode = "including" if match.get("versionStartIncluding") else "excluding"
            pieces.append(f">= {start}" if mode == "including" else f"> {start}")
        if end:
            mode = "including" if match.get("versionEndIncluding") else "excluding"
            pieces.append(f"<= {end}" if mode == "including" else f"< {end}")
        return ", ".join(pieces)
    return "all listed versions"


def _format_iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class NVDClient:
    """Official NVD CVE API v2 client with caching and version-aware filtering."""

    def __init__(self, api_key: str = NVD_API_KEY, cache: Optional[_Cache] = None):
        self.api_key = (api_key or "").strip()
        self._cache = cache or _Cache()
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "VulniX vulnerability scanner"})
        self._window_started = time.monotonic()
        self._request_count = 0
        self._cache.purge_expired()

    def _rate_limit(self) -> None:
        limit = RATE_LIMIT_WITH_KEY if self.api_key else RATE_LIMIT_WITHOUT_KEY
        now = time.monotonic()
        elapsed = now - self._window_started
        if elapsed >= RATE_WINDOW_SECONDS:
            self._window_started = now
            self._request_count = 0
            return
        if self._request_count >= limit:
            time.sleep(max(0.5, RATE_WINDOW_SECONDS - elapsed + 0.25))
            self._window_started = time.monotonic()
            self._request_count = 0
        self._request_count += 1

    def _request(self, params: Dict[str, Any]) -> Optional[Dict]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        last_error = ""

        for attempt in range(1, MAX_RETRIES + 1):
            self._rate_limit()
            try:
                response = self._session.get(
                    NVD_BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.Timeout:
                last_error = "timeout"
                logger.warning("NVD request timed out on attempt %s/%s", attempt, MAX_RETRIES)
                time.sleep(min(2 ** attempt, 12))
                continue
            except requests.RequestException as exc:
                last_error = str(exc)
                logger.warning("NVD request failed on attempt %s/%s: %s", attempt, MAX_RETRIES, exc)
                time.sleep(min(2 ** attempt, 12))
                continue

            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    logger.warning("NVD returned non-JSON response")
                    return None

            nvd_message = response.headers.get("message", "")
            if response.status_code in (429, 500, 502, 503, 504):
                retry_after = response.headers.get("Retry-After")
                try:
                    wait = int(retry_after) if retry_after else min(2 ** attempt * 2, 30)
                except ValueError:
                    wait = min(2 ** attempt * 2, 30)
                logger.warning(
                    "NVD HTTP %s; retrying in %ss. %s",
                    response.status_code,
                    wait,
                    nvd_message,
                )
                time.sleep(wait)
                continue

            if response.status_code == 403:
                logger.error("NVD rejected the request. Check NVD_API_KEY in .env. %s", nvd_message)
                return None

            logger.warning("NVD HTTP %s for params %s. %s", response.status_code, params, nvd_message)
            return None

        logger.warning("NVD request exhausted retries: %s", last_error)
        return None

    def _extract_cvss(self, metrics: Dict) -> Dict:
        empty = {
            "version": None,
            "base_score": None,
            "vector_string": None,
            "severity": "UNKNOWN",
            "exploitability_score": None,
            "impact_score": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality": None,
            "integrity": None,
            "availability": None,
        }
        metric_order = [
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ]
        for key, version in metric_order:
            entries = metrics.get(key) or []
            if not entries:
                continue
            entry = entries[0]
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            severity = (
                entry.get("baseSeverity")
                or data.get("baseSeverity")
                or _severity_from_score(score)
            )
            return {
                "version": version,
                "base_score": score,
                "vector_string": data.get("vectorString"),
                "severity": (severity or "UNKNOWN").upper(),
                "exploitability_score": entry.get("exploitabilityScore"),
                "impact_score": entry.get("impactScore"),
                "attack_vector": data.get("attackVector") or data.get("accessVector"),
                "attack_complexity": data.get("attackComplexity") or data.get("accessComplexity"),
                "privileges_required": data.get("privilegesRequired") or data.get("authentication"),
                "user_interaction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "confidentiality": data.get("confidentialityImpact"),
                "integrity": data.get("integrityImpact"),
                "availability": data.get("availabilityImpact"),
            }
        return empty

    def _collect_cpe_matches(self, configurations: Iterable[Dict]) -> List[Dict]:
        matches: List[Dict] = []

        def walk_node(node: Dict) -> None:
            for item in node.get("cpeMatch") or []:
                parsed = _parse_cpe23(item.get("criteria", ""))
                if not parsed:
                    continue
                parsed.update({
                    "vulnerable": bool(item.get("vulnerable")),
                    "versionStartIncluding": item.get("versionStartIncluding"),
                    "versionStartExcluding": item.get("versionStartExcluding"),
                    "versionEndIncluding": item.get("versionEndIncluding"),
                    "versionEndExcluding": item.get("versionEndExcluding"),
                })
                matches.append(parsed)
            for child in node.get("children") or []:
                walk_node(child)

        for config in configurations or []:
            for node in config.get("nodes") or []:
                walk_node(node)
        return matches

    def _parse_cve(self, cve_data: Dict) -> Dict:
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        cwes: List[str] = []
        for weakness in cve_data.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                value = desc.get("value", "")
                if value.startswith("CWE-") and value not in cwes:
                    cwes.append(value)

        cvss = self._extract_cvss(cve_data.get("metrics") or {})
        references = [
            ref.get("url", "")
            for ref in (cve_data.get("references") or [])[:10]
            if ref.get("url")
        ]
        cpe_matches = self._collect_cpe_matches(cve_data.get("configurations") or [])
        affected_versions = sorted(
            {_version_range_label(match) for match in cpe_matches if match.get("vulnerable")}
        )
        published = (cve_data.get("published") or "")[:10]
        modified = (cve_data.get("lastModified") or "")[:10]
        status = cve_data.get("vulnStatus") or ""

        return {
            "id": cve_id,
            "cve": cve_id,
            "description": description[:900],
            "published": cve_data.get("published") or "",
            "published_date": published,
            "modified_date": modified,
            "vuln_status": status,
            "cwes": cwes,
            "references": references,
            "affected_versions": affected_versions[:20],
            "affected_cpes": cpe_matches[:80],
            "cvss_version": cvss["version"],
            "cvss_score": cvss["base_score"],
            "score": cvss["base_score"],
            "cvss_vector": cvss["vector_string"],
            "severity": cvss["severity"],
            "exploitability_score": cvss["exploitability_score"],
            "impact_score": cvss["impact_score"],
            "attack_vector": cvss["attack_vector"],
            "attack_complexity": cvss["attack_complexity"],
            "privileges_required": cvss["privileges_required"],
            "user_interaction": cvss["user_interaction"],
            "scope": cvss["scope"],
            "confidentiality": cvss["confidentiality"],
            "integrity": cvss["integrity"],
            "availability": cvss["availability"],
            "is_kev": bool(cve_data.get("cisaExploitAdd")),
            "cisa_exploit_date": cve_data.get("cisaExploitAdd"),
            "cisa_required_by": cve_data.get("cisaActionDue"),
            "cisa_description": cve_data.get("cisaVulnerabilityName") or "",
            "epss_score": None,
            "epss_percentile": None,
            "source": "NVD",
            "data_source": "NVD API v2.0",
            "confidence": "medium",
            "confidence_score": 50,
            "match_reason": "NVD result",
        }

    def _is_rejected(self, cve: Dict) -> bool:
        status = (cve.get("vuln_status") or "").lower()
        description = (cve.get("description") or "").lower()
        return "reject" in status or description.startswith("** reject **")

    def _candidate_cpes(self, product: str) -> List[Dict[str, str]]:
        product_key = _clean_product(product)
        candidates = list(PRODUCT_CPE_ALIASES.get(product_key, []))
        if candidates:
            return candidates

        product_cpe = _cpe_value(product_key)
        return [{
            "part": "a",
            "vendor": product_cpe,
            "product": product_cpe,
            "name": product_key,
        }]

    def _virtual_match(self, candidate: Dict[str, str], version: str = "*") -> str:
        return (
            f"cpe:2.3:{candidate.get('part', 'a')}:"
            f"{_cpe_value(candidate.get('vendor'))}:"
            f"{_cpe_value(candidate.get('product'))}:"
            f"{_cpe_value(version or '*')}:*:*:*:*:*:*:*"
        )

    def _match_product_cpes(self, cve: Dict, candidate: Dict[str, str]) -> List[Dict]:
        vendor = _norm_token(candidate.get("vendor", ""))
        product = _norm_token(candidate.get("product", ""))
        hits = []
        for match in cve.get("affected_cpes") or []:
            if not match.get("vulnerable"):
                continue
            if match.get("part") != candidate.get("part", "a"):
                continue
            if _norm_token(match.get("vendor", "")) == vendor and _norm_token(match.get("product", "")) == product:
                hits.append(match)
        return hits

    def _version_status(self, match: Dict, detected_version: str) -> Tuple[bool, str]:
        version = _clean_version(detected_version)
        if not version:
            return True, "product CPE match"

        cpe_version = match.get("version") or ""
        if cpe_version not in ("", "*", "-"):
            if _compare_versions(version, cpe_version) == 0:
                return True, "exact affected CPE version"
            return False, "different fixed CPE version"

        start_inc = match.get("versionStartIncluding")
        start_exc = match.get("versionStartExcluding")
        end_inc = match.get("versionEndIncluding")
        end_exc = match.get("versionEndExcluding")

        if start_inc and _compare_versions(version, start_inc) < 0:
            return False, "below affected version range"
        if start_exc and _compare_versions(version, start_exc) <= 0:
            return False, "below affected version range"
        if end_inc and _compare_versions(version, end_inc) > 0:
            return False, "above affected version range"
        if end_exc and _compare_versions(version, end_exc) >= 0:
            return False, "above affected version range"
        if start_inc or start_exc or end_inc or end_exc:
            return True, "inside affected CPE version range"

        return True, "product CPE match without explicit NVD version range"

    def _annotate_candidate_match(
        self,
        cve: Dict,
        product: str,
        version: str,
        candidate: Optional[Dict[str, str]] = None,
        keyword_fallback: bool = False,
    ) -> Optional[Dict]:
        cve = dict(cve)
        description = (cve.get("description") or "").lower()
        product_key = _clean_product(product)
        version_key = _clean_version(version)

        if candidate:
            product_hits = self._match_product_cpes(cve, candidate)
            if product_hits:
                affected = sorted({_version_range_label(match) for match in product_hits})
                cve["affected_versions"] = affected or cve.get("affected_versions") or []
                cve["matched_product"] = candidate.get("name") or product_key
                cve["matched_vendor"] = candidate.get("vendor")

                if not version_key:
                    cve["confidence"] = "high"
                    cve["confidence_score"] = 86
                    cve["match_reason"] = "exact product CPE match"
                    return cve

                statuses = [self._version_status(match, version_key) for match in product_hits]
                accepted = [reason for ok, reason in statuses if ok]
                if accepted:
                    reason = accepted[0]
                    cve["matched_version"] = version_key
                    cve["match_reason"] = reason
                    cve["confidence"] = "high" if "exact" in reason or "range" in reason else "medium"
                    cve["confidence_score"] = 96 if cve["confidence"] == "high" else 76
                    return cve

                if version_key and version_key.lower() in description:
                    cve["matched_version"] = version_key
                    cve["confidence"] = "medium"
                    cve["confidence_score"] = 68
                    cve["match_reason"] = "product CPE match and version mentioned in description"
                    return cve
                return None

        if keyword_fallback:
            product_tokens = [_clean_product(product_key), product_key.replace(" ", "_")]
            has_product = any(token and token in description for token in product_tokens)
            has_version = not version_key or version_key.lower() in description
            if has_product and has_version:
                cve["matched_product"] = product_key
                cve["matched_version"] = version_key
                cve["confidence"] = "medium" if version_key else "low"
                cve["confidence_score"] = 64 if version_key else 45
                cve["match_reason"] = "keyword fallback with product/version evidence"
                return cve

        return None

    def _dedupe_sort(self, results: Iterable[Dict], limit: int) -> List[Dict]:
        unique: Dict[str, Dict] = {}
        for cve in results:
            cve_id = (cve.get("id") or cve.get("cve") or "").upper()
            if not cve_id or self._is_rejected(cve):
                continue
            existing = unique.get(cve_id)
            if not existing or cve.get("confidence_score", 0) > existing.get("confidence_score", 0):
                unique[cve_id] = cve

        ordered = sorted(
            unique.values(),
            key=lambda item: (
                _date_value(item.get("published") or item.get("published_date") or ""),
                item.get("confidence_score", 0),
                -SEVERITY_ORDER.get((item.get("severity") or "UNKNOWN").upper(), 5),
            ),
            reverse=True,
        )
        modern = [item for item in ordered if _published_year(item) >= MIN_MODERN_YEAR]
        selected = modern if modern else ordered
        return selected[:limit]

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        cve_id = (cve_id or "").upper().strip()
        if not cve_id.startswith("CVE-"):
            return None

        cached = self._cache.get_cve(cve_id)
        if cached:
            return cached

        data = self._request({"cveId": cve_id, "noRejected": ""})
        if not data:
            return self._cache.get_cve(cve_id, allow_expired=True)

        vulnerabilities = data.get("vulnerabilities") or []
        if not vulnerabilities:
            return None

        parsed = self._parse_cve(vulnerabilities[0].get("cve") or {})
        self._cache.set_cve(cve_id, parsed)
        return parsed

    def search(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        virtual_match: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 20,
        keyword_exact: bool = False,
        pub_start: Optional[datetime] = None,
        pub_end: Optional[datetime] = None,
    ) -> List[Dict]:
        params: Dict[str, Any] = {
            "resultsPerPage": min(max(int(limit or 20), 1), MAX_PRODUCT_RESULTS),
            "noRejected": "",
        }
        if keyword:
            params["keywordSearch"] = keyword
            if keyword_exact and " " in keyword.strip():
                params["keywordExactMatch"] = ""
        if cpe_name:
            params["cpeName"] = cpe_name
        if virtual_match:
            params["virtualMatchString"] = virtual_match
        if severity:
            params["cvssV3Severity"] = severity.upper()
        if pub_start and pub_end:
            params["pubStartDate"] = _format_iso_z(pub_start)
            params["pubEndDate"] = _format_iso_z(pub_end)

        key = _cache_key("search", params)
        cached = self._cache.get_search(key)
        if cached is not None:
            return cached

        data = self._request(params)
        if not data:
            stale = self._cache.get_search(key, allow_expired=True)
            return stale or []

        parsed = [
            self._parse_cve(item.get("cve") or {})
            for item in data.get("vulnerabilities") or []
        ]
        parsed = self._dedupe_sort(parsed, limit=params["resultsPerPage"])
        self._cache.set_search(key, parsed)
        return parsed

    def search_by_product(self, product: str, version: Optional[str] = None, limit: int = 10) -> List[Dict]:
        product_key = _clean_product(product)
        version_key = _clean_version(version)
        if not product_key:
            return []

        request_key = _cache_key(
            "product",
            {"product": product_key, "version": version_key, "limit": limit},
        )
        cached = self._cache.get_search(request_key)
        if cached is not None:
            return cached

        candidates = self._candidate_cpes(product_key)
        matches: List[Dict] = []

        for candidate in candidates:
            # First ask NVD for the detected product/version CPE. Then query the
            # product CPE and apply our own version-range checks from configurations.
            virtual_queries = []
            if version_key:
                virtual_queries.append(self._virtual_match(candidate, version_key))
            virtual_queries.append(self._virtual_match(candidate, "*"))

            for virtual_query in dict.fromkeys(virtual_queries):
                cves = self.search(virtual_match=virtual_query, limit=MAX_PRODUCT_RESULTS)
                for cve in cves:
                    annotated = self._annotate_candidate_match(cve, product_key, version_key, candidate)
                    if annotated:
                        matches.append(annotated)

        # Keyword search is only a fallback. It is exact for phrases and must pass
        # product/version evidence checks before the result is displayed.
        if len(matches) < limit:
            keyword = f"{product_key} {version_key}".strip()
            fallback_results = self.search(
                keyword=keyword,
                limit=100,
                keyword_exact=bool(version_key),
            )
            for cve in fallback_results:
                annotated = self._annotate_candidate_match(
                    cve,
                    product_key,
                    version_key,
                    keyword_fallback=True,
                )
                if annotated:
                    matches.append(annotated)

        selected = self._dedupe_sort(matches, limit=limit)
        self._cache.set_search(request_key, selected)
        return selected

    def get_recent_critical(self, days: int = 30, limit: int = 20) -> List[Dict]:
        days = min(max(int(days or 30), 1), 120)
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        return self.search(
            severity="CRITICAL",
            limit=limit,
            pub_start=start,
            pub_end=end,
        )

    def enrich_with_cve_details(self, cve_ids: List[str]) -> Dict[str, Dict]:
        details = {}
        for cve_id in cve_ids:
            detail = self.get_cve(cve_id)
            if detail:
                details[(detail.get("id") or cve_id).upper()] = detail
        return details


class EPSSClient:
    """Small FIRST EPSS client used to add exploitation probability."""

    def get_scores(self, cve_ids: List[str]) -> Dict[str, Dict]:
        clean_ids = sorted({(cve_id or "").upper() for cve_id in cve_ids if cve_id})
        if not clean_ids:
            return {}

        scores: Dict[str, Dict] = {}
        for index in range(0, len(clean_ids), 100):
            batch = clean_ids[index:index + 100]
            try:
                response = requests.get(
                    EPSS_BASE_URL,
                    params={"cve": ",".join(batch)},
                    timeout=15,
                )
                if response.status_code != 200:
                    continue
                for item in response.json().get("data") or []:
                    cve_id = (item.get("cve") or "").upper()
                    scores[cve_id] = {
                        "epss_score": round(float(item.get("epss") or 0), 4),
                        "epss_percentile": round(float(item.get("percentile") or 0), 4),
                    }
            except Exception as exc:
                logger.debug("EPSS lookup failed: %s", exc)
        return scores

    def get_score(self, cve_id: str) -> Optional[Dict]:
        return self.get_scores([cve_id]).get((cve_id or "").upper())


nvd_client = NVDClient(api_key=NVD_API_KEY)
epss_client = EPSSClient()


def search_cves_with_nvd(product: str, version: Optional[str] = None, limit: int = 10) -> List[Dict]:
    """Compatibility wrapper used by scanner modules."""
    return nvd_client.search_by_product(product, version, limit=limit)


def get_cve_full(cve_id: str, include_epss: bool = True) -> Optional[Dict]:
    cve = nvd_client.get_cve(cve_id)
    if not cve:
        return None
    if include_epss:
        epss = epss_client.get_score(cve_id)
        if epss:
            cve = dict(cve)
            cve.update(epss)
    return cve


def enrich_vulnerabilities_with_nvd(vulnerabilities: List[Dict]) -> List[Dict]:
    cve_ids = [
        (item.get("id") or item.get("cve") or "").upper()
        for item in vulnerabilities or []
    ]
    cve_ids = [cve_id for cve_id in cve_ids if cve_id.startswith("CVE-")]
    epss_map = epss_client.get_scores(cve_ids)
    details = nvd_client.enrich_with_cve_details(cve_ids)

    enriched = []
    for item in vulnerabilities or []:
        cve_id = (item.get("id") or item.get("cve") or "").upper()
        detail = details.get(cve_id)
        if detail:
            merged = {**detail, **{k: v for k, v in item.items() if v not in (None, "", [])}}
            if cve_id in epss_map:
                merged.update(epss_map[cve_id])
            enriched.append(merged)
        else:
            enriched.append(item)
    return enriched


def get_recent_critical_cves(days: int = 30, limit: int = 20) -> List[Dict]:
    return nvd_client.get_recent_critical(days=days, limit=limit)


def format_cve_summary(cve: Dict) -> str:
    cve_id = cve.get("id") or cve.get("cve") or "CVE"
    severity = cve.get("severity") or "UNKNOWN"
    score = cve.get("cvss_score") or cve.get("score") or "?"
    published = cve.get("published_date") or "unknown date"
    affected = ", ".join((cve.get("affected_versions") or [])[:2]) or "affected versions unknown"
    return f"{cve_id} [{severity} {score}] published {published}; affected: {affected}"


if __name__ == "__main__":
    for item in search_cves_with_nvd("nginx", "1.18.0", limit=5):
        print(format_cve_summary(item))