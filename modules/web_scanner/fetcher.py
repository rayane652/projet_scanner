import logging
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

MAX_RETRIES = 2
RETRY_DELAY = 0.5
REQUEST_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def create_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    s.max_redirects = 10
    return s


def fetch(method, url, session=None, **kwargs):
    close = False
    if session is None:
        session = create_session()
        close = True
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            r = session.request(method, url, **kwargs)
            return r
        except (requests.ConnectionError, requests.Timeout, requests.RequestException) as e:
            last_exc = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
    if close:
        session.close()
    if last_exc:
        raise last_exc
    return None


def fetch_first(target, session):
    errors = []
    for url in normalize_url(target):
        try:
            r = fetch("GET", url, session, allow_redirects=True)
            return url, r, errors
        except requests.RequestException as e:
            errors.append(f"{url}: {e}")
    return "", None, errors


def normalize_url(target):
    target = (target or "").strip()
    if not target:
        return []
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return [target]
    clean = target.lstrip("/")
    return [f"https://{clean}", f"http://{clean}"]
