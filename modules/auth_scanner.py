import socket

import requests
from requests.auth import HTTPBasicAuth

from modules.utils import resolve_host
from modules.web_scanner import normalize_url


AUTH_TYPE_LABELS = {
    "http_basic": "HTTP Basic",
    "ssh": "SSH",
}


def _base_result(auth_type, username, status, message, checks=None, inventory=None):
    return {
        "type": auth_type,
        "type_label": AUTH_TYPE_LABELS.get(auth_type, auth_type),
        "username": username,
        "status": status,
        "message": message,
        "checks": checks or [],
        "inventory": inventory or {},
    }


def _check(status, name, detail):
    return {
        "status": status,
        "name": name,
        "detail": detail,
    }


def _http_basic_scan(target, username, password):
    urls = normalize_url(target)

    if not urls:
        return _base_result(
            "http_basic",
            username,
            "failed",
            "No valid website URL was available for HTTP authentication.",
            [_check("failed", "HTTP target", "Target could not be normalized as a URL.")],
        )

    session = requests.Session()
    session.headers.update({"User-Agent": "Vulnix-AuthenticatedScanner/1.0"})
    errors = []

    for url in urls:
        try:
            anonymous = session.get(url, timeout=6, allow_redirects=True)
            authenticated = session.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=6,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
            continue

        challenge = anonymous.status_code in (401, 403) or bool(
            anonymous.headers.get("WWW-Authenticate")
        )

        if not challenge:
            return _base_result(
                "http_basic",
                username,
                "unavailable",
                "The target did not request HTTP Basic credentials.",
                [
                    _check(
                        "info",
                        "Anonymous HTTP access",
                        f"{anonymous.url} returned HTTP {anonymous.status_code} without an auth challenge.",
                    )
                ],
            )

        if authenticated.status_code not in (401, 403) and authenticated.status_code < 500:
            return _base_result(
                "http_basic",
                username,
                "success",
                "HTTP Basic credentials were accepted.",
                [
                    _check(
                        "success",
                        "HTTP Basic login",
                        f"{authenticated.url} returned HTTP {authenticated.status_code}.",
                    )
                ],
                {"authenticated_url": authenticated.url},
            )

        return _base_result(
            "http_basic",
            username,
            "failed",
            "HTTP Basic credentials were rejected.",
            [
                _check(
                    "failed",
                    "HTTP Basic login",
                    f"{authenticated.url} returned HTTP {authenticated.status_code}.",
                )
            ],
        )

    return _base_result(
        "http_basic",
        username,
        "failed",
        "Could not connect to the target for HTTP authentication.",
        [_check("failed", "HTTP connection", "; ".join(errors) or "Connection failed.")],
    )


def _ssh_scan(target, username, password):
    ip = resolve_host(target)

    if not ip:
        return _base_result(
            "ssh",
            username,
            "failed",
            "Invalid SSH target.",
            [_check("failed", "SSH target", "Target could not be resolved.")],
        )

    try:
        with socket.create_connection((ip, 22), timeout=4):
            pass
    except OSError as exc:
        return _base_result(
            "ssh",
            username,
            "unavailable",
            "SSH was not reachable on port 22.",
            [_check("failed", "SSH connection", str(exc))],
        )

    try:
        import paramiko
    except ImportError:
        return _base_result(
            "ssh",
            username,
            "unavailable",
            "SSH authenticated checks need the optional paramiko package.",
            [_check("failed", "SSH library", "paramiko is not installed.")],
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            ip,
            port=22,
            username=username,
            password=password,
            timeout=6,
            banner_timeout=6,
            auth_timeout=6,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException:
        return _base_result(
            "ssh",
            username,
            "failed",
            "SSH credentials were rejected.",
            [_check("failed", "SSH login", "Authentication failed.")],
        )
    except (paramiko.SSHException, OSError) as exc:
        return _base_result(
            "ssh",
            username,
            "failed",
            "SSH authentication could not be completed.",
            [_check("failed", "SSH login", str(exc))],
        )

    inventory = {}
    checks = [_check("success", "SSH login", "SSH credentials were accepted.")]

    for key, command in {
        "kernel": "uname -a",
        "user": "id -un",
    }.items():
        try:
            _, stdout, _ = client.exec_command(command, timeout=5)
            inventory[key] = stdout.read().decode(errors="ignore").strip()
        except (paramiko.SSHException, OSError):
            inventory[key] = ""

    client.close()

    return _base_result(
        "ssh",
        username,
        "success",
        "SSH authenticated checks completed.",
        checks,
        inventory,
    )


def run_authenticated_checks(target, auth_type, username, password):
    auth_type = (auth_type or "http_basic").strip()
    username = (username or "").strip()
    password = password or ""

    if not username or not password:
        return _base_result(
            auth_type,
            username,
            "failed",
            "Authenticated scan requires username and password.",
            [_check("failed", "Credentials", "Username or password is missing.")],
        )

    if auth_type == "ssh":
        return _ssh_scan(target, username, password)

    return _http_basic_scan(target, username, password)
