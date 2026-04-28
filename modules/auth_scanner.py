import socket

import requests
from requests.auth import HTTPBasicAuth

from modules.utils import resolve_host
from modules.web_scanner import normalize_url


AUTH_TYPE_LABELS = {
    "http_basic": "HTTP Basic",
    "ssh": "SSH",
}

COMMON_AUTH_PATHS = [
    "/",
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/server-status",
    "/api",
]

SSH_UPDATE_COMMAND = (
    "if command -v apt >/dev/null 2>&1; then "
    "apt list --upgradable 2>/dev/null | sed -n '2,21p'; "
    "elif command -v dnf >/dev/null 2>&1; then "
    "dnf -q check-update 2>/dev/null | sed -n '1,20p'; "
    "elif command -v yum >/dev/null 2>&1; then "
    "yum -q check-update 2>/dev/null | sed -n '1,20p'; "
    "elif command -v zypper >/dev/null 2>&1; then "
    "zypper --non-interactive list-updates 2>/dev/null | sed -n '1,20p'; "
    "else true; fi"
)


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


def _run_ssh_command(client, command, timeout=5):
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="ignore").strip()
    except Exception:
        return ""


def _non_empty_lines(value, limit=20):
    return [line.strip() for line in (value or "").splitlines() if line.strip()][:limit]


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
            checks = [
                _check(
                    "success",
                    "HTTP Basic login",
                    f"{authenticated.url} returned HTTP {authenticated.status_code}.",
                )
            ]
            inventory = {
                "authenticated_url": authenticated.url,
                "status_code": authenticated.status_code,
            }

            protected_paths = []
            exposed_paths = []
            errors = []

            for path in COMMON_AUTH_PATHS:
                path_url = authenticated.url.rstrip("/") + path
                try:
                    anon_resp = session.get(path_url, timeout=5, allow_redirects=True)
                    auth_resp = session.get(
                        path_url,
                        auth=HTTPBasicAuth(username, password),
                        timeout=5,
                        allow_redirects=True,
                    )
                except requests.RequestException as exc:
                    errors.append(f"{path}: {exc}")
                    continue

                if anon_resp.status_code in (401, 403) and auth_resp.status_code < 400:
                    protected_paths.append(f"{path} -> {auth_resp.status_code}")
                elif anon_resp.status_code < 400 and auth_resp.status_code < 400:
                    exposed_paths.append(f"{path} -> public")

            if protected_paths:
                checks.append(_check(
                    "success",
                    "Credentialed web paths",
                    f"{len(protected_paths)} protected path(s) became accessible with credentials.",
                ))
                inventory["protected_paths"] = protected_paths
            else:
                checks.append(_check(
                    "info",
                    "Credentialed web paths",
                    "No additional protected paths were confirmed with the provided credentials.",
                ))

            if exposed_paths:
                inventory["public_paths"] = exposed_paths[:10]
                checks.append(_check(
                    "info",
                    "Public web paths",
                    f"{len(exposed_paths)} scanned paths were already publicly accessible.",
                ))

            auth_header = authenticated.headers.get("Server")
            if auth_header:
                inventory["server"] = auth_header

            set_cookie = authenticated.headers.get("Set-Cookie")
            if set_cookie:
                inventory["cookie_flags"] = set_cookie[:200]
                checks.append(_check(
                    "info",
                    "Session cookie observed",
                    "Authenticated response returned session cookies.",
                ))

            if errors:
                inventory["path_errors"] = errors[:8]

            return _base_result(
                "http_basic",
                username,
                "success",
                "HTTP Basic credentials were accepted.",
                checks,
                inventory,
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
        "os": "cat /etc/os-release 2>/dev/null | head -n 3",
        "hostname": "hostname 2>/dev/null",
        "uptime": "uptime -p 2>/dev/null",
        "sudo_rights": "sudo -n -l 2>/dev/null | head -n 20",
        "listening_services": "ss -tuln 2>/dev/null | head -n 25",
        "local_users": "cut -d: -f1 /etc/passwd 2>/dev/null | head -n 20",
        "world_writable": "find /etc /var/www /opt -xdev -type f -perm -0002 2>/dev/null | head -n 20",
    }.items():
        inventory[key] = _run_ssh_command(client, command)

    package_updates = [
        line.strip()
        for line in _run_ssh_command(client, SSH_UPDATE_COMMAND, timeout=8).splitlines()
        if line.strip()
    ][:20]

    if package_updates:
        inventory["package_updates"] = package_updates
        checks.append(_check(
            "info",
            "Package updates found",
            f"{len(package_updates)} package update(s) were reported by the target.",
        ))
    else:
        checks.append(_check(
            "info",
            "Package update check",
            "No package updates were reported or the package manager was unsupported.",
        ))

    sudo_rights = _non_empty_lines(inventory.get("sudo_rights"), limit=15)
    if sudo_rights:
        inventory["sudo_rights"] = sudo_rights
        checks.append(_check(
            "info",
            "Sudo rights discovered",
            "Sudo privileges are available for this account (review least privilege).",
        ))

    listening = _non_empty_lines(inventory.get("listening_services"), limit=20)
    if listening:
        inventory["listening_services"] = listening
        checks.append(_check(
            "info",
            "Listening services",
            f"Collected {len(listening)} listening socket entries from the host.",
        ))

    writable = _non_empty_lines(inventory.get("world_writable"), limit=20)
    if writable:
        inventory["world_writable"] = writable
        checks.append(_check(
            "failed",
            "World-writable files detected",
            f"{len(writable)} world-writable file(s) found in critical directories.",
        ))

    users = _non_empty_lines(inventory.get("local_users"), limit=20)
    if users:
        inventory["local_users"] = users

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
