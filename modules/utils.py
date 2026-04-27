import socket
from urllib.parse import urlparse


HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


def normalize_target(target):
    target = (target or "").strip()

    if not target:
        return ""

    parsed = urlparse(target)

    if not parsed.hostname and "://" not in target:
        parsed = urlparse(f"//{target}")

    if parsed.hostname:
        return parsed.hostname

    if "://" in target:
        return ""

    return target.split("/")[0].split(":")[0]


def resolve_host(target):
    host = normalize_target(target)

    if not host:
        return None

    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, TypeError, UnicodeError):
        return None


def grab_banner(ip, port):
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner

    except OSError:
        return ""

    finally:
        if sock:
            sock.close()
