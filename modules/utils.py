import socket
import ssl
from urllib.parse import urlparse


HTTP_PORTS = {80, 8000, 8080, 8081, 8888}
HTTPS_PORTS = {443, 8443}

SERVICE_PROBES = {
    21: b"FEAT\r\n",
    25: b"EHLO vulnix.local\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    587: b"EHLO vulnix.local\r\n",
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: vulnix.local\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10buildInfo\x00\x01\x00\x00\x00\x00",
}


def normalize_target(target):
    target = (target or "").strip()

    if not target:
        return ""

    # remove protocol
    target = target.replace("http://", "").replace("https://", "")

    # remove path
    target = target.split("/")[0]

    # remove port
    target = target.split(":")[0]

    return target.strip()


def resolve_host(target):
    host = normalize_target(target)

    if not host:
        return None

    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    try:
        return socket.gethostbyname(host)
    except:
        return None


def _read_available(sock, size=2048):
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b""


def _decode_banner(chunks):
    return "\n".join(
        chunk.decode(errors="ignore").strip()
        for chunk in chunks
        if chunk
    ).strip()


def _wrap_tls(sock, ip):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=ip)


def grab_banner(ip, port):
    sock = None

    try:
        raw_sock = socket.create_connection((ip, port), timeout=2)
        raw_sock.settimeout(1.2)
        sock = raw_sock
        if port in HTTPS_PORTS:
            sock = _wrap_tls(sock, ip)

        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            return _decode_banner([_read_available(sock)])

        if port in HTTPS_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            return _decode_banner([_read_available(sock)])

        chunks = [_read_available(sock)]

        probe = SERVICE_PROBES.get(port)
        if probe:
            sock.sendall(probe)
            chunks.append(_read_available(sock))

        return _decode_banner(chunks)

    except (OSError, ssl.SSLError):
        return ""

    finally:
        if sock:
            sock.close()
