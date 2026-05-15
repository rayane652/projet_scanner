import socket
import ssl
import time
from urllib.parse import urlparse


HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 3000, 5000, 9000, 9090, 10000, 6080, 7070, 8787, 9999}
HTTPS_PORTS = {443, 8443, 8444, 9443, 5443}

SERVICE_PROBES = {
    21: b"FEAT\r\n",
    22: None,
    25: b"EHLO vulnix.local\r\n",
    53: None,
    80: None,
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: None,
    587: b"EHLO vulnix.local\r\n",
    993: None,
    995: None,
    3306: None,
    5432: None,
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: vulnix.local\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10buildInfo\x00\x01\x00\x00\x00\x00",
    11211: b"stats\r\n",
    3000: None,
    5000: None,
    9000: None,
    8000: None,
    8081: None,
    8888: None,
    9090: None,
    10000: None,
    5060: b"OPTIONS sip:vulnix.local SIP/2.0\r\n\r\n",
    5222: b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>\r\n",
    6667: b"PING vulnix\r\n",
    8443: None,
    8444: None,
    9443: None,
    5443: None,
    5601: b"GET / HTTP/1.0\r\nHost: vulnix.local\r\n\r\n",
    5672: b"AMQP\r\n",
    7001: b"GET / HTTP/1.0\r\nHost: vulnix.local\r\n\r\n",
    8089: b"GET / HTTP/1.0\r\nHost: vulnix.local\r\n\r\n",
    61616: b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}


def normalize_target(target):
    target = (target or "").strip()
    if not target:
        return ""
    target = target.replace("http://", "").replace("https://", "")
    target = target.split("/")[0]
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
    except Exception:
        return None


def _read_available(sock, size=4096):
    chunks = []
    try:
        sock.settimeout(0.5)
        while True:
            try:
                chunk = sock.recv(size)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
    except OSError:
        pass
    return b"".join(chunks)


def _decode_banner(chunks):
    return "\n".join(
        chunk.decode(errors="ignore").strip()
        for chunk in chunks
        if chunk
    ).strip()[:2048]


def _wrap_tls(sock, ip):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=ip)


def grab_banner(ip, port):
    sock = None
    try:
        raw_sock = socket.create_connection((ip, port), timeout=2)
        raw_sock.settimeout(1.5)
        sock = raw_sock

        if port in HTTPS_PORTS:
            sock = _wrap_tls(sock, ip)
            sock.settimeout(2.0)
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            time.sleep(0.2)
            return _decode_banner([_read_available(sock)])

        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Vulnix-Scanner/2.0\r\n\r\n".encode())
            time.sleep(0.2)
            return _decode_banner([_read_available(sock)])

        chunks = [_read_available(sock)]

        probe = SERVICE_PROBES.get(port)
        if probe:
            try:
                sock.sendall(probe)
                time.sleep(0.3)
                chunks.append(_read_available(sock))
            except OSError:
                pass

        return _decode_banner(chunks)

    except (OSError, ssl.SSLError, socket.timeout):
        return ""
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def grab_banner_tls(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result = {
                    "tls_version": ssock.version(),
                    "cipher_name": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "cipher_suite": cipher,
                }
                if cert:
                    result["issuer"] = dict(cert.get("issuer", []))
                    result["subject"] = dict(cert.get("subject", []))
                    result["not_after"] = cert.get("notAfter", "")
                    result["not_before"] = cert.get("notBefore", "")
                    serial = cert.get("serialNumber", "")
                    result["serial"] = serial
                    san = cert.get("subjectAltName", [])
                    result["san"] = [entry[1] for entry in san] if san else []
                    is_self_signed = False
                    issuer_org = dict(cert.get("issuer", [])).get("organizationName", "")
                    subject_cn = dict(cert.get("subject", [])).get("commonName", "")
                    if issuer_org == subject_cn or not issuer_org:
                        is_self_signed = True
                    result["self_signed"] = is_self_signed

                    import datetime as dt
                    try:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            now = dt.datetime.utcnow()
                            days_left = (expiry - now).days
                            result["days_left"] = days_left
                            result["expired"] = days_left < 0
                            result["expires_soon"] = 0 <= days_left < 30
                    except (ValueError, TypeError):
                        pass

                return result
    except Exception as e:
        return {"error": str(e)}
