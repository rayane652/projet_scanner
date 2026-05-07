import socket
from concurrent.futures import ThreadPoolExecutor
from modules.utils import grab_banner


COMMON_PORTS = {
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
    8081, 8443, 9200, 27017, 5555, 5985, 5986,
}

COMMON_UDP_PORTS = {
    53, 67, 68, 69, 123, 137, 161, 500, 1900, 5353,
}

UDP_PROBES = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    123: b"\x1b" + (b"\x00" * 47),
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
}

_SCAPY_TOOLS = None
_SCAPY_CHECKED = False


def _tcp_os_hint(ttl):
    if ttl is None:
        return ""

    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return ""

    if ttl <= 64:
        return "Linux/Unix likely"
    if ttl <= 128:
        return "Windows likely"
    return "Network appliance or Unix likely"


# ================= PORT CHECK =================
def scan_tcp_connect_port(ip, port, timeout=0.7, scan_method="tcp_connect", reason="tcp-connect"):
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))

        if result == 0:
            sock.close()
            sock = None
            banner = grab_banner(ip, port)

            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "banner": banner,
                "scan_method": scan_method,
                "reason": reason,
            }

    except OSError:
        pass
    finally:
        if sock:
            sock.close()

    return None


def _get_scapy_tools():
    global _SCAPY_TOOLS, _SCAPY_CHECKED

    if _SCAPY_CHECKED:
        return _SCAPY_TOOLS

    try:
        from scapy.all import IP, TCP, send, sr1
    except Exception:
        _SCAPY_TOOLS = None
    else:
        _SCAPY_TOOLS = (IP, TCP, send, sr1)

    _SCAPY_CHECKED = True
    return _SCAPY_TOOLS


def scan_syn_port(ip, port, timeout=1.0):
    scapy_tools = _get_scapy_tools()
    if not scapy_tools:
        return None

    IP, TCP, send, sr1 = scapy_tools

    try:
        response = sr1(
            IP(dst=ip) / TCP(dport=port, flags="S"),
            timeout=timeout,
            verbose=False,
        )
        if not response or not response.haslayer(TCP):
            return None

        flags = int(response.getlayer(TCP).flags)
        if flags & 0x12 == 0x12:
            send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
            banner = grab_banner(ip, port)
            ttl = getattr(response, "ttl", None)
            tcp_window = getattr(response.getlayer(TCP), "window", None)
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "banner": banner,
                "scan_method": "syn",
                "reason": "syn-ack",
                "ttl": ttl,
                "tcp_window": tcp_window,
                "os_hint": _tcp_os_hint(ttl),
            }
    except Exception:
        return None

    return None


def scan_tcp_port(ip, port, scan_method="connect"):
    if scan_method == "syn":
        syn_result = scan_syn_port(ip, port)
        if syn_result:
            return syn_result
        return scan_tcp_connect_port(
            ip,
            port,
            scan_method="tcp_connect",
            reason="syn-unavailable-fallback",
        )

    return scan_tcp_connect_port(ip, port)


def scan_udp_port(ip, port, timeout=1.2, include_filtered=False):
    probe = UDP_PROBES.get(port, b"")
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(probe, (ip, port))
        data, _ = sock.recvfrom(4096)
        banner = data.decode(errors="ignore").strip()
        return {
            "port": port,
            "protocol": "udp",
            "state": "open",
            "banner": banner,
            "scan_method": "udp_probe",
            "reason": "udp-response",
        }
    except socket.timeout:
        if include_filtered:
            return {
                "port": port,
                "protocol": "udp",
                "state": "open|filtered",
                "banner": "",
                "scan_method": "udp_probe",
                "reason": "no-response",
            }
    except (ConnectionResetError, OSError):
        return None
    finally:
        if sock:
            sock.close()

    return None


def scan_port(ip, port):
    return scan_tcp_connect_port(ip, port)


# ================= FULL SCAN =================
def scan_ports(
    ip,
    ports=None,
    threads=100,
    scan_method="connect",
    include_udp=False,
    udp_ports=None,
):
    if ports is None:
        ports = sorted(set(range(1, 1025)) | COMMON_PORTS)

    open_ports = []
    scan_method = scan_method if scan_method in {"connect", "syn"} else "connect"

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_tcp_port(ip, p, scan_method), ports)

    for res in results:
        if res:
            open_ports.append(res)

    if include_udp:
        udp_targets = sorted(set(udp_ports or COMMON_UDP_PORTS))
        with ThreadPoolExecutor(max_workers=min(threads, len(udp_targets) or 1)) as executor:
            udp_results = executor.map(lambda p: scan_udp_port(ip, p), udp_targets)

        for res in udp_results:
            if res:
                open_ports.append(res)

    return sorted(open_ports, key=lambda item: (item.get("port") or 0, item.get("protocol") or "tcp"))
