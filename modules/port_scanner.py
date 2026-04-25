import socket
from concurrent.futures import ThreadPoolExecutor
from modules.utils import grab_banner


# ================= PORT CHECK =================
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            banner = grab_banner(ip, port)

            return {
                "port": port,
                "banner": banner
            }

    except:
        pass

    return None


# ================= FULL SCAN =================
def scan_ports(ip, ports=range(1, 1025), threads=100):
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for res in results:
        if res:
            open_ports.append(res)

    return open_ports