import socket
from concurrent.futures import ThreadPoolExecutor
from modules.utils import grab_banner


COMMON_PORTS = {
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
    8081, 8443, 9200, 27017, 5555, 5985, 5986,
}


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
def scan_ports(ip, ports=None, threads=100):
    if ports is None:
        ports = sorted(set(range(1, 1025)) | COMMON_PORTS)

    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for res in results:
        if res:
            open_ports.append(res)

    return open_ports
