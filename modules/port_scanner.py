import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp


# =========================
# 🔎 NETWORK DISCOVERY (ARP)
# =========================
def discover_network(network="192.168.1.0/24"):
    print(f"[*] Scanning network: {network}\n")

    devices = []

    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc

            devices.append(ip)
            print(f"[+] {ip} ({mac})")

        if not devices:
            print("[-] No devices found")

        return devices

    except Exception as e:
        print("[-] Error during network discovery:", e)
        return []


# =========================
# 🔌 PORT SCAN (1 → 1024)
# =========================
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            banner = grab_banner(ip, port)
            return {"port": port, "banner": banner}

    except:
        pass

    return None


def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        return banner

    except:
        return ""


def scan_ports(ip, ports=range(1, 1025), threads=100):
    open_ports = []

    print(f"\n[*] Scanning {ip} (ports 1-1024)...\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for res in results:
        if res:
            print(f"[+] OPEN {res['port']} | {res['banner']}")
            open_ports.append(res)

    if not open_ports:
        print("[-] No open ports found.")

    return open_ports
