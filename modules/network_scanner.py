import ipaddress
import logging
import re
import socket
import struct
import subprocess
import platform
import concurrent.futures
import threading
import time
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

from modules.port_scanner import scan_ports
from modules.service_detector import detect_service_and_version
from modules.cve_scanner import search_cves
from modules.web_scanner import scan_website

TOP_PORTS = [22, 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017]
MOBILE_PORTS = [5555, 4244, 3724, 5554, 8080, 8443, 9000]
IOT_PORTS = [1883, 8883, 5683, 5684, 4843, 22, 80, 443, 8080]
MEDIA_PORTS = [32400, 1900, 5353, 5004, 5005, 7000, 7001, 8000, 8890]
DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 8080, 8443]
DISCOVERY_PORTS_EXT = [5555, 32400, 1900, 5353, 1883, 5000, 7000, 8081, 9000]
FALLBACK_PORTS = [22, 80, 443, 445, 8080]
SCAN_TIMEOUT = 3
MAX_DISCOVERY_WORKERS = 80
MAX_ENUM_WORKERS = 30
MAX_SCAN_PORT_WORKERS = 50


def parse_targets(raw):
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        net = ipaddress.ip_network(raw, strict=False)
        if net.num_addresses > 65536:
            return []
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass
    ips = []
    for part in raw.replace(",", " ").split():
        part = part.strip()
        try:
            ipaddress.ip_address(part)
            ips.append(part)
        except ValueError:
            try:
                addr = socket.gethostbyname(part)
                ips.append(addr)
            except socket.gaierror:
                continue
    return ips


_IS_WINDOWS = platform.system().lower() == "windows"

def _ping(ip, timeout=2):
    if _IS_WINDOWS:
        args = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout + 2,
                           creationflags=subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_check(ip, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def _arp_lookup(ip):
    """Return MAC address from ARP cache, or empty string."""
    try:
        if _IS_WINDOWS:
            r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            for line in r.stdout.splitlines():
                if ip in line:
                    for part in line.split():
                        if re.match(r'^([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})$', part):
                            return part.upper()
        else:
            r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                if ip in line:
                    for part in line.split():
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                            return part.upper()
    except Exception:
        pass
    return ""


def _resolve_hostname(ip, timeout=2):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def _get_mac(ip):
    return _arp_lookup(ip)


VENDOR_TABLE = {
    "080007": ("Apple", "desktop"), "001124": ("Apple", "desktop"), "003065": ("Apple", "mobile"),
    "002325": ("Apple", "mobile"), "000A95": ("Apple", "mobile"), "001636": ("Apple", "mobile"),
    "001CB0": ("Apple", "tablet"), "00123D": ("Apple", "mobile"), "0016CB": ("Apple", "mobile"),
    "04A151": ("Apple", "mobile"), "002608": ("Apple", "mobile"), "983B8E": ("Apple", "mobile"),
    "F81EDF": ("Apple", "mobile"), "A40CC3": ("Apple", "mobile"), "70484B": ("Apple", "mobile"),
    "A88808": ("Apple", "desktop"), "B0E235": ("Apple", "desktop"), "F0F61C": ("Apple", "desktop"),
    "58723B": ("Apple", "tablet"), "A42B2C": ("Apple", "desktop"),
    "00177A": ("Samsung", "mobile"), "0021CC": ("Samsung", "mobile"), "E03F49": ("Samsung", "mobile"),
    "0050B6": ("Samsung", "mobile"), "001E4F": ("Samsung", "mobile"), "0025A1": ("Samsung", "mobile"),
    "001EE6": ("Samsung", "mobile"), "A886DD": ("Samsung", "mobile"), "C8D15E": ("Samsung", "mobile"),
    "8C8CAA": ("Samsung", "mobile"), "34A3BF": ("Samsung", "mobile"), "B06685": ("Samsung", "mobile"),
    "44C9A2": ("Samsung", "mobile"), "3C0E6D": ("Samsung", "mobile"),
    "00E0FC": ("Huawei", "mobile"), "001378": ("Huawei", "mobile"), "0C9D92": ("Huawei", "mobile"),
    "1C5C55": ("Huawei", "mobile"), "0C1D1E": ("Huawei", "mobile"), "98A98C": ("Huawei", "mobile"),
    "A4A64B": ("Huawei", "mobile"), "F8BF09": ("Huawei", "mobile"), "D8D22D": ("Huawei", "mobile"),
    "C89C1D": ("Huawei", "mobile"), "4C5FFC": ("Huawei", "router"),
    "001E4E": ("Xiaomi", "mobile"), "002128": ("Xiaomi", "mobile"), "0409A0": ("Xiaomi", "mobile"),
    "18031F": ("Xiaomi", "mobile"), "48037D": ("Xiaomi", "mobile"), "78B8CD": ("Xiaomi", "mobile"),
    "C8C2C1": ("Xiaomi", "mobile"), "D0ADA1": ("Xiaomi", "mobile"), "F48C50": ("Xiaomi", "mobile"),
    "9CE374": ("Xiaomi", "iot"),
    "00037F": ("Google", "mobile"), "001B11": ("Google", "mobile"), "A4C0E1": ("Google", "mobile"),
    "0C8DF6": ("Google", "mobile"), "886657": ("Google", "mobile"), "BCA51E": ("Google", "mobile"),
    "D8D385": ("Google", "iot"), "246990": ("Google", "router"),
    "00BB01": ("Amazon", "iot"), "4013FF": ("Amazon", "iot"), "74C75B": ("Amazon", "iot"),
    "7CFE4E": ("Amazon", "iot"), "AC63BE": ("Amazon", "iot"), "B0802C": ("Amazon", "iot"),
    "0050F2": ("Microsoft", "desktop"), "001DD8": ("Microsoft", "desktop"), "00155D": ("Microsoft", "desktop"),
    "00248A": ("Microsoft", "desktop"), "0003FF": ("Microsoft", "desktop"),
    "000F1C": ("Sony", "tv"), "00134F": ("Sony", "tv"), "0024BE": ("Sony", "mobile"),
    "080046": ("Sony", "tv"), "3481C4": ("Sony", "tv"),
    "001D64": ("LG", "tv"), "00213B": ("LG", "mobile"), "00E070": ("LG", "tv"),
    "4844F7": ("LG", "mobile"), "7CF1C0": ("LG", "tv"),
    "00059B": ("Panasonic", "tv"), "00188A": ("Panasonic", "tv"), "00A05D": ("Panasonic", "tv"),
    "001DDD": ("Roku", "tv"), "002469": ("Roku", "tv"), "0060DF": ("Roku", "tv"),
    "0002A5": ("NVIDIA", "desktop"), "001C42": ("NVIDIA", "desktop"), "984B2C": ("NVIDIA", "desktop"),
    "089EF0": ("Raspberry Pi", "iot"), "B827EB": ("Raspberry Pi", "iot"), "D83A1C": ("Raspberry Pi", "iot"),
    "E45F01": ("Raspberry Pi", "iot"),
    "005043": ("TP-Link", "router"), "1CB72C": ("TP-Link", "router"), "F81A67": ("TP-Link", "router"),
    "00223F": ("TP-Link", "router"), "A8D89C": ("TP-Link", "router"),
    "001AA0": ("Netgear", "router"), "001E2A": ("Netgear", "router"), "00223F": ("Netgear", "router"),
    "080028": ("Netgear", "router"), "A022B8": ("Netgear", "router"),
    "0004F2": ("Cisco", "network"), "00259C": ("Cisco", "network"), "001C0E": ("Cisco", "network"),
    "00504D": ("Cisco", "network"), "001B0C": ("Cisco", "network"),
    "000C29": ("VMware", "server"), "005056": ("VMware", "server"),
    "000347": ("Intel", "desktop"), "001C25": ("Intel", "desktop"), "0050B6": ("Intel", "desktop"),
    "0003FF": ("Dell", "desktop"), "0015D1": ("Dell", "desktop"), "00188B": ("Dell", "desktop"),
    "001150": ("Dell", "desktop"), "001EC0": ("Dell", "desktop"),
    "0001C7": ("HP", "printer"), "002481": ("HP", "desktop"), "0017A4": ("HP", "printer"),
    "003048": ("HP", "printer"), "00A0C9": ("HP", "printer"),
    "000C41": ("IBM", "server"), "0050C2": ("IBM", "server"),
    "000BDB": ("Juniper", "network"), "001B43": ("Juniper", "network"),
    "000C06": ("Arista", "network"),
    "001132": ("Synology", "nas"), "E03F49": ("Synology", "nas"),
    "000FC9": ("QNAP", "nas"), "00248C": ("QNAP", "nas"),
    "001AE9": ("Canon", "printer"), "0025E8": ("Canon", "printer"), "00A0B4": ("Canon", "printer"),
    "001B06": ("Brother", "printer"), "0021A6": ("Brother", "printer"), "000321": ("Brother", "printer"),
    "00123F": ("Epson", "printer"), "000AAC": ("Epson", "printer"), "00A0C6": ("Epson", "printer"),
    "000E58": ("Sonos", "iot"), "B8AEC4": ("Sonos", "iot"),
    "001788": ("Philips", "iot"), "ECB5A2": ("Philips", "iot"),
    "9CE374": ("Xiaomi", "iot"),
    "00151A": ("Belkin", "iot"), "00253B": ("Belkin", "iot"),
    "0015E9": ("Acer", "desktop"), "4437E6": ("Acer", "desktop"), "2486F4": ("Acer", "desktop"),
    "001DDC": ("Lenovo", "desktop"), "00215C": ("Lenovo", "desktop"), "38229D": ("Lenovo", "desktop"),
    "0019CB": ("Asus", "router"), "0022B0": ("Asus", "desktop"), "00604B": ("Asus", "router"),
    "C8C2C1": ("Xiaomi", "router"),
    "001C4A": ("Bose", "iot"), "00259E": ("Bose", "iot"),
    "0022D3": ("Denon", "tv"), "000F94": ("Denon", "tv"),
    "001EE6": ("Samsung", "tv"), "8C8CAA": ("Samsung", "tv"),
    "00B29B": ("Vizio", "tv"), "001AE9": ("Vizio", "tv"),
    "E8DE27": ("Hisense", "tv"), "0C1D1E": ("Hisense", "tv"),
    "3C0E6D": ("TCL", "tv"), "B0EAEA": ("TCL", "tv"),
    "001231": ("Nintendo", "console"), "002540": ("Nintendo", "console"), "8CADAB": ("Nintendo", "console"),
    "001D0B": ("Xbox", "console"), "0026C9": ("Xbox", "console"), "48ECA8": ("Xbox", "console"),
    "0013C6": ("PlayStation", "console"), "0021E5": ("PlayStation", "console"), "00888E": ("PlayStation", "console"),
    "04C5A4": ("PlayStation", "console"), "F4CE46": ("PlayStation", "console"),
    "1C5C55": ("Hikvision", "iot"), "2C4FEE": ("Hikvision", "iot"),
    "000E53": ("Dahua", "iot"), "48A16F": ("Dahua", "iot"),
    "8CA8CD": ("Ring", "iot"), "30A3B0": ("Ring", "iot"),
    "001F1F": ("Nest", "iot"), "18667A": ("Nest", "iot"),
    "402F87": ("Arlo", "iot"), "6C3B45": ("Arlo", "iot"),
}


def _vendor_info(mac):
    if not mac or len(mac) < 8:
        return "", ""
    prefix = mac[:8].upper().replace(":", "").replace("-", "")
    info = VENDOR_TABLE.get(prefix, ("", ""))
    if info[0]:
        return info
    prefix6 = mac[:8].upper().replace(":", "").replace("-", "")[:6]
    info = VENDOR_TABLE.get(prefix6, ("", ""))
    return info if info[0] else ("", "")


DEVICE_PORT_SIGNATURES = {
    "mobile": {5555, 4244, 3724},
    "tv": {32400, 1900, 7000, 7001},
    "iot": {1883, 8883, 5683, 5684},
    "printer": {515, 631, 9100},
    "console": {3074, 9295, 9302},
    "router": {53, 1900, 5000},
}


def _classify_device(ip, hostname, mac, vendor, ports):
    device_type = "unknown"
    vendor_name = vendor or ""

    if vendor:
        vendor_name = vendor
        if isinstance(vendor, tuple):
            vendor_name, device_type = vendor
        elif vendor in VENDOR_TABLE and isinstance(VENDOR_TABLE[vendor], tuple):
            vendor_name, device_type = VENDOR_TABLE[vendor]

    open_ports = {p.get("port") for p in ports if p.get("state") == "open"}
    hostname_lower = (hostname or "").lower()

    port_hints = []
    for dtype, sig_ports in DEVICE_PORT_SIGNATURES.items():
        if open_ports & sig_ports:
            port_hints.append(dtype)

    if device_type != "unknown" and device_type != "desktop":
        pass
    elif port_hints:
        device_type = port_hints[0]
    elif "tv" in hostname_lower or "samsung" in hostname_lower or "lgtv" in hostname_lower or "sony" in hostname_lower:
        device_type = "tv"
    elif "printer" in hostname_lower or "hp-" in hostname_lower or "canon" in hostname_lower or "brother" in hostname_lower or "epson" in hostname_lower:
        device_type = "printer"
    elif "router" in hostname_lower or "router" in hostname_lower or "ap-" in hostname_lower or "wifi" in hostname_lower:
        device_type = "router"
    elif "iphone" in hostname_lower or "ipad" in hostname_lower or "android" in hostname_lower or "samsung" in hostname_lower:
        device_type = "mobile"
    elif "raspberry" in hostname_lower or "pi-" in hostname_lower or "esp-" in hostname_lower or "arduino" in hostname_lower:
        device_type = "iot"
    elif "server" in hostname_lower or "nas" in hostname_lower or "synology" in hostname_lower or "qnap" in hostname_lower:
        device_type = "server"
    elif "laptop" in hostname_lower or "deskto" in hostname_lower or "pc-" in hostname_lower:
        device_type = "desktop"
    elif {515, 631, 9100} & open_ports:
        device_type = "printer"
    elif 32400 in open_ports or 1900 in open_ports:
        device_type = "tv"
    elif 5555 in open_ports or 4244 in open_ports:
        device_type = "mobile"
    elif 1883 in open_ports or 8883 in open_ports:
        device_type = "iot"
    elif 3074 in open_ports:
        device_type = "console"
    elif 443 in open_ports and 22 in open_ports:
        device_type = "server" if len(open_ports) > 5 else "desktop"

    return vendor_name, device_type


def _determine_scan_depth(hosts, scan_duration):
    total_hosts = len(hosts)
    total_ports = sum(len(h.get("ports", [])) for h in hosts)
    risky_hosts = sum(1 for h in hosts if any(p.get("port") in {23, 445, 3389, 5555, 3306, 6379, 27017, 9200} for p in h.get("ports", [])))

    if total_hosts <= 10 and total_ports <= 100:
        return "deep"
    if total_hosts <= 40:
        if risky_hosts > 0 or total_hosts <= 20:
            return "deep"
        return "balanced"
    if total_hosts <= 100:
        if risky_hosts > total_hosts * 0.2:
            return "balanced"
        return "balanced"
    return "balanced"


def _quick_scan_ports(ip, ports, timeout=0.5):
    """Check multiple ports in parallel, return list of open ones."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), 20)) as ex:
        futures = {ex.submit(_tcp_check, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            p = futures[f]
            try:
                if f.result():
                    open_ports.append(p)
            except Exception:
                pass
    return open_ports


def discover_hosts(ips, progress_callback=None):
    discovered = []
    total = len(ips)
    done = [0]

    ALL_PROBE_PORTS = DISCOVERY_PORTS + DISCOVERY_PORTS_EXT + FALLBACK_PORTS
    ALL_PROBE_PORTS = list(set(ALL_PROBE_PORTS))

    def check(ip):
        alive = False
        fallback_used = False
        open_ports = []

        # Phase 1: ICMP ping (works if not firewalled)
        ping_ok = _ping(ip, timeout=1.5)

        # Phase 2: Check ARP cache immediately
        # On Windows, ping populates ARP cache even if ICMP is blocked
        mac = _get_mac(ip)
        arp_ok = bool(mac)

        if ping_ok:
            alive = True
            if not mac:
                mac = _get_mac(ip)

        if arp_ok and not alive:
            alive = True
            fallback_used = True
            logger.info("Host %s: alive via ARP (%s)", ip, mac)

        # Phase 3: Quick TCP sweep (only if not yet confirmed alive)
        if not alive:
            open_ports = _quick_scan_ports(ip, DISCOVERY_PORTS, timeout=0.5)
            if open_ports:
                alive = True
                fallback_used = True
                logger.info("Host %s: alive via TCP ports %s", ip, open_ports)

        # Phase 4: Extended TCP sweep
        if not alive:
            ext = _quick_scan_ports(ip, DISCOVERY_PORTS_EXT, timeout=0.5)
            if ext:
                open_ports.extend(ext)
                alive = True
                fallback_used = True
                logger.info("Host %s: alive via extended TCP ports %s", ip, ext)

        # Phase 5: Fallback TCP with longer timeout
        if not alive:
            fback = _quick_scan_ports(ip, FALLBACK_PORTS, timeout=1.0)
            if fback:
                open_ports.extend(fback)
                alive = True
                fallback_used = True
                logger.info("Host %s: alive via fallback TCP %s", ip, fback)

        info = {"ip": ip, "alive": alive, "discovery_ports": sorted(set(open_ports))[:5], "fallback_used": fallback_used}
        if alive:
            info["hostname"] = _resolve_hostname(ip)
            if not mac:
                mac = _get_mac(ip)
            info["mac"] = mac
            vendor_raw = _vendor_info(mac) if mac else ("", "")
            info["vendor"] = vendor_raw[0] if vendor_raw else ""
            info["device_type"] = vendor_raw[1] if vendor_raw else "unknown"
            discovered.append(info)
        with threading.Lock():
            done[0] += 1
            if progress_callback:
                progress_callback(done[0], total, ip, alive, "discovering")
        return info

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DISCOVERY_WORKERS) as ex:
        ex.map(check, ips)

    return discovered


def _check_single_port(ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            s.send(b"\r\n")
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
            except Exception:
                banner = ""
            s.close()
            svc, ver, prod, conf = detect_service_and_version(port, banner, "tcp")
            return {"port": port, "protocol": "tcp", "state": "open", "service": svc, "version": ver, "product": prod, "confidence": conf, "banner": banner}
        s.close()
    except Exception:
        pass
    return None


def scan_light(ip, timeout=SCAN_TIMEOUT):
    ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCAN_PORT_WORKERS) as ex:
        futures = {ex.submit(_check_single_port, ip, p, timeout): p for p in TOP_PORTS}
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result()
                if r:
                    ports.append(r)
            except Exception:
                pass
    return ports


def scan_deep(ip, scan_method="connect", include_udp=False):
    result = {"ip": ip, "hostname": _resolve_hostname(ip), "ports": [], "cves": [], "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "risk_score": 0, "web": None}

    ports = scan_ports(ip, scan_method=scan_method, include_udp=include_udp) or []
    for p in ports:
        port = p["port"]
        protocol = p.get("protocol", "tcp")
        banner = p.get("banner", "")
        svc, ver, prod, conf = detect_service_and_version(port, banner, protocol)
        cves = []
        if prod:
            try:
                cves = search_cves(prod, ver)
            except Exception:
                cves = []
        for c in cves:
            sev = (c.get("severity") or "INFO").upper()
            if sev in result["severity_counts"]:
                result["severity_counts"][sev] += 1
        result["ports"].append({"port": port, "protocol": protocol, "state": p.get("state", "open"), "service": svc, "version": ver, "product": prod, "confidence": conf, "banner": banner, "cves": cves})
        result["cves"].extend(cves)

    penalty = result["severity_counts"]["critical"] * 25 + result["severity_counts"]["high"] * 16 + result["severity_counts"]["medium"] * 8 + result["severity_counts"]["low"] * 3
    total = sum(result["severity_counts"].values())
    result["risk_score"] = min(100, penalty) if total > 0 else 0

    try:
        web = scan_website(ip)
        if web and not web.get("error"):
            result["web"] = {"title": web.get("title", ""), "server": web.get("server", ""), "status_code": web.get("status_code"), "technologies": [t.get("name", str(t)) for t in (web.get("technologies") or []) if isinstance(t, dict)], "findings_count": len(web.get("findings", []))}
    except Exception:
        pass

    return result


def _add_subnet_info(results, ips):
    try:
        first = ips[0]
        last = ips[-1]
        cidr = None
        if len(ips) > 1:
            net = ipaddress.ip_network(f"{first}/{len(ips)}", strict=False)
            for prefix in range(32, 15, -1):
                try:
                    test = ipaddress.ip_network(f"{first}/{prefix}", strict=False)
                    if test.num_addresses >= len(ips):
                        cidr = str(test)
                        break
                except ValueError:
                    continue
        results["subnet"] = {
            "first_ip": first,
            "last_ip": last,
            "range_size": len(ips),
            "cidr": cidr or f"{first}/32",
            "is_subnet": len(ips) > 1,
        }
    except Exception:
        results["subnet"] = {"range_size": len(ips), "is_subnet": len(ips) > 1}
    return results


OS_PORT_SIGNATURES = {
    "Windows": {135, 139, 445, 3389, 5985, 5986},
    "Linux": {22, 111, 2049},
    "macOS": {88, 548, 5003, 7000},
    "Router": {23, 53, 69, 1900, 5000, 5060},
    "Printer": {515, 631, 9100},
    "Android": {5555, 4244, 3724},
    "IoT": {1883, 8883, 5683, 5684},
}


def _guess_os(ports, banners, hostname):
    open_ports = {p.get("port") for p in ports if p.get("state") == "open"}
    combined = " ".join(banners).lower() if banners else ""
    hostname = (hostname or "").lower()
    hints = []

    for os_name, sig_ports in OS_PORT_SIGNATURES.items():
        if open_ports & sig_ports:
            hints.append((os_name, 60))
    if "windows" in combined or "microsoft" in combined:
        hints.append(("Windows", 80))
    if "linux" in combined or "ubuntu" in combined or "debian" in combined:
        hints.append(("Linux", 80))
    if "ssh" in combined or "openssh" in combined:
        hints.append(("Linux/Unix", 50))
    if "darwin" in combined or "mac" in combined:
        hints.append(("macOS", 60))
    if "android" in combined or "adb" in combined:
        hints.append(("Android", 70))
    if "printer" in hostname or "hp-" in hostname or "canon" in hostname:
        hints.append(("Printer", 80))
    if "router" in hostname or "ap-" in hostname or "wifi" in hostname:
        hints.append(("Router", 70))

    if not hints:
        return "Unknown", "low"
    hints.sort(key=lambda x: -x[1])
    return hints[0][0], "high" if hints[0][1] >= 80 else "medium"


def _risk_level_from_score(score):
    score = max(0, min(100, score))
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


SERVICE_CATEGORIES = {
    "web": {"http", "https", "http-proxy", "http-alt", "https-alt"},
    "database": {"mysql", "mariadb", "postgresql", "oracle", "mssql", "redis", "mongodb", "cassandra", "elasticsearch"},
    "mail": {"smtp", "smtps", "pop3", "pop3s", "imap", "imaps"},
    "file": {"ftp", "sftp", "nfs", "smb", "netbios-ssn", "cifs"},
    "remote": {"ssh", "telnet", "rdp", "vnc", "winrm", "winrm-ssl", "adb"},
    "dns": {"dns", "mdns", "llmnr"},
    "iot": {"mqtt", "coap", "ssdp"},
    "monitoring": {"snmp", "zabbix-agent", "zabbix-trapper", "ntp"},
}


def _categorize_service(service):
    svc = (service or "").lower().strip()
    for cat, names in SERVICE_CATEGORIES.items():
        if svc in names:
            return cat
    return "other"


def _log_phase_results(label, hosts):
    if not hosts:
        logger.info("[%s] No hosts found", label)
        return
    logger.info("[%s] %d host(s) found:", label, len(hosts))
    for h in hosts:
        ip = h.get("ip", "?")
        ports = h.get("ports", [])
        cves = h.get("cves", [])
        os_name = h.get("os", "?")
        svc_list = ", ".join(sorted(set(p.get("service", "?") for p in ports if p.get("service") and p["service"] != "unknown"))) or "none"
        logger.info("  %s | OS: %s | ports: %d | svc: [%s] | CVEs: %d",
                     ip, os_name, len(ports), svc_list, len(cves))
        for p in ports:
            logger.debug("    port %d/%s: %s %s %s | banner: %.60s",
                         p.get("port"), p.get("protocol", "tcp"),
                         p.get("service", "?"), p.get("product", ""), p.get("version", ""),
                         p.get("banner", ""))


def run_network_scan(targets_raw, profile="adaptive", scan_method="connect", include_udp=False, progress_callback=None):
    start = time.time()
    ips = parse_targets(targets_raw)
    if not ips:
        return {"error": "Could not parse any valid targets", "targets_raw": targets_raw}

    is_subnet = len(ips) > 1
    logger.info("=== Network scan started: %s (%d targets) ===", targets_raw, len(ips))
    results = {"targets_raw": targets_raw, "type": "network", "is_subnet": is_subnet, "total_targets": len(ips), "live_count": 0, "hosts": [], "discovery": [], "duration_seconds": 0, "phases": {}, "fallback_hosts": 0, "used_pn_fallback": False}
    results = _add_subnet_info(results, ips)
    logger.info("Subnet: %s (%s -> %s)", results["subnet"].get("cidr", "?"), results["subnet"].get("first_ip", "?"), results["subnet"].get("last_ip", "?"))

    if progress_callback:
        progress_callback(0, len(ips), "", False, "discovering")

    discovered = discover_hosts(ips, progress_callback)
    results["discovery"] = discovered
    results["live_count"] = len(discovered)
    results["phases"]["discovery"] = round(time.time() - start, 1)
    logger.info("Discovery phase: %d/%d hosts alive in %.1fs", len(discovered), len(ips), results["phases"]["discovery"])

    fallback_count = sum(1 for d in discovered if d.get("fallback_used"))
    results["fallback_hosts"] = fallback_count
    if fallback_count:
        logger.info("Fallback used for %d host(s) (ICMP blocked)", fallback_count)

    if not discovered:
        logger.info("Retrying discovery with aggressive -Pn fallback...")
        if progress_callback:
            progress_callback(0, len(ips), "", False, "fallback_discovery")
        discovered = discover_hosts(ips, progress_callback)
        results["discovery"] = discovered
        results["live_count"] = len(discovered)
        results["phases"]["fallback_discovery"] = round(time.time() - start, 1)
        results["used_pn_fallback"] = True
        fallback_count = sum(1 for d in discovered if d.get("fallback_used"))
        results["fallback_hosts"] = fallback_count
        logger.info("Pn fallback found %d host(s)", len(discovered))

    if not discovered:
        logger.warning("NO hosts found in %s — check network connectivity and firewall rules", targets_raw)
        results["duration_seconds"] = round(time.time() - start, 1)
        results["risk_score"] = 0
        results["risk_level"] = "LOW"
        results["risk_class"] = "low"
        results["aggregated"] = {"severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "total_cves": 0, "total_ports": 0, "top_ports": [], "top_services": [], "os_distribution": {}, "service_categories": {}, "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "hosts_by_risk": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        return results

    if progress_callback:
        progress_callback(0, len(discovered), "", False, "enumerating")

    hosts = []
    lock = threading.Lock()
    done = [0]

    def enum_one(host):
        ip = host["ip"]
        logger.info("  Enumerating %s ...", ip)
        light = scan_light(host["ip"])
        vname, dtype = _classify_device(host["ip"], host.get("hostname", ""), host.get("mac", ""), host.get("vendor", ""), light)
        banners = [p.get("banner", "") for p in light]
        os_name, os_conf = _guess_os(light, banners, host.get("hostname", ""))
        port_count = len(light)
        svc_str = ", ".join(sorted(set(p.get("service", "?") for p in light if p.get("service") and p["service"] != "unknown"))) or "none"
        logger.info("    -> %s: %d port(s) open [%s] OS: %s", ip, port_count, svc_str, os_name)
        with lock:
            hosts.append({"ip": host["ip"], "hostname": host.get("hostname", ""), "mac": host.get("mac", ""), "vendor": vname, "device_type": dtype or host.get("device_type", "unknown"), "alive": True, "ports": light, "cves": [], "os": os_name, "os_confidence": os_conf, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "risk_score": 0, "risk_level": "LOW", "scanned": True, "deep_available": True})
            done[0] += 1
            if progress_callback:
                progress_callback(done[0], len(discovered), host["ip"], True, "enumerating")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_ENUM_WORKERS) as ex:
        ex.map(enum_one, discovered)

    hosts.sort(key=lambda h: len(h.get("ports", [])), reverse=True)
    results["hosts"] = hosts
    results["phases"]["enumeration"] = round(time.time() - start, 1)
    logger.info("Enumeration phase: %d hosts enumerated in %.1fs", len(hosts), results["phases"]["enumeration"])
    _log_phase_results("enumeration", hosts)

    logger.info("Starting deep scan phase for %d host(s)...", len(hosts))
    if progress_callback:
        progress_callback(0, len(hosts), "", False, "deep_scan")

    deep_done = [0]
    def deep_one(host):
        ip = host["ip"]
        logger.info("  Deep scanning %s ...", ip)
        deep = scan_deep(ip, scan_method=scan_method, include_udp=include_udp)
        deep_ports = deep.get("ports", [])
        deep_cves = deep.get("cves", [])
        logger.info("    -> %s: %d ports (deep), %d CVE(s)", ip, len(deep_ports), len(deep_cves))
        with lock:
            if deep_ports:
                host["ports"] = deep_ports
            host["cves"] = deep_cves
            host["severity_counts"] = deep.get("severity_counts", host["severity_counts"])
            host["risk_score"] = deep.get("risk_score", 0)
            host["web"] = deep.get("web")
            host["deep_available"] = False
            deep_done[0] += 1
            if progress_callback:
                progress_callback(deep_done[0], len(hosts), ip, True, "deep_scan")

    workers = min(10, len(hosts))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(deep_one, hosts)
    results["phases"]["deep_scan"] = round(time.time() - start, 1)
    logger.info("Deep scan phase: %d hosts scanned in %.1fs", len(hosts), results["phases"]["deep_scan"])
    _log_phase_results("deep_scan", hosts)

    logger.info("Computing aggregation and risk scores...")
    agg_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_cves = 0
    total_ports = 0
    port_freq = defaultdict(int)
    svc_freq = defaultdict(int)
    os_dist = defaultdict(int)
    svc_cat_counts = defaultdict(int)
    risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for h in hosts:
        for k in agg_counts:
            agg_counts[k] += h.get("severity_counts", {}).get(k, 0)
        total_cves += len(h.get("cves", []))
        banners = [p.get("banner", "") for p in h.get("ports", [])]
        os_name, os_conf = _guess_os(h.get("ports", []), banners, h.get("hostname", ""))
        h["os"] = os_name
        h["os_confidence"] = os_conf
        h["risk_level"] = _risk_level_from_score(h.get("risk_score", 0) or 0)
        h["risk_class"] = h["risk_level"].lower()
        os_dist[os_name] += 1
        risk_dist[h["risk_level"]] += 1

        for p in h.get("ports", []):
            total_ports += 1
            port_freq[p.get("port")] += 1
            svc = p.get("service", "unknown")
            svc_freq[svc] += 1
            cat = _categorize_service(svc)
            svc_cat_counts[cat] += 1
        h.pop("severity_counts", None)

    penalty = agg_counts["critical"] * 25 + agg_counts["high"] * 16 + agg_counts["medium"] * 8 + agg_counts["low"] * 3
    results["risk_score"] = min(100, penalty) if sum(agg_counts.values()) > 0 else 0
    results["risk_level"] = _risk_level_from_score(results["risk_score"])
    results["risk_class"] = results["risk_level"].lower()

    results["aggregated"] = {
        "severity_counts": agg_counts,
        "total_cves": total_cves,
        "total_ports": total_ports,
        "top_ports": sorted([{"port": k, "count": v} for k, v in port_freq.items()], key=lambda x: -x["count"])[:12],
        "top_services": sorted([{"service": k, "count": v} for k, v in svc_freq.items()], key=lambda x: -x["count"])[:12],
        "os_distribution": dict(sorted(os_dist.items(), key=lambda x: -x[1])),
        "service_categories": dict(sorted(svc_cat_counts.items(), key=lambda x: -x[1])),
        "risk_distribution": risk_dist,
        "hosts_by_risk": {"critical": sum(1 for h in hosts if h.get("risk_level") == "CRITICAL"),
                          "high": sum(1 for h in hosts if h.get("risk_level") == "HIGH"),
                          "medium": sum(1 for h in hosts if h.get("risk_level") == "MEDIUM"),
                          "low": sum(1 for h in hosts if h.get("risk_level") == "LOW")},
    }

    results["duration_seconds"] = round(time.time() - start, 1)
    logger.info("=== Network scan complete: %d hosts, %d ports, %d CVEs, risk=%s/%d in %.1fs ===",
                len(hosts), total_ports, total_cves, results["risk_level"], results["risk_score"],
                results["duration_seconds"])
    return results


def scan_host_deep(ip, scan_method="connect", include_udp=False):
    return scan_deep(ip, scan_method=scan_method, include_udp=include_udp)
