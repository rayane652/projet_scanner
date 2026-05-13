import ipaddress
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

from modules.port_scanner import scan_ports
from modules.service_detector import detect_service_and_version
from modules.cve_scanner import search_cves
from modules.web_scanner import scan_website

TOP_PORTS = [22, 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017]
MOBILE_PORTS = [5555, 4244, 3724, 5554, 8080, 8443, 9000]
IOT_PORTS = [1883, 8883, 5683, 5684, 4843, 22, 80, 443, 8080]
MEDIA_PORTS = [32400, 1900, 5353, 5004, 5005, 7000, 7001, 8000, 8890]
DISCOVERY_PORTS = list(set([22, 80, 443, 445, 3389, 8080, 8443, 5555, 32400, 1900, 5353, 1883, 5000, 7000, 8081, 9000]))
SCAN_TIMEOUT = 4
MAX_DISCOVERY_WORKERS = 30
MAX_ENUM_WORKERS = 10


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


def _ping(ip, timeout=2):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(["ping", param, "1", "-W", str(timeout), ip], capture_output=True, timeout=timeout+1, creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_check(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def _resolve_hostname(ip, timeout=2):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def _get_mac(ip):
    try:
        if platform.system().lower() == "windows":
            r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in r.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for p in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', p):
                            return p.upper()
        else:
            import re
            r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for p in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', p):
                            return p.upper()
    except Exception:
        pass
    return ""


VENDOR_TABLE = {
    # Apple
    "080007": ("Apple", "desktop"), "001124": ("Apple", "desktop"), "003065": ("Apple", "mobile"),
    "002325": ("Apple", "mobile"), "000A95": ("Apple", "mobile"), "001636": ("Apple", "mobile"),
    "001CB0": ("Apple", "tablet"), "00123D": ("Apple", "mobile"), "0016CB": ("Apple", "mobile"),
    "04A151": ("Apple", "mobile"), "002608": ("Apple", "mobile"), "983B8E": ("Apple", "mobile"),
    "F81EDF": ("Apple", "mobile"), "A40CC3": ("Apple", "mobile"), "70484B": ("Apple", "mobile"),
    "A88808": ("Apple", "desktop"), "B0E235": ("Apple", "desktop"), "F0F61C": ("Apple", "desktop"),
    "58723B": ("Apple", "tablet"), "A42B2C": ("Apple", "desktop"),
    # Samsung
    "00177A": ("Samsung", "mobile"), "0021CC": ("Samsung", "mobile"), "E03F49": ("Samsung", "mobile"),
    "0050B6": ("Samsung", "mobile"), "001E4F": ("Samsung", "mobile"), "0025A1": ("Samsung", "mobile"),
    "001EE6": ("Samsung", "mobile"), "A886DD": ("Samsung", "mobile"), "C8D15E": ("Samsung", "mobile"),
    "8C8CAA": ("Samsung", "mobile"), "34A3BF": ("Samsung", "mobile"), "B06685": ("Samsung", "mobile"),
    "44C9A2": ("Samsung", "mobile"), "3C0E6D": ("Samsung", "mobile"),
    # Huawei
    "00E0FC": ("Huawei", "mobile"), "001378": ("Huawei", "mobile"), "0C9D92": ("Huawei", "mobile"),
    "1C5C55": ("Huawei", "mobile"), "0C1D1E": ("Huawei", "mobile"), "98A98C": ("Huawei", "mobile"),
    "A4A64B": ("Huawei", "mobile"), "F8BF09": ("Huawei", "mobile"), "D8D22D": ("Huawei", "mobile"),
    "C89C1D": ("Huawei", "mobile"), "4C5FFC": ("Huawei", "router"),
    # Xiaomi
    "001E4E": ("Xiaomi", "mobile"), "002128": ("Xiaomi", "mobile"), "0409A0": ("Xiaomi", "mobile"),
    "18031F": ("Xiaomi", "mobile"), "48037D": ("Xiaomi", "mobile"), "78B8CD": ("Xiaomi", "mobile"),
    "C8C2C1": ("Xiaomi", "mobile"), "D0ADA1": ("Xiaomi", "mobile"), "F48C50": ("Xiaomi", "mobile"),
    "9CE374": ("Xiaomi", "iot"),
    # Google
    "00037F": ("Google", "mobile"), "001B11": ("Google", "mobile"), "A4C0E1": ("Google", "mobile"),
    "0C8DF6": ("Google", "mobile"), "886657": ("Google", "mobile"), "BCA51E": ("Google", "mobile"),
    "D8D385": ("Google", "iot"), "246990": ("Google", "router"),
    # Amazon
    "00BB01": ("Amazon", "iot"), "4013FF": ("Amazon", "iot"), "74C75B": ("Amazon", "iot"),
    "7CFE4E": ("Amazon", "iot"), "AC63BE": ("Amazon", "iot"), "B0802C": ("Amazon", "iot"),
    # Microsoft
    "0050F2": ("Microsoft", "desktop"), "001DD8": ("Microsoft", "desktop"), "00155D": ("Microsoft", "desktop"),
    "00248A": ("Microsoft", "desktop"), "0003FF": ("Microsoft", "desktop"),
    # Sony
    "000F1C": ("Sony", "tv"), "00134F": ("Sony", "tv"), "0024BE": ("Sony", "mobile"),
    "080046": ("Sony", "tv"), "3481C4": ("Sony", "tv"),
    # LG
    "001D64": ("LG", "tv"), "00213B": ("LG", "mobile"), "00E070": ("LG", "tv"),
    "4844F7": ("LG", "mobile"), "7CF1C0": ("LG", "tv"),
    # Panasonic
    "00059B": ("Panasonic", "tv"), "00188A": ("Panasonic", "tv"), "00A05D": ("Panasonic", "tv"),
    # Roku / Roku-like
    "001DDD": ("Roku", "tv"), "002469": ("Roku", "tv"), "0060DF": ("Roku", "tv"),
    # NVIDIA
    "0002A5": ("NVIDIA", "desktop"), "001C42": ("NVIDIA", "desktop"), "984B2C": ("NVIDIA", "desktop"),
    # Raspberry Pi
    "089EF0": ("Raspberry Pi", "iot"), "B827EB": ("Raspberry Pi", "iot"), "D83A1C": ("Raspberry Pi", "iot"),
    "E45F01": ("Raspberry Pi", "iot"),
    # TP-Link
    "005043": ("TP-Link", "router"), "1CB72C": ("TP-Link", "router"), "F81A67": ("TP-Link", "router"),
    "00223F": ("TP-Link", "router"), "A8D89C": ("TP-Link", "router"),
    # Netgear
    "001AA0": ("Netgear", "router"), "001E2A": ("Netgear", "router"), "00223F": ("Netgear", "router"),
    "080028": ("Netgear", "router"), "A022B8": ("Netgear", "router"),
    # Cisco
    "0004F2": ("Cisco", "network"), "00259C": ("Cisco", "network"), "001C0E": ("Cisco", "network"),
    "00504D": ("Cisco", "network"), "001B0C": ("Cisco", "network"),
    # VMware
    "000C29": ("VMware", "server"), "005056": ("VMware", "server"),
    # Intel
    "000347": ("Intel", "desktop"), "001C25": ("Intel", "desktop"), "0050B6": ("Intel", "desktop"),
    # Dell
    "0003FF": ("Dell", "desktop"), "0015D1": ("Dell", "desktop"), "00188B": ("Dell", "desktop"),
    "001150": ("Dell", "desktop"), "001EC0": ("Dell", "desktop"),
    # HP
    "0001C7": ("HP", "printer"), "002481": ("HP", "desktop"), "0017A4": ("HP", "printer"),
    "003048": ("HP", "printer"), "00A0C9": ("HP", "printer"),
    # IBM
    "000C41": ("IBM", "server"), "0050C2": ("IBM", "server"),
    # Juniper
    "000BDB": ("Juniper", "network"), "001B43": ("Juniper", "network"),
    # Arista
    "000C06": ("Arista", "network"),
    # Synology
    "001132": ("Synology", "nas"), "E03F49": ("Synology", "nas"),
    # QNAP
    "000FC9": ("QNAP", "nas"), "00248C": ("QNAP", "nas"),
    # Canon
    "001AE9": ("Canon", "printer"), "0025E8": ("Canon", "printer"), "00A0B4": ("Canon", "printer"),
    # Brother
    "001B06": ("Brother", "printer"), "0021A6": ("Brother", "printer"), "000321": ("Brother", "printer"),
    # Epson
    "00123F": ("Epson", "printer"), "000AAC": ("Epson", "printer"), "00A0C6": ("Epson", "printer"),
    # Sonos
    "000E58": ("Sonos", "iot"), "B8AEC4": ("Sonos", "iot"),
    # Philips Hue
    "001788": ("Philips", "iot"), "ECB5A2": ("Philips", "iot"),
    # Xiaomi IoT
    "9CE374": ("Xiaomi", "iot"),
    # Belkin / Wemo
    "00151A": ("Belkin", "iot"), "00253B": ("Belkin", "iot"),
    # Acer
    "0015E9": ("Acer", "desktop"), "4437E6": ("Acer", "desktop"), "2486F4": ("Acer", "desktop"),
    # Lenovo
    "001DDC": ("Lenovo", "desktop"), "00215C": ("Lenovo", "desktop"), "38229D": ("Lenovo", "desktop"),
    # Asus
    "0019CB": ("Asus", "router"), "0022B0": ("Asus", "desktop"), "00604B": ("Asus", "router"),
    # Xiaomi Router
    "C8C2C1": ("Xiaomi", "router"),
    # Bose
    "001C4A": ("Bose", "iot"), "00259E": ("Bose", "iot"),
    # Denon / Marantz
    "0022D3": ("Denon", "tv"), "000F94": ("Denon", "tv"),
    # Samsung TV
    "001EE6": ("Samsung", "tv"), "8C8CAA": ("Samsung", "tv"),
    # Vizio
    "00B29B": ("Vizio", "tv"), "001AE9": ("Vizio", "tv"),
    # Hisense
    "E8DE27": ("Hisense", "tv"), "0C1D1E": ("Hisense", "tv"),
    # TCL
    "3C0E6D": ("TCL", "tv"), "B0EAEA": ("TCL", "tv"),
    # Nintendo
    "001231": ("Nintendo", "console"), "002540": ("Nintendo", "console"), "8CADAB": ("Nintendo", "console"),
    # Microsoft Xbox
    "001D0B": ("Xbox", "console"), "0026C9": ("Xbox", "console"), "48ECA8": ("Xbox", "console"),
    # Sony PlayStation
    "0013C6": ("PlayStation", "console"), "0021E5": ("PlayStation", "console"), "00888E": ("PlayStation", "console"),
    "04C5A4": ("PlayStation", "console"), "F4CE46": ("PlayStation", "console"),
    # Hikvision
    "1C5C55": ("Hikvision", "iot"), "2C4FEE": ("Hikvision", "iot"),
    # Dahua
    "000E53": ("Dahua", "iot"), "48A16F": ("Dahua", "iot"),
    # Ring
    "8CA8CD": ("Ring", "iot"), "30A3B0": ("Ring", "iot"),
    # Nest
    "001F1F": ("Nest", "iot"), "18667A": ("Nest", "iot"),
    # Arlo
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


def discover_hosts(ips, progress_callback=None):
    discovered = []
    total = len(ips)
    done = [0]

    def check(ip):
        open_discovery_ports = [p for p in DISCOVERY_PORTS if _tcp_check(ip, p, 1)]
        alive = _ping(ip) or bool(open_discovery_ports)
        info = {"ip": ip, "alive": alive, "discovery_ports": open_discovery_ports[:5]}
        if alive:
            info["hostname"] = _resolve_hostname(ip)
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


def scan_light(ip, timeout=4):
    ports = []
    for port in TOP_PORTS:
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
                svc, ver, prod = detect_service_and_version(port, banner, "tcp")
                ports.append({"port": port, "protocol": "tcp", "state": "open", "service": svc, "version": ver, "product": prod, "banner": banner})
            else:
                s.close()
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
        svc, ver, prod = detect_service_and_version(port, banner, protocol)
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
        result["ports"].append({"port": port, "protocol": protocol, "state": p.get("state", "open"), "service": svc, "version": ver, "product": prod, "banner": banner, "cves": cves})
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


def run_network_scan(targets_raw, profile="quick", scan_method="connect", include_udp=False, progress_callback=None):
    start = time.time()
    ips = parse_targets(targets_raw)
    if not ips:
        return {"error": "Could not parse any valid targets", "targets_raw": targets_raw}

    is_subnet = len(ips) > 1
    results = {"targets_raw": targets_raw, "type": "network", "profile": profile, "is_subnet": is_subnet, "total_targets": len(ips), "live_count": 0, "hosts": [], "discovery": [], "duration_seconds": 0, "phases": {}}

    if progress_callback:
        progress_callback(0, len(ips), "", False, "discovering")

    discovered = discover_hosts(ips, progress_callback)
    results["discovery"] = discovered
    results["live_count"] = len(discovered)
    results["phases"]["discovery"] = round(time.time() - start, 1)

    if not discovered:
        results["duration_seconds"] = round(time.time() - start, 1)
        return results

    # Phase 2: lightweight enum (always runs)
    if progress_callback:
        progress_callback(0, len(discovered), "", False, "enumerating")

    hosts = []
    lock = threading.Lock()
    done = [0]

    def enum_one(host):
        light = scan_light(host["ip"])
        vname, dtype = _classify_device(host["ip"], host.get("hostname", ""), host.get("mac", ""), host.get("vendor", ""), light)
        with lock:
            hosts.append({"ip": host["ip"], "hostname": host.get("hostname", ""), "mac": host.get("mac", ""), "vendor": vname, "device_type": dtype or host.get("device_type", "unknown"), "alive": True, "ports": light, "cves": [], "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "risk_score": 0, "scanned": True, "deep_available": True})
            done[0] += 1
            if progress_callback:
                progress_callback(done[0], len(discovered), host["ip"], True, "enumerating")

    if profile == "quick":
        for h in discovered:
            enum_one(h)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_ENUM_WORKERS) as ex:
            ex.map(enum_one, discovered)

    hosts.sort(key=lambda h: len(h.get("ports", [])), reverse=True)
    results["hosts"] = hosts
    results["phases"]["enumeration"] = round(time.time() - start, 1)

    # Phase 3: deep scan only for Balanced/Deep profiles
    if profile in ("balanced", "deep"):
        if progress_callback:
            progress_callback(0, len(hosts), "", False, "deep_scan")

        deep_done = [0]
        def deep_one(host):
            deep = scan_deep(host["ip"], scan_method=scan_method, include_udp=include_udp)
            with lock:
                host["ports"] = deep.get("ports", host["ports"])
                host["cves"] = deep.get("cves", [])
                host["severity_counts"] = deep.get("severity_counts", host["severity_counts"])
                host["risk_score"] = deep.get("risk_score", 0)
                host["web"] = deep.get("web")
                host["deep_available"] = False
                deep_done[0] += 1
                if progress_callback:
                    progress_callback(deep_done[0], len(hosts), host["ip"], True, "deep_scan")

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(hosts))) as ex:
            ex.map(deep_one, hosts)
        results["phases"]["deep_scan"] = round(time.time() - start, 1)

    # Aggregate stats
    agg_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_cves = 0
    total_ports = 0
    port_freq = defaultdict(int)
    svc_freq = defaultdict(int)
    for h in hosts:
        for k in agg_counts:
            agg_counts[k] += h.get("severity_counts", {}).get(k, 0)
        total_cves += len(h.get("cves", []))
        for p in h.get("ports", []):
            total_ports += 1
            port_freq[p.get("port")] += 1
            svc_freq[p.get("service", "unknown")] += 1
        h.pop("severity_counts", None)

    results["aggregated"] = {
        "severity_counts": agg_counts,
        "total_cves": total_cves,
        "total_ports": total_ports,
        "top_ports": sorted([{"port": k, "count": v} for k, v in port_freq.items()], key=lambda x: -x["count"])[:10],
        "top_services": sorted([{"service": k, "count": v} for k, v in svc_freq.items()], key=lambda x: -x["count"])[:10],
    }
    results["duration_seconds"] = round(time.time() - start, 1)
    return results


def scan_host_deep(ip, scan_method="connect", include_udp=False):
    return scan_deep(ip, scan_method=scan_method, include_udp=include_udp)
