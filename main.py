from modules.port_scanner import scan_ports
from modules.web_scanner import scan_website
from modules.cve_scanner import search_cves
from modules.utils import resolve_host

def main():
    print("1. Discover Network")
    print("2. Port Scan")
    print("3. Web Scan")
    print("4. CVE Search")
    
    choice = input("Choose: ")

    if choice == "1":
        network = input("Enter network (default 192.168.1.0/24): ")
        if not network:
            network = "192.168.1.0/24"

        discover_network(network)
    elif choice == "2":
        target = input("Target IP or domain: ")
        ip = resolve_host(target)

        if not ip:
            print("Invalid target")
            return

        print(f"Scanning {ip}...")
        results = scan_ports(ip)

        for r in results:
            print(f"Port {r['port']} OPEN | {r['banner']}")

    elif choice == "3":
        url = input("Enter URL (http://...): ")
        result = scan_website(url)

        for k, v in result.items():
            print(f"{k}: {v}")

    elif choice == "4":
        keyword = input("Enter service (e.g. apache, ssh): ")
        results = search_cves(keyword)

        for r in results:
            print(f"{r['cve']} - {r['description']}")
    
if __name__ == "__main__":
    main()
