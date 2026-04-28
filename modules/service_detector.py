import re


PORT_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    8000: "http",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    5555: "adb",
    27017: "mongodb",
}

PORT_PRODUCTS = {
    1433: "microsoft sql server",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9200: "elasticsearch",
    27017: "mongodb",
}

PRODUCT_PATTERNS = [
    ("http", r"server:\s*apache/?\s*([\w\.\-]+)?", "apache"),
    ("http", r"apache/?\s*([\w\.\-]+)?", "apache"),
    ("http", r"server:\s*nginx/?\s*([\w\.\-]+)?", "nginx"),
    ("http", r"nginx/?\s*([\w\.\-]+)?", "nginx"),
    ("http", r"microsoft-iis/?\s*([\w\.\-]+)?", "microsoft iis"),
    ("http", r"apache-coyote/?\s*([\w\.\-]+)?", "apache tomcat"),
    ("ssh", r"openssh[_\s-]*([\w\.\-]+)?", "openssh"),
    ("ftp", r"vsftpd\s*([\w\.\-]+)?", "vsftpd"),
    ("ftp", r"proftpd\s*([\w\.\-]+)?", "proftpd"),
    ("smtp", r"postfix", "postfix"),
    ("smtp", r"exim\s*([\w\.\-]+)?", "exim"),
    ("mysql", r"mysql\s*([\w\.\-]+)?", "mysql"),
    ("mysql", r"mariadb\s*([\w\.\-]+)?", "mariadb"),
    ("postgresql", r"postgresql\s*([\w\.\-]+)?", "postgresql"),
    ("redis", r"redis\s*([\w\.\-]+)?", "redis"),
    ("mongodb", r"mongodb\s*([\w\.\-]+)?", "mongodb"),
]


def _clean_version(version):
    if not version:
        return ""
    return version.strip(" /;,_-()[]")


def detect_service_and_version(port, banner):
    banner_text = banner or ""
    banner_lower = banner_text.lower()
    guessed_service = PORT_SERVICES.get(port, "unknown")

    for service, pattern, product in PRODUCT_PATTERNS:
        match = re.search(pattern, banner_lower, re.IGNORECASE)
        if match:
            version = _clean_version(match.group(1) if match.groups() else "")
            return service, version, product

    if "ssh" in banner_lower:
        return "ssh", "", "ssh"
    if "ftp" in banner_lower:
        return "ftp", "", "ftp"
    if "smtp" in banner_lower or "mail" in banner_lower:
        return "smtp", "", "smtp"
    if "http/" in banner_lower or "server:" in banner_lower:
        return "http", "", "http"

    product = PORT_PRODUCTS.get(port, "")
    return guessed_service, "", product
