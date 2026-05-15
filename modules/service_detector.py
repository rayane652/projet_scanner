import re

PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 500: "isakmp",
    587: "smtp", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
    6379: "redis", 8000: "http", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 1900: "ssdp", 5353: "mdns", 5555: "adb",
    27017: "mongodb", 11211: "memcached", 3000: "http-alt",
    5000: "http-alt", 9000: "http-alt", 8081: "http-alt",
    8888: "http-alt", 9090: "http-alt", 10000: "http-alt",
    6000: "x11", 6667: "irc", 6697: "ircs", 8443: "https-alt",
    10050: "zabbix-agent", 10051: "zabbix-trapper", 2000: "cisco-sccp",
    5060: "sip", 5061: "sips", 5222: "xmpp", 5269: "xmpp-server",
    5443: "https-alt", 5500: "vnc", 5601: "kibana", 5672: "amqp",
    6080: "http-alt", 61616: "activemq", 7001: "weblogic", 7070: "http-alt",
    8089: "splunkd", 8444: "https-alt", 8787: "http-alt",
    9443: "https-alt", 9999: "http-alt",
}

BARE_PRODUCTS = {
    1433: "Microsoft SQL Server", 1521: "Oracle Database",
    3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
    11211: "Memcached", 5601: "Kibana", 5672: "RabbitMQ",
    61616: "ActiveMQ", 7001: "Oracle WebLogic", 8089: "Splunk",
    5000: "HTTP API", 3000: "HTTP API", 9000: "HTTP API",
    6000: "X11", 6667: "IRC", 6697: "IRCS",
}

PRODUCT_PATTERNS = [
    ("http", r"apache(?:/?|\s+)([\w\.\-:+~]+)?", "Apache", "apache"),
    ("http", r"nginx(?:/?|\s+)([\w\.\-:+~]+)?", "Nginx", "nginx"),
    ("http", r"cloudflare", "Cloudflare", "cloudflare"),
    ("http", r"microsoft-iis(?:/?|\s+)([\w\.\-:+~]+)?", "Microsoft IIS", "iis"),
    ("http", r"apache-coyote(?:/?|\s*)([\w\.\-:+~]+)?", "Apache Tomcat", "tomcat"),
    ("http", r"tomcat", "Apache Tomcat", "tomcat"),
    ("http", r"jetty", "Jetty", "jetty"),
    ("http", r"caddy", "Caddy", "caddy"),
    ("http", r"lighttpd", "Lighttpd", "lighttpd"),
    ("http", r"openresty", "OpenResty", "openresty"),
    ("http", r"gunicorn", "Gunicorn", "gunicorn"),
    ("http", r"wsgiref", "WSGIReference", "python"),
    ("http", r"python", "Python", "python"),
    ("http", r"node\.?js", "Node.js", "nodejs"),
    ("http", r"express", "Express.js", "expressjs"),
    ("http", r"php(?:/?|\s+)([\w\.\-:+~]+)?", "PHP", "php"),
    ("http", r"x-powered-by:\s*php(?:/?|\s+)([\w\.\-:+~]+)?", "PHP", "php"),
    ("http", r"x-powered-by:\s*express", "Express.js", "expressjs"),
    ("http", r"x-powered-by:\s*asp\.net", "ASP.NET", "aspnet"),
    ("http", r"x-aspnet-version", "ASP.NET", "aspnet"),
    ("http", r"x-powered-by:\s*rails", "Ruby on Rails", "rails"),
    ("http", r"x-powered-by:\s*openresty", "OpenResty", "openresty"),
    ("http", r"x-generator:\s*drupal", "Drupal", "drupal"),
    ("http", r"x-generator:\s*wordpress", "WordPress", "wordpress"),
    ("http", r"x-drupal", "Drupal", "drupal"),
    ("http", r"wp-json", "WordPress", "wordpress"),
    ("http", r"wp-content", "WordPress", "wordpress"),
    ("http", r"laravel_session", "Laravel", "laravel"),
    ("http", r"laravel", "Laravel", "laravel"),
    ("http", r"symfony", "Symfony", "symfony"),
    ("http", r"django", "Django", "django"),
    ("http", r"flask", "Flask", "flask"),
    ("http", r"react", "React", "react"),
    ("http", r"vue\.?js", "Vue.js", "vuejs"),
    ("http", r"angular", "Angular", "angular"),
    ("http", r"next\.?js", "Next.js", "nextjs"),
    ("http", r"nuxt\.?js", "Nuxt.js", "nuxtjs"),
    ("http", r"jquery", "jQuery", "jquery"),
    ("http", r"bootstrap", "Bootstrap", "bootstrap"),
    ("http", r"tailwind", "Tailwind CSS", "tailwind"),
    ("http", r"shopify", "Shopify", "shopify"),
    ("http", r"magento", "Magento", "magento"),
    ("http", r"joomla", "Joomla", "joomla"),
    ("http", r"atlassian", "Atlassian", "atlassian"),
    ("http", r"confluence", "Confluence", "confluence"),
    ("http", r"jira", "JIRA", "jira"),
    ("http", r"varnish", "Varnish", "varnish"),
    ("http", r"haproxy", "HAProxy", "haproxy"),
    ("http", r"akamai", "Akamai", "akamai"),
    ("http", r"cloudfront", "CloudFront", "cloudfront"),
    ("http", r"fastly", "Fastly", "fastly"),
    ("ssh", r"openssh[_\s/-]*([\w\.\-p:+~]+)?", "OpenSSH", "openssh"),
    ("ssh", r"ssh-\d\.\d-openssh[_\s/-]*([\w\.\-p:+~]+)?", "OpenSSH", "openssh"),
    ("ssh", r"dropbear[_\s/-]*([\w\.\-p:+~]+)?", "Dropbear SSH", "dropbear"),
    ("ftp", r"vsftpd\s*([\w\.\-:+~]+)?", "vsftpd", "vsftpd"),
    ("ftp", r"proftpd\s*([\w\.\-:+~]+)?", "ProFTPD", "proftpd"),
    ("ftp", r"pure-?ftpd\s*([\w\.\-:+~]+)?", "Pure-FTPd", "pureftpd"),
    ("ftp", r"filezilla", "FileZilla", "filezilla"),
    ("ftp", r"microsoft ftp", "Microsoft FTP", "msftp"),
    ("smtp", r"postfix\s*([\w\.\-:+~]+)?", "Postfix", "postfix"),
    ("smtp", r"exim\s*([\w\.\-:+~]+)?", "Exim", "exim"),
    ("smtp", r"sendmail\s*([\w\.\-:+~]+)?", "Sendmail", "sendmail"),
    ("smtp", r"qmail", "Qmail", "qmail"),
    ("smtp", r"courier", "Courier", "courier"),
    ("smtp", r"microsoft esmtp", "Microsoft ESMTP", "msesmtp"),
    ("mysql", r"mysql\s*([\w\.\-:+~]+)?", "MySQL", "mysql"),
    ("mysql", r"mariadb\s*([\w\.\-:+~]+)?", "MariaDB", "mariadb"),
    ("postgresql", r"postgresql\s*([\w\.\-:+~]+)?", "PostgreSQL", "postgresql"),
    ("redis", r"redis\s*([\w\.\-:+~]+)?", "Redis", "redis"),
    ("mongodb", r"mongodb\s*([\w\.\-:+~]+)?", "MongoDB", "mongodb"),
    ("vnc", r"rfb\s*([\w\.\-:+~]+)?", "VNC", "vnc"),
    ("vnc", r"tightvnc", "TightVNC", "tightvnc"),
    ("vnc", r"realvnc", "RealVNC", "realvnc"),
    ("snmp", r"snmp", "SNMP", "snmp"),
    ("dns", r"bind\s*([\w\.\-]+)?", "BIND", "bind"),
    ("dns", r"dnsmasq", "Dnsmasq", "dnsmasq"),
    ("dns", r"unbound", "Unbound", "unbound"),
    ("http", r"microsoft-http-api/?\s*([\w\.\-:+~]+)?", "Microsoft HTTP API", "mshttp"),
    ("smtp", r"esmtp", "ESMTP", "esmtp"),
    ("ftp", r"wu-?ftpd", "WU-FTPD", "wuftpd"),
    ("http", r"weblogic", "Oracle WebLogic", "weblogic"),
    ("http", r"jboss", "JBoss", "jboss"),
    ("http", r"wildfly", "WildFly", "wildfly"),
    ("http", r"glassfish", "GlassFish", "glassfish"),
    ("http", r"payara", "Payara", "payara"),
    ("redis", r"elasticache", "Amazon ElastiCache Redis", "elasticache"),
]

OS_PATTERNS = [
    (r"ubuntu", "Ubuntu Linux", "Linux"),
    (r"debian", "Debian Linux", "Linux"),
    (r"centos", "CentOS Linux", "Linux"),
    (r"red hat", "Red Hat Enterprise Linux", "Linux"),
    (r"rhel", "Red Hat Enterprise Linux", "Linux"),
    (r"fedora", "Fedora Linux", "Linux"),
    (r"rocky linux", "Rocky Linux", "Linux"),
    (r"almalinux", "AlmaLinux", "Linux"),
    (r"amazon linux", "Amazon Linux", "Linux"),
    (r"opensuse", "openSUSE", "Linux"),
    (r"suse linux", "SUSE Linux", "Linux"),
    (r"kali", "Kali Linux", "Linux"),
    (r"parrot", "Parrot OS", "Linux"),
    (r"blackarch", "BlackArch Linux", "Linux"),
    (r"arch linux", "Arch Linux", "Linux"),
    (r"manjaro", "Manjaro Linux", "Linux"),
    (r"alpine linux", "Alpine Linux", "Linux"),
    (r"alpine", "Alpine Linux", "Linux"),
    (r"metasploitable", "Metasploitable", "Linux"),
    (r"android", "Android", "Android"),
    (r"windows server 2025", "Windows Server 2025", "Windows"),
    (r"windows server 2022", "Windows Server 2022", "Windows"),
    (r"windows server 2019", "Windows Server 2019", "Windows"),
    (r"windows server 2016", "Windows Server 2016", "Windows"),
    (r"windows server 2012", "Windows Server 2012", "Windows"),
    (r"windows server 2008", "Windows Server 2008", "Windows"),
    (r"windows 11", "Windows 11", "Windows"),
    (r"windows 10", "Windows 10", "Windows"),
    (r"windows 8", "Windows 8", "Windows"),
    (r"windows 7", "Windows 7", "Windows"),
    (r"windows vista", "Windows Vista", "Windows"),
    (r"windows xp", "Windows XP", "Windows"),
    (r"microsoft windows", "Windows", "Windows"),
    (r"freebsd", "FreeBSD", "FreeBSD"),
    (r"openbsd", "OpenBSD", "OpenBSD"),
    (r"netbsd", "NetBSD", "NetBSD"),
    (r"darwin", "macOS", "macOS"),
    (r"mac os", "macOS", "macOS"),
    (r"apple", "macOS", "macOS"),
    (r"solaris", "Solaris", "Solaris"),
    (r"sunos", "Solaris", "Solaris"),
    (r"aix", "IBM AIX", "AIX"),
    (r"hp-ux", "HP-UX", "HP-UX"),
    (r"irix", "IRIX", "IRIX"),
    (r"openwrt", "OpenWrt", "Linux"),
    (r"dd-wrt", "DD-WRT", "Linux"),
    (r"tomato", "Tomato", "Linux"),
    (r"pfsense", "pfSense", "FreeBSD"),
    (r"opnsense", "OPNsense", "FreeBSD"),
    (r"vyos", "VyOS", "Linux"),
    (r"sonos", "Sonos", "Linux"),
    (r"synology", "Synology DSM", "Linux"),
    (r"qnap", "QNAP QTS", "Linux"),
    (r"unraid", "Unraid", "Linux"),
    (r"truenas", "TrueNAS", "FreeBSD"),
    (r"proxmox", "Proxmox VE", "Linux"),
    (r"esxi", "VMware ESXi", "VMware"),
    (r"vcenter", "VMware vCenter", "Linux"),
    (r"xen", "Xen Server", "Linux"),
    (r"nutanix", "Nutanix", "Linux"),
]


def _clean_version(version):
    if not version:
        return ""
    text = version.strip(" /;,_-()[]")
    match = re.search(r"\d+(?:\.\d+){0,5}(?:[a-z]\d*)?", text, re.IGNORECASE)
    return match.group(0) if match else text


def _mysql_banner_version(banner_lower):
    if "mariadb" in banner_lower:
        match = re.search(r"5\.5\.5-(\d+(?:\.\d+){1,4})-mariadb", banner_lower)
        if match:
            return "MariaDB", match.group(1), "mariadb"
        match = re.search(r"(\d+(?:\.\d+){1,4})-mariadb", banner_lower)
        if match:
            return "MariaDB", match.group(1), "mariadb"
    match = re.match(r"\D*(\d+(?:\.\d+){1,4})", banner_lower)
    if match:
        return "MySQL", match.group(1), "mysql"
    return "", "", ""


def detect_os_from_banners(banners_text, ports, os_hints):
    combined = " ".join(banners_text).lower()
    detected_name = ""
    detected_family = ""
    confidence = "Low"

    for pattern, name, family in OS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            detected_name = name
            detected_family = family
            confidence = "High"
            break

    if not detected_name:
        if 5555 in ports:
            detected_name = "Android"
            detected_family = "Android"
            confidence = "Medium"
        elif {135, 139, 445, 3389, 5985, 5986} & ports:
            detected_name = "Windows"
            detected_family = "Windows"
            confidence = "Medium"
        elif os_hints:
            hint = os_hints[0]
            if "Windows" in hint:
                detected_name = "Windows"
                detected_family = "Windows"
                confidence = "Medium"
            elif "Linux" in hint or "Unix" in hint:
                detected_name = "Linux/Unix"
                detected_family = "Linux"
                confidence = "Medium"

    if not detected_name and {21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379} & ports:
        detected_name = "Linux/Unix"
        detected_family = "Linux"
        confidence = "Low"

    return detected_name, detected_family, confidence


def detect_service_and_version(port, banner, protocol="tcp", headers=None):
    banner_text = banner or ""
    banner_lower = banner_text.lower()
    guessed_service = PORT_SERVICES.get(port, "unknown")
    product_name = ""
    product_version = ""
    product_key = ""
    confidence = "low"

    if port == 3306:
        mysql_product, mysql_version, mysql_key = _mysql_banner_version(banner_lower)
        if mysql_product:
            return "mysql", mysql_version, mysql_product, "high"

    for service, pattern, product, key in PRODUCT_PATTERNS:
        match = re.search(pattern, banner_lower, re.IGNORECASE)
        if match:
            version = _clean_version(match.group(1) if match.groups() else "")
            confidence = "high" if version else "medium"
            return service, version, product, confidence

    if "ssh" in banner_lower:
        return "ssh", "", "", "medium"
    if "ftp" in banner_lower:
        return "ftp", "", "", "medium"
    if "smtp" in banner_lower or "mail" in banner_lower:
        return "smtp", "", "", "medium"
    if "http/" in banner_lower or "server:" in banner_lower:
        return "http", "", "", "medium"
    if "pop3" in banner_lower or "pop" in banner_lower:
        return "pop3", "", "", "medium"
    if "imap" in banner_lower:
        return "imap", "", "", "medium"

    if protocol == "udp":
        if port == 53:
            return "dns", "", "", "medium"
        if port == 123:
            return "ntp", "", "", "medium"
        if port == 161:
            return "snmp", "", "", "medium"
        if port == 1900:
            return "ssdp", "", "", "medium"
        if port == 5353:
            return "mdns", "", "", "medium"

    product_name = BARE_PRODUCTS.get(port, "")
    if product_name:
        confidence = "medium"

    return guessed_service, "", product_name, confidence


def detect_web_technologies(headers, html, cookies):
    techs = []
    seen = set()

    server = (headers.get("Server") or "").lower()
    powered = (headers.get("X-Powered-By") or "").lower()
    html_lower = html.lower()
    set_cookie = str(headers.get("Set-Cookie", "")).lower()
    combined = f"{server} {powered} {html_lower} {set_cookie} "
    if cookies:
        combined += " ".join(c.name.lower() for c in cookies)

    for keyword, label, key in [
        ("wordpress", "WordPress", "wordpress"),
        ("wp-content", "WordPress", "wordpress"),
        ("wp-json", "WordPress", "wordpress"),
        ("laravel", "Laravel", "laravel"),
        ("laravel_session", "Laravel", "laravel"),
        ("drupal", "Drupal", "drupal"),
        ("joomla", "Joomla", "joomla"),
        ("magento", "Magento", "magento"),
        ("shopify", "Shopify", "shopify"),
        ("django", "Django", "django"),
        ("flask", "Flask", "flask"),
        ("symfony", "Symfony", "symfony"),
        ("react", "React", "react"),
        ("vue.js", "Vue.js", "vuejs"),
        ("vuejs", "Vue.js", "vuejs"),
        ("angular", "Angular", "angular"),
        ("next.js", "Next.js", "nextjs"),
        ("nuxt.js", "Nuxt.js", "nuxtjs"),
        ("jquery", "jQuery", "jquery"),
        ("bootstrap", "Bootstrap", "bootstrap"),
        ("tailwind", "Tailwind CSS", "tailwind"),
        ("express", "Express.js", "expressjs"),
        ("node.js", "Node.js", "nodejs"),
        ("node_modules", "Node.js", "nodejs"),
        ("tomcat", "Apache Tomcat", "tomcat"),
        ("jboss", "JBoss", "jboss"),
        ("weblogic", "Oracle WebLogic", "weblogic"),
        ("php", "PHP", "php"),
        ("phpmyadmin", "phpMyAdmin", "phpmyadmin"),
        ("adminer", "Adminer", "adminer"),
        ("asp.net", "ASP.NET", "aspnet"),
        ("sharepoint", "SharePoint", "sharepoint"),
        ("cloudflare", "Cloudflare", "cloudflare"),
        ("nginx", "Nginx", "nginx"),
        ("apache", "Apache", "apache"),
        ("iis", "IIS", "iis"),
        ("caddy", "Caddy", "caddy"),
        ("haproxy", "HAProxy", "haproxy"),
        ("varnish", "Varnish", "varnish"),
        ("graphql", "GraphQL", "graphql"),
        ("swagger", "Swagger", "swagger"),
        ("sentry", "Sentry", "sentry"),
        ("datadog", "Datadog", "datadog"),
        ("newrelic", "New Relic", "newrelic"),
        ("google analytics", "Google Analytics", "ganalytics"),
        ("recaptcha", "reCAPTCHA", "recaptcha"),
        ("hotjar", "Hotjar", "hotjar"),
        ("cdn", "CDN", "cdn"),
        ("akamai", "Akamai", "akamai"),
        ("fastly", "Fastly", "fastly"),
        ("cloudfront", "CloudFront", "cloudfront"),
    ]:
        if keyword in combined and key not in seen:
            conf = "high" if (keyword in server or keyword in powered) else "medium"
            techs.append({"name": label, "confidence": conf, "evidence": f"Matched keyword: {keyword}"})
            seen.add(key)

    for cookie in (cookies or []):
        if cookie.name.lower() in ("phpsessid",):
            if "php" not in seen:
                techs.append({"name": "PHP", "confidence": "high", "evidence": "Cookie: PHPSESSID"})
                seen.add("php")
        elif cookie.name.lower() in ("jsessionid",):
            if "tomcat" not in seen:
                techs.append({"name": "Apache Tomcat", "confidence": "high", "evidence": "Cookie: JSESSIONID"})
                seen.add("tomcat")
        elif cookie.name.lower() in ("aspsessionid", ".aspxauth", "asp.net_sessionid"):
            if "aspnet" not in seen:
                techs.append({"name": "ASP.NET", "confidence": "high", "evidence": f"Cookie: {cookie.name}"})
                seen.add("aspnet")
        elif cookie.name.lower() in ("laravel_session",):
            if "laravel" not in seen:
                techs.append({"name": "Laravel", "confidence": "high", "evidence": "Cookie: laravel_session"})
                seen.add("laravel")

    return techs
