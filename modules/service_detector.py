import re

def detect_service_and_version(port, banner):
    banner = banner.lower()

    # FTP
    if port == 21 or "ftp" in banner:
        m = re.search(r"vsftpd\s*([\d\.]+)", banner)
        if m:
            return "ftp", m.group(1), "vsftpd"

    # SSH
    if port == 22 or "ssh" in banner:
        m = re.search(r"openssh[_\s]?([\d\.p]+)", banner)
        if m:
            version = m.group(1).replace("p", "")
            return "ssh", version, "openssh"

    # SMTP (Postfix)
    if port == 25 or "postfix" in banner:
        return "smtp", "", "postfix"

    # HTTP
    if port == 80:
        return "http", "", "apache"

    return "unknown", "", ""
