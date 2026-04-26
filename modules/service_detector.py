import re

def detect_service_and_version(port, banner):
    banner = (banner or "").lower()

    # FTP
    if port == 21 or "ftp" in banner:
        m = re.search(r"vsftpd\s*([\d\.]+)", banner)
        if m:
            return "ftp", m.group(1), "vsftpd"

    # SSH
    if port == 22 or "ssh" in banner:
        m = re.search(r"openssh[_\s]?([\d\.]+)", banner)
        if m:
            return "ssh", m.group(1), "openssh"

    # SMTP
    if port == 25 or "postfix" in banner:
        return "smtp", "", "postfix"

    # HTTP
    if port == 80:
        return "http", "", "http"

    return "unknown", "", ""
