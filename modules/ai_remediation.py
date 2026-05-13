"""
ai_remediation.py — VulniX Auto-Fix Engine
Priority: static library → OpenRouter AI (with model fallbacks) → recommendation fallback
"""

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"

# Multiple fallback models — tries each one until one works
MODEL_FALLBACKS = [
    "qwen/qwen-2.5-7b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "google/gemma-2-9b-it:free",
    "mistralai/mistral-7b-instruct:free",
]

MAX_WORKERS  = 4
MAX_TOKENS   = 700
TEMPERATURE  = 0.3


# ─────────────────────────────────────────────────────────────────────────────
#  Static fix library — instant, zero API cost
# ─────────────────────────────────────────────────────────────────────────────

_STATIC = {
    # ── Web security headers ──────────────────────────────────────────────────
    "x-frame-options": {
        "title":       "Add X-Frame-Options header",
        "explanation": "Missing X-Frame-Options allows attackers to embed your page in an iframe for clickjacking attacks.",
        "impact":      "Users can be tricked into clicking hidden UI elements, leading to credential theft or unwanted actions.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx: add inside server {} block ─────────────\nadd_header X-Frame-Options \"DENY\" always;\n\n# ── Apache: .htaccess or VirtualHost ───────────────\nHeader always set X-Frame-Options DENY",
    },
    "content-security-policy": {
        "title":       "Add Content-Security-Policy header",
        "explanation": "A CSP header tells the browser which sources to trust, blocking XSS and data injection.",
        "impact":      "Without CSP, injected scripts can steal cookies, redirect users, or silently exfiltrate data.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx ──────────────────────────────────────────\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'\" always;\n\n# ── Apache ─────────────────────────────────────────\nHeader always set Content-Security-Policy \"default-src 'self'\"",
    },
    "x-content-type": {
        "title":       "Add X-Content-Type-Options header",
        "explanation": "Without this header, browsers may MIME-sniff responses and execute unexpected content types.",
        "impact":      "An attacker can upload a file that the browser treats as executable script.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx ──────────────────────────────────────────\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# ── Apache ─────────────────────────────────────────\nHeader always set X-Content-Type-Options nosniff",
    },
    "strict-transport-security": {
        "title":       "Enable HSTS",
        "explanation": "HSTS forces all connections over HTTPS, preventing SSL-stripping and downgrade attacks.",
        "impact":      "An on-path attacker can silently downgrade to HTTP and read all traffic.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx ──────────────────────────────────────────\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# ── Apache ─────────────────────────────────────────\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
    },
    "referrer-policy": {
        "title":       "Add Referrer-Policy header",
        "explanation": "Controls how much URL info is sent in Referer headers, preventing internal path leaks.",
        "impact":      "Sensitive paths or tokens in URLs may leak to third-party analytics or CDN providers.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx ──────────────────────────────────────────\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n# ── Apache ─────────────────────────────────────────\nHeader always set Referrer-Policy \"strict-origin-when-cross-origin\"",
    },
    "permissions-policy": {
        "title":       "Add Permissions-Policy header",
        "explanation": "Disables browser APIs (camera, mic, geolocation) that your app does not use.",
        "impact":      "Malicious injected scripts could silently access sensitive hardware APIs.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx ──────────────────────────────────────────\nadd_header Permissions-Policy \"geolocation=(), microphone=(), camera=(), payment=()\" always;\n\n# ── Apache ─────────────────────────────────────────\nHeader always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
    },
    "server header": {
        "title":       "Hide Server version header",
        "explanation": "The Server header reveals your software and version, helping attackers pick targeted exploits.",
        "impact":      "Attackers fingerprint the stack and search for version-specific CVEs in public databases.",
        "commands":    ["sudo nginx -t && sudo systemctl reload nginx"],
        "config":      "# ── Nginx ──────────────────────────────────────────\nserver_tokens off;\n\n# ── Apache: httpd.conf or apache2.conf ─────────────\nServerTokens Prod\nServerSignature Off",
    },
    # ── SSH ───────────────────────────────────────────────────────────────────
    "permitrootlogin": {
        "title":       "Disable SSH root login",
        "explanation": "Direct root SSH means an attacker only needs one credential — no privilege escalation needed.",
        "impact":      "Brute-force or credential-stuffing gives immediate root access with no further steps.",
        "commands":    [
            "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            "sudo sshd -t && sudo systemctl restart sshd",
        ],
        "config":      "# ── /etc/ssh/sshd_config ───────────────────────────\nPermitRootLogin no\nMaxAuthTries 3\nLoginGraceTime 30",
    },
    "passwordauthentication": {
        "title":       "Disable SSH password auth, use keys",
        "explanation": "Password auth is brute-forceable offline. Key-based auth uses cryptographic proof instead.",
        "impact":      "Weak or reused passwords can be cracked and provide full shell access.",
        "commands":    [
            "# Ensure your public key is in ~/.ssh/authorized_keys first!",
            "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "sudo sshd -t && sudo systemctl restart sshd",
        ],
        "config":      "# ── /etc/ssh/sshd_config ───────────────────────────\nPasswordAuthentication no\nChallengeResponseAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys",
    },
    "ssh protocol": {
        "title":       "Enforce SSH Protocol 2 only",
        "explanation": "SSH Protocol 1 has known cryptographic weaknesses trivially broken with modern tools.",
        "impact":      "An attacker on the network can decrypt Protocol 1 sessions in real time.",
        "commands":    [
            "sudo sed -i '/^Protocol/d' /etc/ssh/sshd_config",
            "echo 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ],
        "config":      "# ── /etc/ssh/sshd_config ───────────────────────────\nProtocol 2\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
    },
    # ── Package updates ───────────────────────────────────────────────────────
    "package update": {
        "title":       "Apply all pending package updates",
        "explanation": "Outdated packages contain public CVEs with ready-made exploits.",
        "impact":      "Known vulnerabilities in unpatched packages are the leading cause of breaches.",
        "commands":    [
            "# Debian / Ubuntu",
            "sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y",
            "sudo apt autoremove -y",
            "# RHEL / CentOS / Rocky",
            "sudo dnf update -y --security",
            "sudo reboot",
        ],
        "config":      "# ── /etc/apt/apt.conf.d/50unattended-upgrades ──────\nUnattended-Upgrade::Allowed-Origins {\n    \"${distro_id}:${distro_codename}-security\";\n};\nUnattended-Upgrade::Remove-Unused-Dependencies \"true\";",
    },
    "missing update": {
        "title":       "Install missing security patches",
        "explanation": "Security patches fix known vulnerabilities. Every day unpatched increases exposure.",
        "impact":      "Attackers actively scan for unpatched hosts using CVE databases and exploit kits.",
        "commands":    [
            "sudo apt update && sudo apt upgrade -y",
            "sudo apt autoremove -y",
        ],
        "config":      "",
    },
    "missing windows update": {
        "title":       "Install missing Windows updates",
        "explanation": "Missing Windows updates leave known CVEs unpatched on the host.",
        "impact":      "Attackers exploit publicly known vulnerabilities — patching is the highest-ROI security action.",
        "commands":    [
            "# PowerShell: install all pending updates",
            "Install-Module PSWindowsUpdate -Force -Confirm:$false",
            "Get-WindowsUpdate -Install -AcceptAll -AutoReboot",
            "# Or via Windows Update settings",
            "Start-Process ms-settings:windowsupdate",
        ],
        "config":      "# ── Group Policy: enable automatic updates ──────────\n# Computer Configuration > Administrative Templates\n# > Windows Components > Windows Update\n# Set: Configure Automatic Updates = Enabled (option 4 = Auto download and install)",
    },
    "windows update": {
        "title":       "Apply pending Windows updates",
        "explanation": "Windows updates include critical security patches for OS and built-in components.",
        "impact":      "Unpatched Windows hosts are prime targets — many ransomware strains exploit known Windows CVEs.",
        "commands":    [
            "Install-Module PSWindowsUpdate -Force -Confirm:$false",
            "Get-WindowsUpdate -Install -AcceptAll -AutoReboot",
        ],
        "config":      "",
    },
    "update required": {
        "title":       "Install required update",
        "explanation": "A package or firmware update is available and should be applied to fix known vulnerabilities.",
        "impact":      "Unpatched software can be exploited using publicly available CVEs and exploit kits.",
        "commands":    [
            "# Windows: install via PowerShell",
            "Install-Module PSWindowsUpdate -Force -Confirm:$false",
            "Get-WindowsUpdate -Install -AcceptAll -AutoReboot",
            "# Linux: update specific package",
            "sudo apt update && sudo apt install --only-upgrade <package-name>",
        ],
        "config":      "",
    },
    "firmware": {
        "title":       "Update firmware to latest version",
        "explanation": "Outdated firmware can contain vulnerabilities that bypass OS-level security controls.",
        "impact":      "Firmware vulnerabilities are hard to detect and can persist across OS reinstalls.",
        "commands":    [
            "# Windows: update via Windows Update or manufacturer tool",
            "Install-Module PSWindowsUpdate -Force -Confirm:$false",
            "Get-WindowsUpdate -Install -AcceptAll -AutoReboot",
            "# Check manufacturer site for firmware update tool (e.g. Lenovo System Update)",
            "# Lenovo: https://support.lenovo.com/solutions/ht003029",
        ],
        "config":      "",
    },
    # ── File permissions ──────────────────────────────────────────────────────
    "world-writable": {
        "title":       "Fix world-writable file permissions",
        "explanation": "World-writable files in sensitive directories can be overwritten by any local user.",
        "impact":      "A low-privilege attacker can inject malicious content into configs or web files.",
        "commands":    [
            "find /etc /var/www /opt -xdev -type f -perm -0002 -exec chmod o-w {} \\;",
            "find /etc /var/www /opt -xdev -type d -perm -0002 -exec chmod o-w {} \\;",
            "find /etc /var/www /opt -xdev -perm -0002 2>/dev/null",
        ],
        "config":      "",
    },
    "suid": {
        "title":       "Remove dangerous SUID bits",
        "explanation": "SUID binaries run as root regardless of who calls them — used for instant privilege escalation.",
        "impact":      "A local attacker uses GTFOBins techniques to get a root shell in seconds.",
        "commands":    [
            "find / -perm -4000 -type f 2>/dev/null",
            "sudo chmod u-s /path/to/binary",
        ],
        "config":      "",
    },
    # ── Sudo ──────────────────────────────────────────────────────────────────
    "nopasswd": {
        "title":       "Remove NOPASSWD from sudoers",
        "explanation": "NOPASSWD lets the account run sudo without a password — trivial escalation for any process running as that user.",
        "impact":      "Any compromised service running as this user automatically gets root access.",
        "commands":    ["sudo visudo"],
        "config":      "# ── /etc/sudoers ────────────────────────────────────\n# REMOVE:\n#   username ALL=(ALL) NOPASSWD: ALL\n\n# REPLACE with specific commands:\nusername ALL=(ALL) /usr/bin/systemctl restart nginx\n\n# Validate: sudo visudo -c",
    },
    # ── Windows RPC / NetBIOS ─────────────────────────────────────────────────
    "msrpc": {
        "title":       "Restrict MSRPC (Port 135) access",
        "explanation": "MSRPC on port 135 enables remote Windows service enumeration and RPC-based exploitation.",
        "impact":      "Attackers use it for lateral movement, service enumeration, and exploiting RPC vulnerabilities like MS03-026.",
        "commands":    [
            "# Block from internet, allow from LAN (PowerShell as Admin)",
            "New-NetFirewallRule -DisplayName 'Block MSRPC WAN' -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress Internet -Action Block",
            "New-NetFirewallRule -DisplayName 'Allow MSRPC LAN' -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress LocalSubnet -Action Allow",
        ],
        "config":      "# netsh (CMD as Admin)\nnetsh advfirewall firewall add rule name=\"Block MSRPC\" protocol=TCP dir=in localport=135 action=block\nnetsh advfirewall firewall add rule name=\"Allow MSRPC LAN\" protocol=TCP dir=in localport=135 remoteip=LocalSubnet action=allow",
    },
    "port 135": {
        "title":       "Block public MSRPC port (135)",
        "explanation": "Port 135 (MSRPC) should never be reachable from the internet — internal Windows use only.",
        "impact":      "Remote exploitation of RPC services can lead to SYSTEM-level compromise.",
        "commands":    [
            "New-NetFirewallRule -DisplayName 'Block MSRPC WAN' -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress Internet -Action Block",
            "New-NetFirewallRule -DisplayName 'Allow MSRPC LAN' -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress LocalSubnet -Action Allow",
        ],
        "config":      "# netsh (CMD as Admin)\nnetsh advfirewall firewall add rule name=\"Block Port 135\" protocol=TCP dir=in localport=135 action=block\nnetsh advfirewall firewall add rule name=\"Allow Port 135 LAN\" protocol=TCP dir=in localport=135 remoteip=LocalSubnet action=allow",
    },
    "netbios": {
        "title":       "Block NetBIOS ports (137/138/139)",
        "explanation": "NetBIOS leaks hostname, workgroup, and share information. Should never be exposed publicly.",
        "impact":      "Attackers enumerate network resources, usernames, and shares for lateral movement.",
        "commands":    [
            "netsh advfirewall firewall add rule name='Block NetBIOS 137' protocol=UDP dir=in localport=137 action=block",
            "netsh advfirewall firewall add rule name='Block NetBIOS 138' protocol=UDP dir=in localport=138 action=block",
            "netsh advfirewall firewall add rule name='Block NetBIOS 139' protocol=TCP dir=in localport=139 action=block",
        ],
        "config":      "",
    },
    "port 139": {
        "title":       "Block NetBIOS Session Service (Port 139)",
        "explanation": "Port 139 is NetBIOS over TCP — leaks system info and enables legacy SMB connections.",
        "impact":      "Enables enumeration and exploitation of Windows shares.",
        "commands":    [
            "netsh advfirewall firewall add rule name='Block Port 139' protocol=TCP dir=in localport=139 action=block",
        ],
        "config":      "",
    },
    "port 445": {
        "title":       "Block public SMB port (445)",
        "explanation": "Port 445 is SMB Direct. EternalBlue (WannaCry/NotPetya) specifically targets this port.",
        "impact":      "Remote code execution without authentication on unpatched systems.",
        "commands":    [
            "netsh advfirewall firewall add rule name='Block SMB 445' protocol=TCP dir=in localport=445 action=block",
            "sudo ufw deny 445",
        ],
        "config":      "# /etc/samba/smb.conf\n[global]\n    server min protocol = SMB2\n    restrict anonymous = 2",
    },
    # ── Remote access ─────────────────────────────────────────────────────────
    "winrm": {
        "title":       "Restrict WinRM (Port 5985/5986) access",
        "explanation": "WinRM allows remote PowerShell execution. Publicly exposed it is a direct remote management interface.",
        "impact":      "An attacker with valid credentials gets full remote command execution — equivalent to RDP but scriptable.",
        "commands":    [
            "New-NetFirewallRule -DisplayName 'Block WinRM WAN' -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress Internet -Action Block",
            "New-NetFirewallRule -DisplayName 'Allow WinRM LAN' -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress LocalSubnet -Action Allow",
            "Set-Item WSMan:\\localhost\\Service\\IPv4Filter '192.168.0.0/16'",
        ],
        "config":      "# PowerShell: restrict WinRM to trusted subnet\nSet-Item WSMan:\\localhost\\Service\\IPv4Filter \"192.168.1.0/24\"\nSet-Item WSMan:\\localhost\\Service\\IPv6Filter \"\"",
    },
    "port 5985": {
        "title":       "Restrict WinRM HTTP (Port 5985)",
        "explanation": "Port 5985 is WinRM over HTTP — remote PowerShell without encryption.",
        "impact":      "Full remote command execution for anyone with valid Windows credentials.",
        "commands":    [
            "New-NetFirewallRule -DisplayName 'Block WinRM 5985 WAN' -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress Internet -Action Block",
        ],
        "config":      "# Restrict WinRM to trusted subnet\nSet-Item WSMan:\\localhost\\Service\\IPv4Filter \"192.168.1.0/24\"",
    },
    "port 5986": {
        "title":       "Restrict WinRM HTTPS (Port 5986)",
        "explanation": "Port 5986 is WinRM over HTTPS. Even encrypted, it should never face the public internet.",
        "impact":      "Remote PowerShell execution accessible to any internet host with valid credentials.",
        "commands":    [
            "New-NetFirewallRule -DisplayName 'Block WinRM 5986 WAN' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress Internet -Action Block",
        ],
        "config":      "# Restrict WinRM HTTPS to trusted subnet\nSet-Item WSMan:\\localhost\\Service\\IPv4Filter \"192.168.1.0/24\"",
    },
    "rdp": {
        "title":       "Restrict RDP access",
        "explanation": "Publicly exposed RDP is the #1 ransomware entry point.",
        "impact":      "Brute-force or credential stuffing gives direct GUI access to the system.",
        "commands":    [
            "netsh advfirewall firewall add rule name='RDP Allow' protocol=TCP dir=in localport=3389 remoteip=YOUR.IP action=allow",
            "netsh advfirewall firewall add rule name='RDP Block All' protocol=TCP dir=in localport=3389 action=block",
        ],
        "config":      "",
    },
    "port 3389": {
        "title":       "Restrict RDP port (3389)",
        "explanation": "Exposed RDP is the #1 ransomware entry point. Restrict to VPN or trusted IPs only.",
        "impact":      "Brute-force or credential stuffing gives direct GUI access with no further steps.",
        "commands":    [
            "netsh advfirewall firewall add rule name='RDP Allow' protocol=TCP dir=in localport=3389 remoteip=YOUR.IP action=allow",
            "netsh advfirewall firewall add rule name='RDP Block All' protocol=TCP dir=in localport=3389 action=block",
        ],
        "config":      "",
    },
    # ── Databases ─────────────────────────────────────────────────────────────
    "port 3306": {
        "title":       "Block public MySQL port (3306)",
        "explanation": "MySQL should only be accessible from localhost or app servers — never the public internet.",
        "impact":      "Brute-force attacks on MySQL can lead to full database compromise and data exfiltration.",
        "commands":    [
            "sudo ufw deny 3306",
            "sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf",
            "sudo systemctl restart mysql",
        ],
        "config":      "# ── /etc/mysql/mysql.conf.d/mysqld.cnf ─────────────\n[mysqld]\nbind-address = 127.0.0.1",
    },
    "port 5432": {
        "title":       "Block public PostgreSQL port (5432)",
        "explanation": "PostgreSQL should only accept connections from localhost or trusted app servers.",
        "impact":      "Exposed PostgreSQL is a direct path to full database access and potential OS-level exploitation.",
        "commands":    [
            "sudo ufw deny 5432",
            "sudo sed -i \"s/^listen_addresses.*/listen_addresses = 'localhost'/\" /etc/postgresql/*/main/postgresql.conf",
            "sudo systemctl restart postgresql",
        ],
        "config":      "# ── /etc/postgresql/XX/main/postgresql.conf ─────────\nlisten_addresses = 'localhost'\n\n# ── pg_hba.conf ──────────────────────────────────────\nlocal all all                trust\nhost  all all 127.0.0.1/32  md5",
    },
    "port 6379": {
        "title":       "Block public Redis port (6379)",
        "explanation": "Redis has no authentication by default. A public Redis port is a critical data exposure risk.",
        "impact":      "Full read/write access to all cached data, potential remote code execution via Redis commands.",
        "commands":    [
            "sudo ufw deny 6379",
            "sudo sed -i 's/^bind.*/bind 127.0.0.1/' /etc/redis/redis.conf",
            "sudo systemctl restart redis",
        ],
        "config":      "# ── /etc/redis/redis.conf ───────────────────────────\nbind 127.0.0.1\nprotected-mode yes\nrequirepass YOUR_STRONG_PASSWORD",
    },
    "port 27017": {
        "title":       "Block public MongoDB port (27017)",
        "explanation": "MongoDB without auth on a public port is one of the most common mass data breach causes.",
        "impact":      "Complete database access — read, write, delete all data — no credentials needed if auth is off.",
        "commands":    [
            "sudo ufw deny 27017",
            "sudo sed -i 's/^#*  bindIp.*/  bindIp: 127.0.0.1/' /etc/mongod.conf",
            "sudo systemctl restart mongod",
        ],
        "config":      "# ── /etc/mongod.conf ────────────────────────────────\nnet:\n  port: 27017\n  bindIp: 127.0.0.1\n\nsecurity:\n  authorization: enabled",
    },
    "port 1433": {
        "title":       "Block public MSSQL port (1433)",
        "explanation": "SQL Server should never accept connections from the public internet.",
        "impact":      "Direct database access enabling data exfiltration or xp_cmdshell OS exploitation.",
        "commands":    [
            "netsh advfirewall firewall add rule name='Block MSSQL' protocol=TCP dir=in localport=1433 action=block",
            "netsh advfirewall firewall add rule name='Allow MSSQL LAN' protocol=TCP dir=in localport=1433 remoteip=LocalSubnet action=allow",
        ],
        "config":      "",
    },
    # ── Cleartext protocols ───────────────────────────────────────────────────
    "ftp": {
        "title":       "Disable FTP — switch to SFTP",
        "explanation": "FTP sends credentials and data in cleartext over the network.",
        "impact":      "Passwords and file contents visible to anyone capturing network traffic.",
        "commands":    ["sudo systemctl stop vsftpd && sudo systemctl disable vsftpd"],
        "config":      "# ── SFTP via OpenSSH (/etc/ssh/sshd_config) ────────\nSubsystem sftp internal-sftp\n\nMatch Group sftpusers\n    ChrootDirectory /var/sftp\n    ForceCommand internal-sftp\n    AllowTcpForwarding no",
    },
    "telnet": {
        "title":       "Disable Telnet",
        "explanation": "Telnet transmits everything including passwords in plaintext.",
        "impact":      "All credentials and session data visible to anyone on the network segment.",
        "commands":    [
            "sudo systemctl stop telnet && sudo systemctl disable telnet",
            "sudo apt remove --purge telnetd -y",
        ],
        "config":      "",
    },
    "smb": {
        "title":       "Disable SMBv1",
        "explanation": "SMBv1 has critical flaws including EternalBlue (MS17-010) used in WannaCry.",
        "impact":      "Remote code execution without authentication on any unpatched host.",
        "commands":    ["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
        "config":      "# ── /etc/samba/smb.conf ─────────────────────────────\n[global]\n    server min protocol = SMB2\n    ntlm auth = no\n    restrict anonymous = 2",
    },
    # ── Windows security ──────────────────────────────────────────────────────
    "firewall disabled": {
        "title":       "Enable Windows Firewall",
        "explanation": "A disabled firewall removes all network-level filtering.",
        "impact":      "Every listening service is reachable from the local network with no restrictions.",
        "commands":    [
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            "Get-NetFirewallProfile | Select Name, Enabled",
        ],
        "config":      "",
    },
    "defender": {
        "title":       "Enable Windows Defender real-time protection",
        "explanation": "Real-time protection blocks malware before it can execute.",
        "impact":      "Ransomware, trojans, and keyloggers run undetected without antivirus.",
        "commands":    [
            "Set-MpPreference -DisableRealtimeMonitoring $false",
            "Update-MpSignature",
            "Start-MpScan -ScanType QuickScan",
        ],
        "config":      "",
    },
    # ── Authenticated scan INFO findings — security advice ────────────────────
    "installed hotfix": {
        "title":       "Review installed hotfixes for gaps",
        "explanation": "The hotfix list shows which patches are applied. Cross-check against the latest Microsoft Security Updates to identify any missing patches.",
        "impact":      "Gaps in hotfix history mean known CVEs are unpatched and exploitable.",
        "commands":    [
            "# List all installed hotfixes sorted by date",
            "Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn",
            "# Compare with latest Windows security updates",
            "# https://msrc.microsoft.com/update-guide",
            "# Install missing updates",
            "Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install -AcceptAll",
        ],
        "config":      "",
    },
    "installed software": {
        "title":       "Audit and harden installed software",
        "explanation": "Review all installed programs — remove unused software, keep everything updated, and ensure no unauthorized tools are present.",
        "impact":      "Every installed program is an attack surface. Unused or outdated software contains known CVEs that can be exploited.",
        "commands":    [
            "# List all installed software",
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, DisplayVersion | Sort DisplayName",
            "# Uninstall an unwanted program",
            "Get-Package 'ProgramName' | Uninstall-Package",
            "# Check for outdated software with winget",
            "winget upgrade --all",
        ],
        "config":      "# Best practices for software inventory:\n# 1. Remove all software not required for business use\n# 2. Enable automatic updates for remaining software\n# 3. Use an application allowlist (Windows Defender WDAC)\n# 4. Review quarterly with: winget upgrade --all",
    },
    "installed packages": {
        "title":       "Audit installed packages for vulnerabilities",
        "explanation": "Review all installed packages and remove unused ones. Audit for known CVEs using a vulnerability scanner.",
        "impact":      "Unused packages increase attack surface. Outdated packages contain known exploits.",
        "commands":    [
            "# List outdated packages (Debian/Ubuntu)",
            "apt list --upgradable 2>/dev/null",
            "sudo apt update && sudo apt upgrade -y",
            "# Remove unused packages",
            "sudo apt autoremove -y",
            "# Audit packages for CVEs",
            "sudo apt install debsecan && debsecan",
        ],
        "config":      "",
    },
    "local users": {
        "title":       "Audit local user accounts",
        "explanation": "Review all local accounts — disable unused accounts, enforce strong passwords, and ensure no unauthorized users have admin access.",
        "impact":      "Unused or overprivileged accounts are prime targets for lateral movement after initial compromise.",
        "commands":    [
            "# List all local users (Windows)",
            "Get-LocalUser | Format-Table Name, Enabled, LastLogon",
            "# Disable an unused account",
            "Disable-LocalUser -Name 'OldAccount'",
            "# Linux: list non-system users",
            "awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd",
            "# Lock a Linux account",
            "sudo usermod -L username",
        ],
        "config":      "# Linux: enforce password policy in /etc/security/pwquality.conf\nminlen = 12\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\nretry = 3",
    },
    "listening services": {
        "title":       "Review and harden listening services",
        "explanation": "Audit all services listening on open ports. Disable any service not required for business operations.",
        "impact":      "Every listening service is an attack surface. Unnecessary services that contain vulnerabilities can be exploited even if not publicly exposed.",
        "commands":    [
            "# Windows: list all listening ports with process",
            "netstat -ano | findstr LISTENING",
            "Get-Process -Id (netstat -ano | findstr LISTENING | ForEach-Object { ($_ -split '\\s+')[5] })",
            "# Linux: list listening services",
            "ss -tunlp",
            "# Disable an unnecessary service (Linux)",
            "sudo systemctl stop <service> && sudo systemctl disable <service>",
        ],
        "config":      "",
    },
    "cron jobs": {
        "title":       "Audit cron jobs for malicious or risky entries",
        "explanation": "Review all scheduled tasks and cron jobs. Attackers often plant persistence via cron or scheduled tasks.",
        "impact":      "A malicious cron entry runs attacker code automatically with elevated privileges — a common persistence mechanism.",
        "commands":    [
            "# List all cron jobs for all users",
            "for user in $(cut -d: -f1 /etc/passwd); do crontab -l -u $user 2>/dev/null | grep -v '^#'; done",
            "# Check system-wide cron",
            "ls /etc/cron.* && cat /etc/cron.d/*",
            "# Windows: list scheduled tasks",
            "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Format-Table TaskName, TaskPath, State",
        ],
        "config":      "",
    },
    "failed login": {
        "title":       "Investigate failed login attempts",
        "explanation": "Multiple failed logins indicate brute-force activity or credential stuffing against this host.",
        "impact":      "Successful brute-force gives attacker shell access. High failure rates indicate active targeting.",
        "commands":    [
            "# Linux: check failed SSH logins",
            "sudo grep 'Failed password' /var/log/auth.log | tail -20",
            "sudo lastb | head -20",
            "# Block repeat offenders with fail2ban",
            "sudo apt install fail2ban -y",
            "# Windows: check failed logins",
            "Get-EventLog -LogName Security -InstanceId 4625 -Newest 20 | Select TimeGenerated, Message",
        ],
        "config":      "# ── /etc/fail2ban/jail.local ────────────────────────\n[sshd]\nenabled  = true\nport     = ssh\nfilter   = sshd\nlogpath  = /var/log/auth.log\nmaxretry = 5\nbantime  = 3600\nfindtime = 600",
    },
    "last login": {
        "title":       "Review login history for anomalies",
        "explanation": "Check login history for unexpected users, unusual times, or logins from unknown IPs.",
        "impact":      "Undetected unauthorized logins allow attackers to operate unnoticed for extended periods.",
        "commands":    [
            "# Linux: recent logins",
            "last -20",
            "# Check for logins from unusual IPs",
            "last | awk '{print $3}' | sort | uniq -c | sort -rn",
            "# Windows: successful logins",
            "Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 | Select TimeGenerated, Message",
        ],
        "config":      "",
    },
    "privileges": {
        "title":       "Review and restrict user privileges",
        "explanation": "Audit enabled privileges and remove any not required for the account's role.",
        "impact":      "Overprivileged accounts allow attackers to perform high-impact actions immediately after compromise.",
        "commands":    [
            "# Windows: check current user privileges",
            "whoami /priv",
            "# List admin group members",
            "net localgroup administrators",
            "# Remove a user from Administrators",
            "Remove-LocalGroupMember -Group 'Administrators' -Member 'username'",
            "# Linux: check sudo rights",
            "sudo -l",
        ],
        "config":      "",
    },
    "admin share": {
        "title":       "Review and restrict administrative shares",
        "explanation": "Admin shares (C$, ADMIN$, IPC$) give full remote filesystem access to administrators. Disable if not needed.",
        "impact":      "Attackers with admin credentials can access the entire filesystem remotely via admin shares.",
        "commands":    [
            "# List all shares",
            "net share",
            "# Disable admin shares permanently",
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'AutoShareWks' -Value 0",
            "# Disable IPC$ remote registry access",
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg' -Name 'AllowedPaths' -Value ''",
        ],
        "config":      "",
    },
    "startup": {
        "title":       "Audit startup programs for persistence",
        "explanation": "Review all programs that run at startup — attackers use startup entries for persistence.",
        "impact":      "Malicious startup entries survive reboots and re-establish attacker access automatically.",
        "commands":    [
            "# Windows: list startup programs",
            "Get-CimInstance Win32_StartupCommand | Select Name, Command, Location",
            "# Remove a suspicious startup entry",
            "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SuspiciousProgram'",
            "# Linux: check systemd services",
            "systemctl list-unit-files --state=enabled",
        ],
        "config":      "",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _match_static(title: str, description: str, severity: str = "") -> dict | None:
    haystack = f"{title} {description}".lower()

    # Exact keyword match
    for kw, fix in _STATIC.items():
        if kw in haystack:
            return {**fix, "source": "static"}

    # Generic fallback — catches ANY "TCP/UDP Port XXXX / service" finding
    m = re.search(r'(?:tcp|udp)\s+port\s+(\d+)(?:\s*/\s*(\S+))?', haystack)
    if m:
        port    = m.group(1)
        service = (m.group(2) or f"port {port}").upper()
        return {
            "title":       f"Restrict access to {service} (Port {port})",
            "explanation": f"Port {port} ({service}) is reachable from the scanner. Services should only be exposed to the networks that actually need them.",
            "impact":      "An attacker can fingerprint the service, attempt exploitation, or use it as a pivot point for lateral movement.",
            "commands":    [
                f"# Linux — block with ufw",
                f"sudo ufw deny {port}",
                f"sudo ufw allow from 192.168.0.0/16 to any port {port}",
                f"# Windows — block with netsh",
                f"netsh advfirewall firewall add rule name=\"Block {service} {port}\" protocol=TCP dir=in localport={port} action=block",
                f"netsh advfirewall firewall add rule name=\"Allow {service} LAN\" protocol=TCP dir=in localport={port} remoteip=LocalSubnet action=allow",
            ],
            "config":      f"# ── iptables (Linux) ─────────────────────────────\n# Block from internet\n-A INPUT -p tcp --dport {port} -j DROP\n# Allow from trusted internal subnet only\n-A INPUT -s 192.168.0.0/16 -p tcp --dport {port} -j ACCEPT\n\n# Save rules\nsudo iptables-save > /etc/iptables/rules.v4",
            "source":      "static",
        }

    # INFO severity fallback — general security hardening tips
    if severity.upper() == "INFO":
        return {
            "title":       f"Security review: {title}",
            "explanation": f"This is an informational finding. Review the collected data and apply the relevant hardening steps below.",
            "impact":      "Informational findings provide visibility into the host configuration. Misconfigurations found here can be exploited if left unreviewed.",
            "commands":    [
                "# Review the finding details in the scan report",
                "# Cross-reference with your security baseline",
                "# Apply any missing hardening steps",
                "# Document accepted risks with a justification",
            ],
            "config":      "# Security hardening checklist for authenticated findings:\n# 1. Remove/disable unused accounts, services, and software\n# 2. Apply least-privilege to all accounts\n# 3. Enable logging and monitoring\n# 4. Keep all software and OS up to date\n# 5. Review firewall rules quarterly",
            "source":      "static",
        }

    return None


def _build_prompt(title, description, severity, evidence="", recommendation=""):
    ev  = f"\nEvidence: {evidence}"            if evidence       else ""
    rec = f"\nRecommendation: {recommendation}" if recommendation else ""
    return f"""You are an elite cybersecurity remediation engineer.
Finding:
  Title: {title}
  Severity: {severity}
  Description: {description}{ev}{rec}

Reply with JSON ONLY — no markdown fences, no text outside the JSON.

{{
  "title": "short fix title",
  "explanation": "what is wrong and what the fix achieves (max 60 words)",
  "impact": "what an attacker gains if not fixed (max 40 words)",
  "commands": ["runnable command 1", "command 2"],
  "config": "# /path/to/file\\nconfig snippet here, or empty string"
}}

Rules:
- commands: real, copy-pasteable shell/PowerShell, max 6 items
- config: first line = comment with target file path
- Web headers: include nginx AND apache in config
- SSH issues: include sshd_config snippet
- No filler, be direct
"""


def _ask_ai(prompt: str) -> str:
    """Try each model in MODEL_FALLBACKS until one works."""
    if not OPENROUTER_API_KEY:
        raise EnvironmentError("OPENROUTER_API_KEY not set in .env")

    last_error = None
    for model in MODEL_FALLBACKS:
        try:
            resp = requests.post(
                OPENROUTER_URL,
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}",
                         "Content-Type":  "application/json"},
                json={
                    "model":       model,
                    "messages":    [
                        {"role": "system",
                         "content": "You are a cybersecurity expert. Respond only with valid JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": TEMPERATURE,
                    "max_tokens":  MAX_TOKENS,
                },
                timeout=45,
            )
            if resp.status_code == 404:
                logger.warning("Model '%s' returned 404, trying next model...", model)
                last_error = requests.HTTPError(f"404 for model {model}", response=resp)
                continue
            resp.raise_for_status()
            data = resp.json()
            if "choices" not in data or not data["choices"]:
                continue
            logger.info("Auto-fix used model: %s", model)
            return data["choices"][0]["message"]["content"]
        except requests.HTTPError as e:
            last_error = e
            # Don't retry on auth or rate-limit errors
            if e.response is not None and e.response.status_code in (401, 429):
                raise
            continue
        except Exception as e:
            last_error = e
            continue

    raise last_error or RuntimeError("All OpenRouter models failed.")


def _parse(raw: str, title: str) -> dict:
    clean = raw.strip()
    if "```" in clean:
        parts = clean.split("```")
        clean = parts[1] if len(parts) > 1 else clean
        if clean.lower().startswith("json"):
            clean = clean[4:]
    try:
        parsed = json.loads(clean.strip())
        parsed.setdefault("title",       title)
        parsed.setdefault("explanation", "")
        parsed.setdefault("impact",      "")
        parsed.setdefault("commands",    [])
        parsed.setdefault("config",      "")
        parsed["source"] = "ai"
        return parsed
    except json.JSONDecodeError:
        return {"title": title, "explanation": clean,
                "impact": "", "commands": [], "config": "", "source": "ai"}


def _fallback(title: str, recommendation: str = "", error: str = "") -> dict:
    return {
        "title":       title,
        "explanation": recommendation or "Review and remediate per security best practices.",
        "impact":      error,
        "commands":    [],
        "config":      "",
        "source":      "fallback",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Core: process one finding
# ─────────────────────────────────────────────────────────────────────────────

def _process_one(finding: dict) -> dict:
    title = (finding.get("title")          or "").strip()
    desc  = (finding.get("description")    or "").strip()
    sev   = (finding.get("severity")       or "INFO").strip()
    ev    = (finding.get("evidence")       or "").strip()
    rec   = (finding.get("recommendation") or "").strip()

    # 1. Static library (instant, no API)
    static = _match_static(title, desc, sev)
    if static:
        return {**static, "title": title}

    # 2. AI via OpenRouter (tries multiple models on 404)
    if OPENROUTER_API_KEY:
        try:
            raw = _ask_ai(_build_prompt(title, desc, sev, ev, rec))
            return _parse(raw, title)
        except requests.HTTPError as e:
            status = e.response.status_code if e.response else "?"
            friendly = {
                401: "OpenRouter API key is invalid. Check OPENROUTER_API_KEY in .env",
                404: "No AI model available right now — showing recommendation.",
                429: "OpenRouter rate limit reached. The fix will be available shortly — try again in a few seconds.",
                500: "OpenRouter server error. Try again later.",
            }.get(status, f"API error (HTTP {status})")
            logger.error("HTTP %s for '%s': %s", status, title, friendly)
            return _fallback(title, rec, friendly)
        except Exception as e:
            logger.error("AI fix failed for '%s': %s", title, e)
            return _fallback(title, rec, "AI generation failed. Showing recommendation fallback.")

    # 3. Fallback
    return _fallback(title, rec)


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_remediation(findings: list) -> list:
    """Generate fixes for multiple findings in parallel."""
    if not findings:
        return []
    results   = [None] * len(findings)
    index_map = {id(f): i for i, f in enumerate(findings)}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(findings))) as ex:
        futs = {ex.submit(_process_one, f): f for f in findings}
        for fut in as_completed(futs):
            f   = futs[fut]
            idx = index_map[id(f)]
            try:
                results[idx] = fut.result()
            except Exception as e:
                results[idx] = _fallback(f.get("title", ""), error=str(e))
    return results


def generate_single_remediation(data: dict) -> dict:
    """Generate a fix for a single finding."""
    r = generate_remediation([data])
    return r[0] if r else _fallback(data.get("title", ""))