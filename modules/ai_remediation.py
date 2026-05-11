"""
ai_remediation.py — VulniX Auto-Fix Engine
Priority: static library → OpenRouter AI → recommendation fallback
"""

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"
MODEL              = "mistralai/mistral-7b-instruct:free"
MAX_WORKERS        = 4
MAX_TOKENS         = 700
TEMPERATURE        = 0.3


# ─────────────────────────────────────────────────────────────────────────────
#  Static fix library — instant, zero API cost
# ─────────────────────────────────────────────────────────────────────────────

_STATIC = {
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
    "world-writable": {
        "title":       "Fix world-writable file permissions",
        "explanation": "World-writable files in sensitive directories can be overwritten by any local user.",
        "impact":      "A low-privilege attacker can inject malicious content into configs or web files.",
        "commands":    [
            "find /etc /var/www /opt -xdev -type f -perm -0002 -exec chmod o-w {} \\;",
            "find /etc /var/www /opt -xdev -type d -perm -0002 -exec chmod o-w {} \\;",
            "# Verify — should return nothing",
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
    "nopasswd": {
        "title":       "Remove NOPASSWD from sudoers",
        "explanation": "NOPASSWD lets the account run sudo without a password — trivial escalation for any process running as that user.",
        "impact":      "Any compromised service running as this user automatically gets root access.",
        "commands":    ["sudo visudo"],
        "config":      "# ── /etc/sudoers ────────────────────────────────────\n# REMOVE:\n#   username ALL=(ALL) NOPASSWD: ALL\n\n# REPLACE with specific commands:\nusername ALL=(ALL) /usr/bin/systemctl restart nginx\n\n# Validate: sudo visudo -c",
    },
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
        "commands":    [
            "# Windows PowerShell",
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        ],
        "config":      "# ── /etc/samba/smb.conf ─────────────────────────────\n[global]\n    server min protocol = SMB2\n    ntlm auth = no\n    restrict anonymous = 2",
    },
    "rdp": {
        "title":       "Restrict RDP access",
        "explanation": "Publicly exposed RDP is the #1 ransomware entry point.",
        "impact":      "Brute-force or credential-stuffing gives direct GUI access to the machine.",
        "commands":    [
            "netsh advfirewall firewall add rule name='RDP Allow' protocol=TCP dir=in localport=3389 remoteip=YOUR.IP action=allow",
            "netsh advfirewall firewall add rule name='RDP Block' protocol=TCP dir=in localport=3389 action=block",
        ],
        "config":      "",
    },
    "winrm": {
        "title":       "Restrict WinRM (Port 5985/5986) access",
        "explanation": "WinRM allows remote PowerShell execution. Exposed publicly it gives attackers a direct management interface.",
        "impact":      "An attacker with credentials gets full remote command execution — equivalent to RDP but scriptable.",
        "commands":    [
            "# Allow WinRM only from trusted admin IPs",
            "netsh advfirewall firewall add rule name='WinRM Allow' protocol=TCP dir=in localport=5985 remoteip=YOUR.ADMIN.IP action=allow",
            "netsh advfirewall firewall add rule name='WinRM Block' protocol=TCP dir=in localport=5985 action=block",
            "# Also restrict port 5986 (HTTPS WinRM)",
            "netsh advfirewall firewall add rule name='WinRM HTTPS Allow' protocol=TCP dir=in localport=5986 remoteip=YOUR.ADMIN.IP action=allow",
            "netsh advfirewall firewall add rule name='WinRM HTTPS Block' protocol=TCP dir=in localport=5986 action=block",
        ],
        "config":      "# PowerShell: restrict WinRM to specific subnet\nSet-Item WSMan:\\localhost\\Service\\IPv4Filter \"192.168.1.0/24\"\nSet-Item WSMan:\\localhost\\Service\\IPv6Filter \"\"\n\n# Verify current listeners\nGet-WSManInstance winrm/config/listener -Enumerate",
    },
    "5985": {
        "title":       "Restrict WinRM (Port 5985) access",
        "explanation": "Port 5985 is WinRM HTTP. Exposed publicly it gives attackers a remote PowerShell management interface.",
        "impact":      "Full remote command execution for anyone who obtains valid credentials.",
        "commands":    [
            "netsh advfirewall firewall add rule name='WinRM Allow' protocol=TCP dir=in localport=5985 remoteip=YOUR.ADMIN.IP action=allow",
            "netsh advfirewall firewall add rule name='WinRM Block' protocol=TCP dir=in localport=5985 action=block",
        ],
        "config":      "# Restrict WinRM to trusted subnet (PowerShell)\nSet-Item WSMan:\\localhost\\Service\\IPv4Filter \"192.168.1.0/24\"",
    },
    "5986": {
        "title":       "Restrict WinRM HTTPS (Port 5986) access",
        "explanation": "Port 5986 is WinRM over HTTPS. Even with TLS, it should never be exposed to the public internet.",
        "impact":      "Remote PowerShell execution accessible to any internet host that has credentials.",
        "commands":    [
            "netsh advfirewall firewall add rule name='WinRM HTTPS Allow' protocol=TCP dir=in localport=5986 remoteip=YOUR.ADMIN.IP action=allow",
            "netsh advfirewall firewall add rule name='WinRM HTTPS Block' protocol=TCP dir=in localport=5986 action=block",
        ],
        "config":      "# Restrict WinRM HTTPS to trusted subnet (PowerShell)\nSet-Item WSMan:\\localhost\\Service\\IPv4Filter \"192.168.1.0/24\"",
    },
    "port 22": {
        "title":       "Harden SSH (Port 22) exposure",
        "explanation": "SSH exposed publicly is constantly targeted by automated brute-force bots.",
        "impact":      "Weak credentials or vulnerable SSH versions can be exploited for full shell access.",
        "commands":    [
            "# Change to a non-standard port (optional)",
            "sudo sed -i 's/^#*Port.*/Port 2222/' /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
            "# Or restrict with firewall",
            "sudo ufw allow from YOUR.IP to any port 22",
            "sudo ufw deny 22",
        ],
        "config":      "# ── /etc/ssh/sshd_config ───────────────────────────\nPermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\nLoginGraceTime 30\nPubkeyAuthentication yes",
    },
    "port 3306": {
        "title":       "Block public MySQL port (3306)",
        "explanation": "MySQL should never be exposed to the public internet — only accessible from localhost or app servers.",
        "impact":      "Brute-force attacks on MySQL can lead to database compromise and full data exfiltration.",
        "commands":    [
            "sudo ufw deny 3306",
            "# Or in MySQL: bind to localhost only",
            "sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf",
            "sudo systemctl restart mysql",
        ],
        "config":      "# ── /etc/mysql/mysql.conf.d/mysqld.cnf ─────────────\n[mysqld]\nbind-address = 127.0.0.1\nskip-networking = 0",
    },
    "port 5432": {
        "title":       "Block public PostgreSQL port (5432)",
        "explanation": "PostgreSQL should only accept connections from localhost or trusted app servers, never the public internet.",
        "impact":      "Exposed PostgreSQL is a direct path to full database access and potential OS-level exploitation.",
        "commands":    [
            "sudo ufw deny 5432",
            "sudo sed -i \"s/^listen_addresses.*/listen_addresses = 'localhost'/\" /etc/postgresql/*/main/postgresql.conf",
            "sudo systemctl restart postgresql",
        ],
        "config":      "# ── /etc/postgresql/XX/main/postgresql.conf ─────────\nlisten_addresses = 'localhost'\n\n# ── /etc/postgresql/XX/main/pg_hba.conf ──────────────\n# Allow only local connections\nlocal all all                trust\nhost  all all 127.0.0.1/32  md5",
    },
    "port 6379": {
        "title":       "Block public Redis port (6379)",
        "explanation": "Redis has no authentication by default. A public Redis port is a critical data exposure risk.",
        "impact":      "Full read/write access to all cached data, potential for remote code execution via Redis commands.",
        "commands":    [
            "sudo ufw deny 6379",
            "# Bind to localhost in redis.conf",
            "sudo sed -i 's/^bind.*/bind 127.0.0.1/' /etc/redis/redis.conf",
            "sudo systemctl restart redis",
        ],
        "config":      "# ── /etc/redis/redis.conf ───────────────────────────\nbind 127.0.0.1\nprotected-mode yes\nrequirepass YOUR_STRONG_PASSWORD",
    },
    "port 27017": {
        "title":       "Block public MongoDB port (27017)",
        "explanation": "MongoDB without auth on a public port is one of the most common causes of mass data breaches.",
        "impact":      "Complete database access — read, write, delete all data — no credentials needed if auth is disabled.",
        "commands":    [
            "sudo ufw deny 27017",
            "sudo sed -i 's/^#*  bindIp.*/  bindIp: 127.0.0.1/' /etc/mongod.conf",
            "sudo systemctl restart mongod",
        ],
        "config":      "# ── /etc/mongod.conf ────────────────────────────────\nnet:\n  port: 27017\n  bindIp: 127.0.0.1\n\nsecurity:\n  authorization: enabled",
    },
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
}


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _match_static(title: str, description: str) -> dict | None:
    haystack = f"{title} {description}".lower()
    for kw, fix in _STATIC.items():
        if kw in haystack:
            return {**fix, "source": "static"}
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
    if not OPENROUTER_API_KEY:
        raise EnvironmentError("OPENROUTER_API_KEY not set in .env")
    resp = requests.post(
        OPENROUTER_URL,
        headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}",
                 "Content-Type":  "application/json"},
        json={
            "model":       MODEL,
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
    resp.raise_for_status()
    data = resp.json()
    if "choices" not in data or not data["choices"]:
        raise ValueError(f"Unexpected API response: {data}")
    return data["choices"][0]["message"]["content"]


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

    # 1. Static library (instant)
    static = _match_static(title, desc)
    if static:
        return {**static, "title": title}

    # 2. AI via OpenRouter
    if OPENROUTER_API_KEY:
        try:
            raw = _ask_ai(_build_prompt(title, desc, sev, ev, rec))
            return _parse(raw, title)
        except requests.HTTPError as e:
            status = e.response.status_code if e.response else "?"
            msg = {401: "Invalid API key.", 429: "Rate limit hit.",
                   500: "Server error."}.get(status, str(e))
            logger.error("HTTP %s for '%s': %s", status, title, msg)
            return _fallback(title, rec, msg)
        except Exception as e:
            logger.error("AI fix failed for '%s': %s", title, e)
            return _fallback(title, rec, str(e))

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
