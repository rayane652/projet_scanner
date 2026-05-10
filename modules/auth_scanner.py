"""
auth_scanner.py — VulniX Authenticated Scanner
Supports:
  - HTTP Basic
  - SSH  (password or private key, custom port)
  - Windows WinRM (NTLM, HTTP port 5985 / HTTPS port 5986)
"""

import io
import socket
import requests
from requests.auth import HTTPBasicAuth

from modules.utils import resolve_host
from modules.web_scanner import normalize_url


# ─────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────

AUTH_TYPE_LABELS = {
    "http_basic": "HTTP Basic",
    "ssh":        "SSH (Linux/Unix)",
    "winrm":      "Windows (WinRM)",
}

COMMON_AUTH_PATHS = [
    "/", "/admin", "/administrator", "/login",
    "/wp-admin", "/phpmyadmin", "/server-status", "/api",
]

DANGEROUS_SUID = {
    "bash", "sh", "python", "python3", "perl", "ruby", "awk", "nmap",
    "find", "vim", "nano", "less", "more", "man", "cp", "mv",
    "chmod", "chown", "dd", "curl", "wget", "nc", "netcat",
}

DANGEROUS_SUDO_KEYWORDS = [
    "ALL", "NOPASSWD", "/bin/bash", "/bin/sh", "/usr/bin/python",
    "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/vim", "/usr/bin/nano",
    "/usr/bin/awk", "/usr/bin/find", "/usr/bin/nmap",
]

DANGEROUS_WINDOWS_PRIVS = {
    "SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege",
}

SSH_PKG_UPDATE_CMD = (
    "if command -v apt >/dev/null 2>&1; then "
    "apt list --upgradable 2>/dev/null | sed -n '2,30p'; "
    "elif command -v dnf >/dev/null 2>&1; then "
    "dnf -q check-update 2>/dev/null | sed -n '1,30p'; "
    "elif command -v yum >/dev/null 2>&1; then "
    "yum -q check-update 2>/dev/null | sed -n '1,30p'; "
    "elif command -v zypper >/dev/null 2>&1; then "
    "zypper --non-interactive list-updates 2>/dev/null | sed -n '1,30p'; "
    "elif command -v pacman >/dev/null 2>&1; then "
    "pacman -Qu 2>/dev/null | head -30; "
    "else true; fi"
)

SSH_PKG_COUNT_CMD = (
    "dpkg -l 2>/dev/null | tail -n +6 | wc -l || "
    "rpm -qa 2>/dev/null | wc -l || "
    "pacman -Q 2>/dev/null | wc -l || "
    "echo 0"
)

WINDOWS_PS_COMMANDS = {
    "os":              "(Get-WmiObject Win32_OperatingSystem).Caption",
    "hostname":        "$env:COMPUTERNAME",
    "user":            "whoami",
    "ps_version":      "$PSVersionTable.PSVersion.ToString()",
    "uptime":          "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | ForEach-Object { \"$($_.Days)d $($_.Hours)h $($_.Minutes)m\" }",
    "local_users":     "Get-LocalUser | ForEach-Object { $_.Name + ' [' + $(if($_.Enabled){'enabled'}else{'disabled'}) + ']' }",
    "admins":          "net localgroup administrators 2>$null | Where-Object { $_ -match '^[a-zA-Z]' } | Select-Object -Skip 1",
    "hotfixes":        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 | ForEach-Object { ($_.HotFixID + '  ' + $_.Description + '  ' + $_.InstalledOn) }",
    "services":        "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 25 | ForEach-Object { $_.Name + ': ' + $_.DisplayName }",
    "open_ports":      "netstat -ano | findstr LISTENING | Select-Object -First 20",
    "firewall":        "Get-NetFirewallProfile | ForEach-Object { $_.Name + ': ' + $(if($_.Enabled){'ENABLED'}else{'DISABLED'}) }",
    "privileges":      "whoami /priv | findstr Enabled",
    "shares":          "net share 2>$null | Select-Object -Skip 4 | Select-Object -First 10",
    "installed_sw":    "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Select-Object -First 25 | ForEach-Object { $_.DisplayName + '  ' + $_.DisplayVersion }",
    "startup":         "Get-CimInstance Win32_StartupCommand | Select-Object -First 10 | ForEach-Object { $_.Name + ': ' + $_.Command }",
    "env_secrets":     "[System.Environment]::GetEnvironmentVariables() | Out-String | Select-String -Pattern 'pass|key|secret|token|api' -CaseSensitive:$false | Select-Object -First 8",
    "missing_updates": "try { $s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $r=$s.Search('IsInstalled=0').Updates; $r | ForEach-Object { $_.Title } | Select-Object -First 20 } catch { 'WUA_UNAVAILABLE' }",
    "defender_status": "try { Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled } catch { 'UNAVAILABLE' }",
}


# ─────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────

def _base_result(auth_type, username, status, message, checks=None, inventory=None):
    return {
        "type":       auth_type,
        "type_label": AUTH_TYPE_LABELS.get(auth_type, auth_type),
        "username":   username,
        "status":     status,
        "message":    message,
        "checks":     checks or [],
        "inventory":  inventory or {},
    }


def _check(status, name, detail):
    return {"status": status, "name": name, "detail": detail}


def _non_empty_lines(value, limit=20):
    return [l.strip() for l in (value or "").splitlines() if l.strip()][:limit]


def _port_open(ip, port, timeout=4):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# ─────────────────────────────────────────────────────────
# SSH analysis helpers
# ─────────────────────────────────────────────────────────

def _run_ssh_command(client, command, timeout=6):
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="ignore").strip()
    except Exception:
        return ""


def _analyze_sudo(sudo_output):
    lines = _non_empty_lines(sudo_output, limit=30)
    findings, severity = [], "info"
    has_nopasswd = has_all = False
    dangerous_cmds = []

    for line in lines:
        ll = line.lower()
        if "nopasswd" in ll:
            has_nopasswd = True
        if "(all)" in ll or "(root)" in ll:
            has_all = True
        for kw in DANGEROUS_SUDO_KEYWORDS:
            if kw.lower() in ll and kw not in dangerous_cmds:
                dangerous_cmds.append(kw)

    if has_nopasswd and has_all:
        findings.append("NOPASSWD ALL — full root without password!")
        severity = "critical"
    elif has_nopasswd:
        findings.append("NOPASSWD rule — can run commands without password")
        severity = "high"
    elif has_all:
        findings.append("(ALL) rule — full sudo access as root")
        severity = "high"

    if dangerous_cmds:
        findings.append(f"Risky commands in sudoers: {', '.join(dangerous_cmds[:5])}")
        if severity == "info":
            severity = "medium"

    return findings, severity, lines


def _analyze_suid(suid_output):
    all_suid = _non_empty_lines(suid_output, limit=25)
    dangerous = [p for p in all_suid if p.split("/")[-1].lower() in DANGEROUS_SUID]
    return all_suid, dangerous


def _analyze_ssh_config(config_output):
    issues, lines = [], _non_empty_lines(config_output, limit=20)
    for line in lines:
        ll = line.lower()
        if ll.startswith("permitrootlogin") and "no" not in ll and "prohibit" not in ll:
            issues.append(f"PermitRootLogin is not 'no': {line}")
        if ll.startswith("passwordauthentication yes"):
            issues.append("PasswordAuthentication enabled — prefer key-based auth")
        if ll.startswith("protocol 1"):
            issues.append("SSH Protocol 1 is enabled — deprecated and insecure")
        if ll.startswith("permitemptypasswords yes"):
            issues.append("PermitEmptyPasswords is enabled!")
    return issues, lines


# ─────────────────────────────────────────────────────────
# SSH Scan
# ─────────────────────────────────────────────────────────

def _ssh_scan(target, username, password, port=22, ssh_key_text=None):
    ip = resolve_host(target)
    if not ip:
        return _base_result("ssh", username, "failed", "Target could not be resolved.",
                            [_check("failed", "SSH target", "DNS resolution failed.")])

    port = int(port or 22)
    if not _port_open(ip, port):
        return _base_result("ssh", username, "unavailable",
                            f"SSH not reachable on port {port}.",
                            [_check("failed", "SSH port", f"Port {port} is closed or filtered.")])

    try:
        import paramiko
    except ImportError:
        return _base_result("ssh", username, "unavailable",
                            "SSH scan requires paramiko. Run: pip install paramiko",
                            [_check("failed", "SSH library", "paramiko not installed.")])

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = dict(
        hostname=ip, port=port, username=username,
        timeout=8, banner_timeout=8, auth_timeout=8,
        look_for_keys=False, allow_agent=False,
    )

    # Private key takes priority over password
    if ssh_key_text and ssh_key_text.strip():
        key_obj = None
        for KeyClass in (paramiko.RSAKey, paramiko.Ed25519Key,
                         paramiko.ECDSAKey, paramiko.DSSKey):
            try:
                key_obj = KeyClass.from_private_key(io.StringIO(ssh_key_text.strip()))
                break
            except Exception:
                continue
        if not key_obj:
            return _base_result("ssh", username, "failed",
                                "Private key could not be parsed (unsupported format).",
                                [_check("failed", "SSH key", "Tried RSA, Ed25519, ECDSA, DSS.")])
        connect_kwargs["pkey"] = key_obj
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        return _base_result("ssh", username, "failed", "SSH credentials were rejected.",
                            [_check("failed", "SSH login", "Authentication failed.")])
    except (paramiko.SSHException, OSError) as exc:
        return _base_result("ssh", username, "failed", "SSH connection error.",
                            [_check("failed", "SSH connect", str(exc)[:200])])

    auth_method = "key" if connect_kwargs.get("pkey") else "password"
    checks = [_check("success", "SSH login",
                     f"Connected via {auth_method} auth on port {port}.")]
    inventory = {}

    # ── System info ──
    for key, cmd in {
        "kernel":   "uname -a",
        "os":       "cat /etc/os-release 2>/dev/null | head -5",
        "hostname": "hostname 2>/dev/null",
        "user":     "id",
        "uptime":   "uptime -p 2>/dev/null",
    }.items():
        inventory[key] = _run_ssh_command(client, cmd)

    # ── Sudo analysis ──
    sudo_raw = _run_ssh_command(client, "sudo -n -l 2>/dev/null", timeout=8)
    sudo_findings, sudo_sev, sudo_lines = _analyze_sudo(sudo_raw)
    if sudo_lines:
        inventory["sudo_rights"] = sudo_lines
        detail = " | ".join(sudo_findings) if sudo_findings else f"{len(sudo_lines)} sudo rule(s) found."
        check_status = "failed" if sudo_sev in ("critical", "high") else "info"
        checks.append(_check(check_status, "Sudo rights analysis", detail))

    # ── SUID files ──
    suid_raw = _run_ssh_command(client,
                                "find / -perm -4000 -type f 2>/dev/null | head -20",
                                timeout=10)
    all_suid, dangerous_suid = _analyze_suid(suid_raw)
    if all_suid:
        inventory["suid_files"] = all_suid
    if dangerous_suid:
        inventory["dangerous_suid"] = dangerous_suid
        checks.append(_check("failed", "Dangerous SUID binaries",
                             f"{len(dangerous_suid)} risky SUID: {', '.join(dangerous_suid[:3])}"))
    elif all_suid:
        checks.append(_check("info", "SUID files",
                             f"{len(all_suid)} SUID file(s) — none flagged as dangerous."))

    # ── SSH daemon config ──
    sshd_raw = _run_ssh_command(client,
                                "cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#|^$' | head -25")
    ssh_issues, ssh_config_lines = _analyze_ssh_config(sshd_raw)
    if ssh_config_lines:
        inventory["ssh_config"] = ssh_config_lines
    for issue in ssh_issues:
        checks.append(_check("failed", "SSH config issue", issue))
    if ssh_config_lines and not ssh_issues:
        checks.append(_check("success", "SSH config", "No obvious sshd_config issues detected."))

    # ── World-writable files ──
    ww_raw = _run_ssh_command(client,
                              "find /etc /var/www /opt -xdev -type f -perm -0002 2>/dev/null | head -20",
                              timeout=10)
    ww_files = _non_empty_lines(ww_raw, limit=20)
    if ww_files:
        inventory["world_writable"] = ww_files
        checks.append(_check("failed", "World-writable files",
                             f"{len(ww_files)} world-writable file(s) in sensitive paths."))

    # ── Cron jobs ──
    cron_raw = _run_ssh_command(client,
                                "crontab -l 2>/dev/null; "
                                "ls /etc/cron.d/ 2>/dev/null | head -10; "
                                "cat /etc/cron.d/* 2>/dev/null | grep -vE '^#|^$' | head -15")
    cron_lines = _non_empty_lines(cron_raw, limit=20)
    if cron_lines:
        inventory["cron_jobs"] = cron_lines
        checks.append(_check("info", "Cron jobs", f"{len(cron_lines)} cron entry/file(s) found."))

    # ── Listening services ──
    listen_raw = _run_ssh_command(client,
                                  "ss -tunlp 2>/dev/null | head -30 || "
                                  "netstat -tunlp 2>/dev/null | head -30")
    listen_lines = _non_empty_lines(listen_raw, limit=25)
    if listen_lines:
        inventory["listening_services"] = listen_lines
        checks.append(_check("info", "Listening services (internal)",
                             f"{len(listen_lines)} socket(s) visible from inside the host."))

    # ── Local users ──
    inventory["local_users"] = _non_empty_lines(
        _run_ssh_command(client,
                         "awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null"),
        limit=20,
    )
    inventory["all_users"] = _non_empty_lines(
        _run_ssh_command(client, "cut -d: -f1 /etc/passwd 2>/dev/null | head -30"),
        limit=30,
    )

    # ── Package auditing ──
    try:
        pkg_count = int(_run_ssh_command(client, SSH_PKG_COUNT_CMD).split()[0])
        inventory["package_count"] = pkg_count
        checks.append(_check("info", "Installed packages",
                             f"{pkg_count} package(s) installed on this host."))
    except (ValueError, IndexError):
        pass

    pkg_updates = _non_empty_lines(
        _run_ssh_command(client, SSH_PKG_UPDATE_CMD, timeout=12), limit=30
    )
    if pkg_updates:
        inventory["package_updates"] = pkg_updates
        sev = "failed" if len(pkg_updates) > 5 else "info"
        checks.append(_check(sev, "Pending package updates",
                             f"{len(pkg_updates)} update(s) available — patch recommended."))
    else:
        checks.append(_check("success", "Package updates", "No pending updates detected."))

    # ── Sensitive env variables ──
    env_raw = _run_ssh_command(client,
                               "env 2>/dev/null | grep -iE '(pass|key|secret|token|api_)' | head -10")
    env_hits = _non_empty_lines(env_raw, limit=10)
    if env_hits:
        inventory["env_secrets"] = ["[REDACTED — sensitive variable name]"] * len(env_hits)
        checks.append(_check("failed", "Sensitive env variables",
                             f"{len(env_hits)} variable(s) with sensitive-looking names (pass/key/secret/token)."))

    # ── Login history ──
    last_raw  = _run_ssh_command(client, "last 2>/dev/null | head -8")
    lastb_raw = _run_ssh_command(client,
                                 "lastb 2>/dev/null | head -8 || "
                                 "grep -i 'Failed password' /var/log/auth.log 2>/dev/null | tail -5")
    if _non_empty_lines(last_raw):
        inventory["last_logins"] = _non_empty_lines(last_raw, limit=8)
    if _non_empty_lines(lastb_raw):
        inventory["failed_logins"] = _non_empty_lines(lastb_raw, limit=8)
        checks.append(_check("info", "Failed login attempts",
                             "Recent failed logins recorded in system log."))

    client.close()

    return _base_result("ssh", username, "success",
                        "SSH authenticated scan completed.", checks, inventory)


# ─────────────────────────────────────────────────────────
# Windows WinRM Scan
# ─────────────────────────────────────────────────────────

def _windows_scan(target, username, password, port=5985):
    ip = resolve_host(target)
    if not ip:
        return _base_result("winrm", username, "failed", "Target could not be resolved.",
                            [_check("failed", "WinRM target", "DNS resolution failed.")])

    port   = int(port or 5985)
    scheme = "https" if port == 5986 else "http"

    if not _port_open(ip, port):
        return _base_result("winrm", username, "unavailable",
                            f"WinRM not reachable on port {port}.",
                            [_check("failed", "WinRM port",
                                    f"Port {port} closed/filtered. Enable with: winrm quickconfig")])

    try:
        import winrm
    except ImportError:
        return _base_result("winrm", username, "unavailable",
                            "Windows scan requires pywinrm. Run: pip install pywinrm",
                            [_check("failed", "WinRM library", "pywinrm not installed.")])

    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=15,
            operation_timeout_sec=12,
        )
        probe = session.run_ps("$PSVersionTable.PSVersion.ToString()")
        if probe.status_code != 0:
            raise Exception(probe.std_err.decode(errors="ignore")[:200])
    except Exception as exc:
        print("WINRM FULL ERROR:", repr(exc))
        err = str(exc)
        if any(k in err for k in ("401", "403", "Unauthorized", "authentication", "Access denied")):
            return _base_result("winrm", username, "failed",
                                "WinRM credentials rejected (NTLM).",
                                [_check("failed", "WinRM login",
                                        "Authentication failed. Verify credentials and WinRM access.")])
        return _base_result("winrm", username, "failed",
                            f"WinRM error: {err[:150]}",
                            [_check("failed", "WinRM connect", err[:200])])

    checks = [_check("success", "WinRM login",
                     f"Connected via {'HTTPS' if port == 5986 else 'HTTP'} WinRM on port {port}.")]
    inventory = {}

    def run_ps(cmd):
        try:
            r = session.run_ps(cmd)
            return r.std_out.decode(errors="ignore").strip()
        except Exception:
            return ""

    # ── System info ──
    for key in ("os", "hostname", "user", "ps_version", "uptime"):
        inventory[key] = run_ps(WINDOWS_PS_COMMANDS[key])

    # ── Users & admins ──
    inventory["local_users"] = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["local_users"]), 20)
    inventory["admins"]      = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["admins"]), 10)
    if inventory["admins"]:
        checks.append(_check("info", "Local administrators",
                             f"{len(inventory['admins'])} member(s) in the Administrators group."))

    # ── Privileges ──
    priv_lines = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["privileges"]), 20)
    if priv_lines:
        inventory["privileges"] = priv_lines
        dangerous = [p for p in priv_lines if any(d in p for d in DANGEROUS_WINDOWS_PRIVS)]
        if dangerous:
            names = [p.split()[0] for p in dangerous[:3]]
            checks.append(_check("failed", "Dangerous privileges enabled",
                                 f"{len(dangerous)} high-risk privilege(s): {', '.join(names)}"))
        else:
            checks.append(_check("info", "User privileges",
                                 f"{len(priv_lines)} privilege(s) enabled — none flagged critical."))

    # ── Firewall ──
    fw_lines = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["firewall"]), 5)
    if fw_lines:
        inventory["firewall"] = fw_lines
        fw_off = [f for f in fw_lines if "DISABLED" in f.upper()]
        if fw_off:
            checks.append(_check("failed", "Windows Firewall disabled",
                                 f"Firewall is OFF for: {', '.join(fw_off)}"))
        else:
            checks.append(_check("success", "Windows Firewall",
                                 "Firewall is enabled on all profiles."))

    # ── Windows Defender ──
    defender = run_ps(WINDOWS_PS_COMMANDS["defender_status"]).strip().lower()
    if defender in ("true", "1"):
        inventory["defender"] = "enabled"
        checks.append(_check("success", "Windows Defender", "Real-time protection is active."))
    elif defender in ("false", "0"):
        inventory["defender"] = "disabled"
        checks.append(_check("failed", "Windows Defender disabled",
                             "Antivirus real-time protection is OFF!"))

    # ── Missing updates (Windows Update API) ──
    wu_raw = run_ps(WINDOWS_PS_COMMANDS["missing_updates"])
    if wu_raw and "WUA_UNAVAILABLE" not in wu_raw:
        missing = _non_empty_lines(wu_raw, 20)
        if missing:
            inventory["package_updates"] = missing
            checks.append(_check("failed", "Missing Windows updates",
                                 f"{len(missing)} update(s) not installed — patch immediately."))
        else:
            checks.append(_check("success", "Windows updates",
                                 "No pending updates (Windows Update API)."))

    # ── Hotfixes history ──
    hf_lines = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["hotfixes"]), 15)
    if hf_lines:
        inventory["hotfixes"] = hf_lines
        checks.append(_check("info", "Installed hotfixes",
                             f"{len(hf_lines)} recent hotfix(es) found."))

    # ── Running services ──
    inventory["services"]           = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["services"]), 25)
    inventory["listening_services"] = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["open_ports"]), 20)

    # ── Installed software ──
    sw_list = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["installed_sw"]), 25)
    if sw_list:
        inventory["installed_software"] = sw_list
        checks.append(_check("info", "Installed software",
                             f"{len(sw_list)} installed program(s) found."))

    # ── Shared folders ──
    shares = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["shares"]), 10)
    if shares:
        inventory["shares"] = shares
        admin_shares = [s for s in shares if any(s.upper().startswith(p)
                        for p in ("C$", "D$", "ADMIN$", "IPC$"))]
        if admin_shares:
            checks.append(_check("info", "Admin shares present",
                                 f"Default admin shares: {', '.join(admin_shares[:3])}"))

    # ── Startup programs ──
    startup = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["startup"]), 10)
    if startup:
        inventory["startup"] = startup

    # ── Sensitive env variables ──
    env_hits = _non_empty_lines(run_ps(WINDOWS_PS_COMMANDS["env_secrets"]), 8)
    if env_hits:
        inventory["env_secrets"] = ["[REDACTED — sensitive variable name detected]"] * len(env_hits)
        checks.append(_check("failed", "Sensitive env variables",
                             f"{len(env_hits)} env variable(s) with sensitive-looking names."))

    return _base_result("winrm", username, "success",
                        "Windows authenticated scan completed.", checks, inventory)


# ─────────────────────────────────────────────────────────
# HTTP Basic Scan
# ─────────────────────────────────────────────────────────

def _http_basic_scan(target, username, password):
    urls = normalize_url(target)
    if not urls:
        return _base_result("http_basic", username, "failed",
                            "No valid website URL for HTTP authentication.",
                            [_check("failed", "HTTP target", "Target could not be normalized as a URL.")])

    session = requests.Session()
    session.headers.update({"User-Agent": "Vulnix-AuthenticatedScanner/1.0"})
    errors = []

    for url in urls:
        try:
            anonymous     = session.get(url, timeout=6, allow_redirects=True)
            authenticated = session.get(url, auth=HTTPBasicAuth(username, password),
                                        timeout=6, allow_redirects=True)
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
            continue

        challenge = anonymous.status_code in (401, 403) or bool(
            anonymous.headers.get("WWW-Authenticate"))

        if not challenge:
            return _base_result("http_basic", username, "unavailable",
                                "Target did not request HTTP Basic credentials.",
                                [_check("info", "Anonymous HTTP access",
                                        f"{anonymous.url} returned {anonymous.status_code} without auth challenge.")])

        if authenticated.status_code not in (401, 403) and authenticated.status_code < 500:
            checks    = [_check("success", "HTTP Basic login",
                                f"{authenticated.url} returned HTTP {authenticated.status_code}.")]
            inventory = {"authenticated_url": authenticated.url,
                         "status_code": authenticated.status_code}

            protected, exposed, path_errors = [], [], []
            for path in COMMON_AUTH_PATHS:
                path_url = authenticated.url.rstrip("/") + path
                try:
                    ar = session.get(path_url, timeout=5, allow_redirects=True)
                    aa = session.get(path_url, auth=HTTPBasicAuth(username, password),
                                     timeout=5, allow_redirects=True)
                except requests.RequestException as exc:
                    path_errors.append(f"{path}: {exc}")
                    continue
                if ar.status_code in (401, 403) and aa.status_code < 400:
                    protected.append(f"{path} → {aa.status_code}")
                elif ar.status_code < 400:
                    exposed.append(f"{path} → public")

            if protected:
                checks.append(_check("success", "Credentialed web paths",
                                     f"{len(protected)} protected path(s) unlocked."))
                inventory["protected_paths"] = protected
            else:
                checks.append(_check("info", "Credentialed web paths",
                                     "No additional protected paths confirmed."))

            if exposed:
                inventory["public_paths"] = exposed[:10]
            if authenticated.headers.get("Server"):
                inventory["server"] = authenticated.headers["Server"]
            if authenticated.headers.get("Set-Cookie"):
                inventory["cookie_flags"] = authenticated.headers["Set-Cookie"][:200]
                checks.append(_check("info", "Session cookie",
                                     "Authenticated response set a session cookie."))
            if path_errors:
                inventory["path_errors"] = path_errors[:8]

            return _base_result("http_basic", username, "success",
                                "HTTP Basic credentials were accepted.", checks, inventory)

        return _base_result("http_basic", username, "failed",
                            "HTTP Basic credentials were rejected.",
                            [_check("failed", "HTTP Basic login",
                                    f"{authenticated.url} returned HTTP {authenticated.status_code}.")])

    return _base_result("http_basic", username, "failed",
                        "Could not connect for HTTP authentication.",
                        [_check("failed", "HTTP connection",
                                "; ".join(errors) or "Connection failed.")])


# ─────────────────────────────────────────────────────────
# Public entry-point
# ─────────────────────────────────────────────────────────

def run_authenticated_checks(target, auth_type, username, password,
                              port=None, ssh_key=None):
    """
    Parameters
    ----------
    target    : hostname / IP to scan
    auth_type : 'ssh' | 'winrm' | 'http_basic'
    username  : login username
    password  : login password  (ignored when ssh_key provided for SSH)
    port      : optional custom port (int or str)
    ssh_key   : optional PEM private key text (SSH only)
    """
    auth_type = (auth_type or "http_basic").strip()
    username  = (username or "").strip()
    password  = password or ""

    if not username:
        return _base_result(auth_type, username, "failed",
                            "Authenticated scan requires a username.",
                            [_check("failed", "Credentials", "Username is missing.")])

    if auth_type == "ssh":
        if not password and not (ssh_key and ssh_key.strip()):
            return _base_result("ssh", username, "failed",
                                "SSH scan requires a password or a private key.",
                                [_check("failed", "Credentials",
                                        "No password and no private key provided.")])
        return _ssh_scan(target, username, password,
                         port=port or 22, ssh_key_text=ssh_key)

    if auth_type == "winrm":
        if not password:
            return _base_result("winrm", username, "failed",
                                "WinRM scan requires a password.",
                                [_check("failed", "Credentials", "Password is missing.")])
        return _windows_scan(target, username, password, port=port or 5985)

    # default: http_basic
    if not password:
        return _base_result("http_basic", username, "failed",
                            "HTTP Basic scan requires a password.",
                            [_check("failed", "Credentials", "Password is missing.")])
    return _http_basic_scan(target, username, password)
