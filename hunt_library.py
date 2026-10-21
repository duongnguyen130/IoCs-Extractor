"""
Static knowledge used to turn names mentioned in an advisory into huntable artifacts.

- TOOLS:      software names (STIX `malware` / `tool` objects) -> process names / domains
- CVES:       product context for CVEs commonly listed in #StopRansomware advisories
"""

import re


def norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# --------------------------------------------------------------------------- #
# Tools / software commonly abused by ransomware affiliates
#   noisy=True  -> legitimate admin software that is everywhere; excluded from the
#                  main sweep and hunted with a "rare usage" query instead.
# --------------------------------------------------------------------------- #
TOOLS = {
    "anydesk":        {"label": "AnyDesk", "kind": "Remote access (RMM)", "processes": ["AnyDesk.exe"], "domains": ["anydesk.com"]},
    "screenconnect":  {"label": "ScreenConnect", "kind": "Remote access (RMM)", "processes": ["ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.Service.exe"], "domains": ["screenconnect.com"]},
    "simplehelp":     {"label": "SimpleHelp", "kind": "Remote access (RMM)", "processes": ["Remote Access.exe", "session_win.exe"], "keywords": ["JWrapper-Remote Access", "SimpleHelp"]},
    "teamviewer":     {"label": "TeamViewer", "kind": "Remote access (RMM)", "processes": ["TeamViewer.exe", "TeamViewer_Service.exe"], "domains": ["teamviewer.com"], "noisy": True},
    "atera":          {"label": "Atera", "kind": "Remote access (RMM)", "processes": ["AteraAgent.exe"], "domains": ["atera.com"]},
    "splashtop":      {"label": "Splashtop", "kind": "Remote access (RMM)", "processes": ["SRService.exe", "SRManager.exe", "strwinclt.exe"], "domains": ["splashtop.com"]},
    "ngrok":          {"label": "ngrok", "kind": "Tunneling", "processes": ["ngrok.exe"], "domains": ["ngrok.io", "ngrok-free.app"]},
    "rclone":         {"label": "Rclone", "kind": "Exfiltration", "processes": ["rclone.exe"], "keywords": ["rclone.conf"]},
    "megasync":       {"label": "MEGAsync", "kind": "Exfiltration", "processes": ["MEGAsync.exe"], "domains": ["mega.nz", "mega.io"]},
    "backblaze":      {"label": "Backblaze", "kind": "Exfiltration (cloud storage)", "processes": ["bzbui.exe", "bzserv.exe", "bztransmit.exe"], "domains": ["backblazeb2.com", "backblaze.com"]},
    "filezilla":      {"label": "FileZilla", "kind": "Exfiltration (FTP/SFTP)", "processes": ["filezilla.exe", "fzsftp.exe"]},
    "winscp":         {"label": "WinSCP", "kind": "Exfiltration (SFTP)", "processes": ["WinSCP.exe"]},
    "putty":          {"label": "PuTTY", "kind": "Remote shell / tunneling", "processes": ["putty.exe", "plink.exe", "pscp.exe"]},
    "psexec":         {"label": "PsExec", "kind": "Lateral movement", "processes": ["PsExec.exe", "PsExec64.exe", "PSEXESVC.exe"]},
    "mimikatz":       {"label": "Mimikatz", "kind": "Credential dumping", "processes": ["mimikatz.exe"], "keywords": ["sekurlsa::", "lsadump::", "kerberos::"]},
    "procdump":       {"label": "ProcDump", "kind": "Credential dumping", "processes": ["procdump.exe", "procdump64.exe"]},
    "adfind":         {"label": "AdFind", "kind": "Discovery", "processes": ["AdFind.exe"]},
    "sharphound":     {"label": "SharpHound", "kind": "Discovery", "processes": ["SharpHound.exe"], "keywords": ["SharpHound"]},
    "bloodhound":     {"label": "BloodHound", "kind": "Discovery", "processes": ["SharpHound.exe"], "keywords": ["SharpHound", "BloodHound"]},
    "netscan":        {"label": "SoftPerfect NetScan", "kind": "Discovery", "processes": ["netscan.exe"]},
    "softperfect":    {"label": "SoftPerfect NetScan", "kind": "Discovery", "processes": ["netscan.exe"]},
    "advancedipscanner": {"label": "Advanced IP Scanner", "kind": "Discovery", "processes": ["advanced_ip_scanner.exe"]},
    "ccleaner":       {"label": "CCleaner", "kind": "Anti-forensics", "processes": ["CCleaner.exe", "CCleaner64.exe"]},
    "winrar":         {"label": "WinRAR", "kind": "Archiving / staging", "processes": ["WinRAR.exe", "Rar.exe"], "noisy": True},
    "7zip":           {"label": "7-Zip", "kind": "Archiving / staging", "processes": ["7z.exe", "7za.exe", "7zG.exe"], "noisy": True},
    "winrm":          {"label": "WinRM", "kind": "Lateral movement", "processes": ["wsmprovhost.exe", "winrshost.exe", "winrs.exe"], "noisy": True},
    "powershell":     {"label": "PowerShell", "kind": "Execution", "processes": ["powershell.exe", "pwsh.exe"], "noisy": True},
    "certutil":       {"label": "certutil", "kind": "LOLBin", "processes": ["certutil.exe"], "noisy": True},
    "bitsadmin":      {"label": "BITSAdmin", "kind": "LOLBin", "processes": ["bitsadmin.exe"], "noisy": True},
    "vssadmin":       {"label": "vssadmin", "kind": "Inhibit recovery", "processes": ["vssadmin.exe"], "noisy": True},
    "nltest":         {"label": "nltest", "kind": "Discovery", "processes": ["nltest.exe"], "noisy": True},
    "wmic":           {"label": "WMIC", "kind": "Execution", "processes": ["wmic.exe"], "noisy": True},
    "cobaltstrike":   {"label": "Cobalt Strike", "kind": "C2 framework", "processes": [], "keywords": ["Cobalt Strike", "CobaltStrike", "beacon.dll"]},
    "impacket":       {"label": "Impacket", "kind": "Lateral movement", "processes": [], "keywords": ["__output", "wmiexec", "smbexec", "secretsdump"]},
}


def lookup_tool(name: str):
    """Return the TOOLS entry for a software name, or None."""
    key = norm_name(name)
    if not key:
        return None
    if key in TOOLS:
        return TOOLS[key]
    for k, v in TOOLS.items():
        if len(k) >= 5 and k in key:
            return v
    return None


# --------------------------------------------------------------------------- #
# CVE context (products affected) – used to tell the analyst which log sources
# matter. Unknown CVEs still get NVD / KEV links.
# --------------------------------------------------------------------------- #
CVES = {
    "CVE-2024-40766": {"product": "SonicWall SonicOS (SSLVPN / management)", "issue": "Improper access control", "sourcetypes": ["*sonicwall*"]},
    "CVE-2020-3259":  {"product": "Cisco ASA / FTD (web services)", "issue": "Information disclosure", "sourcetypes": ["cisco:asa", "*cisco:ftd*"]},
    "CVE-2023-20269": {"product": "Cisco ASA / FTD (remote-access VPN)", "issue": "Brute force / unauthorized VPN access", "sourcetypes": ["cisco:asa", "*cisco:ftd*"]},
    "CVE-2024-40711": {"product": "Veeam Backup & Replication", "issue": "Deserialization RCE", "sourcetypes": ["*veeam*"]},
    "CVE-2023-27532": {"product": "Veeam Backup & Replication", "issue": "Credential exposure (TCP 9401)", "sourcetypes": ["*veeam*"]},
    "CVE-2023-48788": {"product": "Fortinet FortiClient EMS", "issue": "SQL injection RCE", "sourcetypes": ["*forti*"]},
    "CVE-2025-10035": {"product": "Fortra GoAnywhere MFT", "issue": "License servlet deserialization", "sourcetypes": ["*goanywhere*"]},
    "CVE-2024-1709":  {"product": "ConnectWise ScreenConnect", "issue": "Authentication bypass", "sourcetypes": ["*screenconnect*", "*connectwise*"]},
    "CVE-2024-55591": {"product": "Fortinet FortiOS / FortiProxy", "issue": "Authentication bypass (Node.js websocket)", "sourcetypes": ["fortigate*", "*forti*"]},
    "CVE-2025-24472": {"product": "Fortinet FortiOS / FortiProxy", "issue": "Authentication bypass (CSF proxy)", "sourcetypes": ["fortigate*", "*forti*"]},
}


# --------------------------------------------------------------------------- #
# Shared infrastructure – IPs here are real IOCs in the advisory but will also
# match lots of benign traffic. We flag them, we don't drop them.
# --------------------------------------------------------------------------- #
SHARED_INFRA = [
    ("140.82.112.0/20", "GitHub"),
    ("185.199.108.0/22", "GitHub (githubusercontent / Pages)"),
    ("192.30.252.0/22", "GitHub"),
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("162.158.0.0/15", "Cloudflare"),
    ("173.194.0.0/16", "Google"),
    ("142.250.0.0/15", "Google"),
    ("172.217.0.0/16", "Google"),
    ("8.8.8.0/24", "Google DNS"),
    ("1.1.1.0/24", "Cloudflare DNS"),
]
