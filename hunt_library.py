"""
Static knowledge used to turn names mentioned in an advisory into huntable artifacts.

- TOOLS:      software names (STIX `malware` / `tool` objects) -> process names / domains
- TECHNIQUES: MITRE ATT&CK IDs -> broad Splunk hunt queries
- CVES:       product context for CVEs commonly listed in #StopRansomware advisories

Query templates use two placeholders filled at runtime:
  {scope}    e.g. index=*            (user configurable in the UI)
  {earliest} e.g. -90d               (user configurable in the UI)
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


# --------------------------------------------------------------------------- #
# ATT&CK technique -> broad hunt queries
# --------------------------------------------------------------------------- #
_PROC_SUFFIX = """
| eval cmd=substr(coalesce(process, CommandLine, Process_Command_Line, ScriptBlockText, _raw), 1, 400)
| fillnull value="-" host user
| stats count min(_time) AS first_seen max(_time) AS last_seen values(sourcetype) AS sourcetype values(cmd) AS command_line BY host user
| convert ctime(first_seen) ctime(last_seen)
| sort - count"""

_EXFIL_DOMAINS = '"mega.nz" OR "mega.io" OR "backblazeb2.com" OR "transfer.sh" OR "gofile.io" OR "file.io" OR "temp.sh" OR "filemail.com" OR "sendspace.com" OR "anonfiles" OR "pcloud.com"'

_DISCOVERY = [{
    "title": "AD / network discovery commands",
    "spl": "{scope} earliest={earliest} ((\"nltest\" (\"/dclist\" OR \"/domain_trusts\")) OR (\"net\" \"group\" \"domain admins\") OR (\"net\" \"view\" \"/all\") OR \"AdFind.exe\" OR \"advanced_ip_scanner\" OR \"netscan.exe\" OR \"SharpHound\")" + _PROC_SUFFIX,
    "note": "Admins run some of these legitimately. Look for workstations or service accounts you wouldn't expect.",
}]

TECHNIQUES = {
    "T1490": [{
        "title": "Shadow copy / backup deletion",
        "spl": "{scope} earliest={earliest} ((\"vssadmin\" \"delete\" \"shadows\") OR (\"wmic\" \"shadowcopy\" \"delete\") OR (\"bcdedit\" \"recoveryenabled\" \"no\") OR (\"wbadmin\" \"delete\") OR (\"Win32_ShadowCopy\" \"Delete\"))" + _PROC_SUFFIX,
        "note": "Any hit is high-fidelity ransomware precursor activity.",
    }],
    "T1059.001": [{
        "title": "Suspicious PowerShell (encoded / download cradles)",
        "spl": "{scope} earliest={earliest} (\"powershell\" OR \"pwsh\" OR EventCode=4104) (\"-enc\" OR \"-encodedcommand\" OR \"FromBase64String\" OR \"DownloadString\" OR \"DownloadFile\" OR \"Invoke-Expression\" OR \"IEX\" OR \"-ExecutionPolicy Bypass\" OR \"-w hidden\")" + _PROC_SUFFIX,
        "note": "Noisy in environments with management scripts. Baseline known-good hosts and parents, then exclude them.",
    }],
    "T1059.003": [{
        "title": "cmd.exe spawned by server / Office processes (CIM Endpoint)",
        "spl": "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Processes.process) AS command_line from datamodel=Endpoint.Processes where earliest={earliest} Processes.process_name=\"cmd.exe\" Processes.parent_process_name IN (\"w3wp.exe\", \"sqlservr.exe\", \"java.exe\", \"tomcat*.exe\", \"httpd.exe\", \"php-cgi.exe\", \"winword.exe\", \"excel.exe\", \"outlook.exe\") by Processes.dest Processes.user Processes.parent_process_name\n| rename Processes.* AS *\n| convert ctime(first_seen) ctime(last_seen)",
        "note": "Requires the CIM Endpoint data model (EDR or Sysmon mapped to CIM).",
    }],
    "T1569.002": [{
        "title": "New service installed (EventCode 7045)",
        "spl": "{scope} earliest={earliest} (EventCode=7045 OR EventID=7045)\n| eval svc_name=coalesce(Service_Name, ServiceName), svc_path=coalesce(Service_File_Name, ImagePath)\n| fillnull value=\"-\" svc_name svc_path\n| stats count min(_time) AS first_seen max(_time) AS last_seen values(svc_path) AS service_path dc(host) AS host_count values(host) AS hosts BY svc_name\n| convert ctime(first_seen) ctime(last_seen)\n| sort host_count",
        "note": "Rare service names on few hosts are the interesting ones (PSEXESVC, random names, paths in \\Temp or \\ProgramData).",
    }],
    "T1021.001": [{
        "title": "RDP logons (4624 type 10)",
        "spl": "{scope} earliest={earliest} EventCode=4624 (Logon_Type=10 OR LogonType=10)\n| eval src=coalesce(Source_Network_Address, IpAddress, src), user=coalesce(TargetUserName, mvindex(Account_Name, -1), user)\n| fillnull value=\"-\" src user\n| stats count min(_time) AS first_seen max(_time) AS last_seen dc(host) AS dest_count values(host) AS dests BY user src\n| convert ctime(first_seen) ctime(last_seen)\n| sort - dest_count",
        "note": "One account/source fanning out to many hosts is lateral movement.",
    }],
    "T1021.002": [{
        "title": "Admin share access (ADMIN$ / C$)",
        "spl": "{scope} earliest={earliest} (EventCode=5140 OR EventCode=5145) (\"ADMIN$\" OR \"C$\")\n| eval src=coalesce(Source_Address, IpAddress, src), user=coalesce(SubjectUserName, Account_Name, user), share=coalesce(Share_Name, ShareName)\n| fillnull value=\"-\" src user share\n| stats count min(_time) AS first_seen max(_time) AS last_seen dc(host) AS dest_count values(host) AS dests BY user src share\n| convert ctime(first_seen) ctime(last_seen)\n| sort - dest_count",
        "note": "Requires File Share auditing. Compare against known admin jump hosts.",
    }],
    "T1021.006": [{
        "title": "WinRM remote sessions",
        "spl": "{scope} earliest={earliest} (\"wsmprovhost.exe\" OR \"winrshost.exe\" OR (sourcetype=*WinRM* EventCode=91))" + _PROC_SUFFIX,
        "note": "wsmprovhost.exe = inbound PowerShell remoting on that host.",
    }],
    "T1110": [
        {
            "title": "Windows brute force / password spray",
            "spl": "{scope} earliest={earliest} (EventCode=4625 OR EventCode=4771)\n| eval src=coalesce(Source_Network_Address, IpAddress, Client_Address, src), user=coalesce(TargetUserName, mvindex(Account_Name, -1), user)\n| bin _time span=15m\n| stats count AS failures dc(user) AS users_tried values(user) AS users BY _time src\n| where failures>=20 OR users_tried>=10\n| sort - failures",
            "note": "Tune thresholds for your environment.",
        },
        {
            "title": "VPN / SSO auth failures (CIM Authentication)",
            "spl": "| tstats summariesonly=false count AS failures dc(Authentication.user) AS users_tried from datamodel=Authentication where earliest={earliest} Authentication.action=failure by _time span=15m Authentication.src Authentication.app\n| rename Authentication.* AS *\n| where failures>=20 OR users_tried>=10\n| iplocation src\n| sort - failures",
            "note": "Covers firewall / VPN auth if your TAs map to CIM Authentication.",
        },
    ],
    "T1133": [{
        "title": "Successful remote-access logins from outside the US (CIM Authentication)",
        "spl": "| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Authentication.app) AS app from datamodel=Authentication where earliest={earliest} Authentication.action=success by Authentication.user Authentication.src\n| rename Authentication.* AS *\n| iplocation src\n| search Country=* Country!=\"United States\"\n| convert ctime(first_seen) ctime(last_seen)\n| sort - count",
        "note": "Filter app to your VPN / RDP gateway. Review new or foreign sources for each user.",
    }],
    "T1548.002": [{
        "title": "UAC bypass indicators",
        "spl": "{scope} earliest={earliest} (\"ms-settings\\\\shell\\\\open\\\\command\" OR \"mscfile\\\\shell\\\\open\\\\command\" OR \"exefile\\\\shell\\\\open\\\\command\" OR \"fodhelper.exe\" OR \"computerdefaults.exe\" OR \"sdclt.exe\")" + _PROC_SUFFIX,
        "note": "Registry writes to these keys or child processes of fodhelper/computerdefaults are suspicious.",
    }],
    "T1070.004": [{
        "title": "File deletion / log clearing",
        "spl": "{scope} earliest={earliest} (\"sdelete.exe\" OR \"sdelete64.exe\" OR (\"cipher\" \"/w\") OR (\"wevtutil\" \"cl\") OR \"Clear-EventLog\" OR EventCode=1102 OR (EventCode=104 sourcetype=*System*))" + _PROC_SUFFIX,
        "note": "EventCode 1102/104 means a log was cleared. That's always worth a look.",
    }],
    "T1560.001": [{
        "title": "Password-protected / split archives (staging)",
        "spl": "{scope} earliest={earliest} (\"7z.exe\" OR \"7za.exe\" OR \"rar.exe\" OR \"WinRAR.exe\")\n| eval cmd=coalesce(process, CommandLine, Process_Command_Line)\n| regex cmd=\"(?i)\\s-(h?p\\S+|mhe=on|v\\d+[kmg])\"\n| fillnull value=\"-\" host user\n| stats count min(_time) AS first_seen max(_time) AS last_seen values(cmd) AS command_line BY host user\n| convert ctime(first_seen) ctime(last_seen)",
        "note": "Password (-p/-hp), header encryption, or volume split flags.",
    }],
    "T1567": [{
        "title": "Traffic to file-sharing / cloud-storage exfil services",
        "spl": "{scope} earliest={earliest} (" + _EXFIL_DOMAINS + ")\n| eval dest_host=coalesce(url, query, dest, dest_host, site)\n| fillnull value=\"-\" src user\n| stats count sum(bytes_out) AS bytes_out values(dest_host) AS destinations BY src user\n| sort - bytes_out",
        "note": "Proxy / DNS / firewall data. Large bytes_out to these services stands out.",
    }],
    "T1048": [{
        "title": "Large outbound transfers to external hosts (CIM Network_Traffic)",
        "spl": "| tstats summariesonly=false sum(All_Traffic.bytes_out) AS bytes_out count from datamodel=Network_Traffic where earliest={earliest} by All_Traffic.src All_Traffic.dest All_Traffic.dest_port\n| rename All_Traffic.* AS *\n| where NOT (cidrmatch(\"10.0.0.0/8\", dest) OR cidrmatch(\"172.16.0.0/12\", dest) OR cidrmatch(\"192.168.0.0/16\", dest))\n| where bytes_out > 1073741824\n| eval GB_out=round(bytes_out/1024/1024/1024, 2)\n| sort - bytes_out",
        "note": "More than 1 GB out to one external destination. Check for FTP/SFTP (21/22/990) and odd ports.",
    }],
    "T1098": [{
        "title": "Account creation / group / password changes",
        "spl": "{scope} earliest={earliest} EventCode IN (4720, 4722, 4724, 4728, 4732, 4738, 4756, 4781)\n| eval actor=coalesce(SubjectUserName, mvindex(Account_Name, 0)), target=coalesce(TargetUserName, mvindex(Account_Name, -1)), group=coalesce(Group_Name, TargetUserName)\n| stats count min(_time) AS first_seen max(_time) AS last_seen values(EventCode) AS event_codes values(target) AS targets values(host) AS hosts BY actor\n| convert ctime(first_seen) ctime(last_seen)\n| sort - count",
        "note": "Watch for new accounts added to Domain Admins / Administrators.",
    }],
    "T1486": [{
        "title": "Mass file creation / renames (Sysmon 11)",
        "spl": "{scope} earliest={earliest} sourcetype=*sysmon* (EventCode=11 OR EventCode=23)\n| eval ext=lower(replace(TargetFilename, \"^.*\\.\", \"\"))\n| bin _time span=5m\n| stats dc(TargetFilename) AS files values(Image) AS process BY _time host ext\n| where files > 300\n| sort - files",
        "note": "Hundreds of files with one new extension in 5 minutes suggests encryption. EDR alerts usually fire first.",
    }],
    "T1562.001": [{
        "title": "Security tool tampering",
        "spl": "{scope} earliest={earliest} ((\"Set-MpPreference\" (\"DisableRealtimeMonitoring\" OR \"DisableBehaviorMonitoring\" OR \"DisableIOAVProtection\" OR \"ExclusionPath\" OR \"ExclusionProcess\")) OR (\"Add-MpPreference\" \"Exclusion*\") OR (\"sc\" (\"stop\" OR \"config\" OR \"delete\") (\"WinDefend\" OR \"Sense\" OR \"CSFalconService\" OR \"SentinelAgent\")) OR (\"netsh\" \"advfirewall\" \"off\") OR \"DisableAntiSpyware\" OR EventCode=5001 OR \"EDRKillShifter\" OR \"AuKill\" OR \"Backstab\")" + _PROC_SUFFIX,
        "note": "Defender EventCode 5001 = real-time protection disabled. Also review EDR tamper alerts.",
    }],
    "T1003.001": [{
        "title": "LSASS credential dumping",
        "spl": "{scope} earliest={earliest} ((EventCode=10 TargetImage=\"*\\\\lsass.exe\" GrantedAccess IN (\"0x1010\", \"0x1410\", \"0x1438\", \"0x143a\", \"0x1fffff\")) OR (\"procdump\" \"lsass\") OR (\"comsvcs\" \"MiniDump\") OR \"sekurlsa::\")\n| eval cmd=substr(coalesce(process, CommandLine, SourceImage, _raw), 1, 400)\n| fillnull value=\"-\" host\n| stats count min(_time) AS first_seen max(_time) AS last_seen values(cmd) AS source BY host\n| convert ctime(first_seen) ctime(last_seen)",
        "note": "Exclude known AV/EDR SourceImages after the first run.",
    }],
    "T1047": [{
        "title": "WMI remote process creation",
        "spl": "{scope} earliest={earliest} ((\"wmic\" \"/node:\") OR (\"wmic\" \"process\" \"call\" \"create\") OR \"Invoke-WmiMethod\" OR \"Win32_Process\")" + _PROC_SUFFIX,
        "note": "",
    }],
    "T1053.005": [{
        "title": "Scheduled task creation",
        "spl": "{scope} earliest={earliest} (EventCode=4698 OR (\"schtasks\" \"/create\") OR \"Register-ScheduledTask\")" + _PROC_SUFFIX,
        "note": "Tasks that run from Temp, ProgramData, or user profile paths are the interesting ones.",
    }],
    "T1105": [{
        "title": "Ingress tool transfer via LOLBins",
        "spl": "{scope} earliest={earliest} ((\"certutil\" (\"urlcache\" OR \"-split\")) OR (\"bitsadmin\" \"/transfer\") OR \"Start-BitsTransfer\" OR \"DownloadFile\" OR (\"curl\" \"-o\" \".exe\"))" + _PROC_SUFFIX,
        "note": "",
    }],
    "T1018": _DISCOVERY, "T1087": _DISCOVERY, "T1087.002": _DISCOVERY, "T1482": _DISCOVERY,
    "T1046": _DISCOVERY, "T1069": _DISCOVERY, "T1069.002": _DISCOVERY, "T1016": _DISCOVERY,
}
# aliases
TECHNIQUES["T1685"] = TECHNIQUES["T1562.001"]       # ATT&CK v19 "Defense Impairment / Disable or Modify Tools"
TECHNIQUES["T1562"] = TECHNIQUES["T1562.001"]
TECHNIQUES["T1543.003"] = TECHNIQUES["T1569.002"]
TECHNIQUES["T1003"] = TECHNIQUES["T1003.001"]
TECHNIQUES["T1070.001"] = TECHNIQUES["T1070.004"]
TECHNIQUES["T1110.003"] = TECHNIQUES["T1110"]
TECHNIQUES["T1110.001"] = TECHNIQUES["T1110"]

# Techniques where we deliberately give pointers instead of a query
TECHNIQUE_POINTERS = {
    "T1190": "Hunted with the CVE queries. Check WAF, VPN and firewall logs on the exposed devices listed there.",
    "T1219": "Hunted with the Tools & Software queries (remote access software).",
    "T1027": "Packed or obfuscated binaries are hunted with the hash IOCs.",
    "T1027.002": "Packed binaries are hunted with the hash IOCs.",
    "T1078": "Valid accounts: review the Authentication / RDP / VPN queries for unusual sources.",
    "T1560.002": "Archiving via a library happens inside the malware. Hunt the hash IOCs and T1560.001 staging.",
    "T1059": "See the PowerShell (T1059.001) and cmd (T1059.003) queries.",
    "T1021": "See the RDP, SMB and WinRM queries.",
    "T1218": "System binary proxy execution: baseline rundll32/regsvr32/mshta with unusual command lines.",
}


def technique_queries(tid: str):
    if tid in TECHNIQUES:
        return TECHNIQUES[tid]
    return None
