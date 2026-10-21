"""
Generate "recommended broad search" SPL for each IOC category.

Every atomic-IOC search follows the same pattern:
  1. raw term search across the configured scope (catches any field name / TA)
  2. rex to pull out WHICH IOC matched
  3. stats by IOC with first/last seen, indexes, sourcetypes, hosts
Where it helps, a CIM data model (tstats) alternative is added.
"""

import re

from . import hunt_library as lib
from .extractor import CATEGORIES

MAX_INLINE = 500  # beyond this, recommend a lookup instead of inline OR lists


def _q(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _in(values) -> str:
    return "(" + ", ".join(_q(v) for v in values) + ")"


def _rx(values) -> str:
    """Regex alternation, escaped for use inside an SPL double-quoted string."""
    parts = sorted({re.escape(v) for v in values}, key=len, reverse=True)
    alt = "|".join(parts)
    return alt.replace("\\\\", "\\\\\\\\").replace('"', '\\"')


def _terms(values) -> str:
    return " OR ".join(_q(v) for v in values)


def _broad(values, scope, earliest, rx_values=None, pre="", post="", lower=True):
    rx_values = rx_values or values
    spl = (
        f"{scope} earliest={earliest} latest=now\n"
        f"    ({_terms(values)})\n"
        f"| rex field=_raw max_match=0 \"(?i){pre}(?<ioc_hit>{_rx(rx_values)}){post}\"\n"
        f"| fillnull value=\"(term match - check _raw)\" ioc_hit\n"
        f"| mvexpand ioc_hit\n"
    )
    if lower:
        spl += "| eval ioc_hit=lower(ioc_hit)\n"
    spl += (
        "| stats count AS hits min(_time) AS first_seen max(_time) AS last_seen "
        "values(index) AS index values(sourcetype) AS sourcetype dc(host) AS host_count values(host) AS hosts BY ioc_hit\n"
        "| convert ctime(first_seen) ctime(last_seen)\n"
        "| sort - hits"
    )
    return spl


def _size_note(n):
    if n > MAX_INLINE:
        return (f" {n} values is a lot to inline. Consider uploading the list as a lookup "
                "(| inputlookup cisa_iocs.csv) and using a subsearch instead.")
    return ""


def _q_ips(items, scope, earliest):
    vals = [i["value"] for i in items]
    noisy = [i["value"] for i in items if any("Shared infrastructure" in c for c in i["context"])]
    singles = [v for v in vals if "/" not in v]
    out = [{
        "title": "Broad sweep: any log containing these IPs",
        "spl": _broad(singles or vals, scope, earliest, pre=r"(?<![\d.])", post=r"(?![\d.])", lower=False),
        "note": "Searches raw events in every index in scope (firewall, proxy, VPN, EDR, DNS, auth)." + _size_note(len(vals))
                + (f" Heads up: {', '.join(noisy)} are shared CDN/cloud addresses, so expect benign hits." if noisy else ""),
    }, {
        "title": "CIM Network_Traffic (accelerated, faster)",
        "spl": (
            f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen "
            f"values(All_Traffic.action) AS action values(All_Traffic.dest_port) AS dest_port values(sourcetype) AS sourcetype "
            f"from datamodel=Network_Traffic where earliest={earliest} "
            f"(All_Traffic.src_ip IN {_in(vals)} OR All_Traffic.dest_ip IN {_in(vals)}) "
            f"by All_Traffic.src_ip All_Traffic.dest_ip\n"
            "| rename All_Traffic.* AS *\n"
            "| convert ctime(first_seen) ctime(last_seen)\n"
            "| sort - count"
        ),
        "note": "Only covers sources mapped to the CIM Network_Traffic data model. CIDR values work with IN on IP fields.",
    }]
    return out


def _q_domains(items, scope, earliest):
    vals = [i["value"] for i in items]
    return [{
        "title": "Broad sweep: any log containing these domains",
        "spl": _broad(vals, scope, earliest, pre=r"(?<![\w-])", post=r"(?![\w-])"),
        "note": "Matches subdomains too (e.g. x.domain.com)." + _size_note(len(vals)),
    }, {
        "title": "CIM DNS + Web (accelerated)",
        "spl": (
            f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(DNS.src) AS src "
            f"from datamodel=Network_Resolution where earliest={earliest} DNS.query IN {_in(['*' + v for v in vals])} by DNS.query\n"
            "| rename DNS.query AS ioc\n"
            "| eval source_dm=\"DNS\"\n"
            f"| append [| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Web.src) AS src "
            f"from datamodel=Web where earliest={earliest} Web.url IN {_in(['*' + v + '*' for v in vals])} by Web.url "
            "| rename Web.url AS ioc | eval source_dm=\"Web\"]\n"
            "| convert ctime(first_seen) ctime(last_seen)\n"
            "| sort - count"
        ),
        "note": "Leading wildcards are slower but needed to catch subdomains.",
    }]


def _q_urls(items, scope, earliest):
    vals = [i["value"] for i in items]
    stripped = [re.sub(r"^[a-z]+://", "", v, flags=re.I) for v in vals]
    terms = []
    for s in stripped:
        host, _, path = s.partition("/")
        host_only = host.split(":")[0]
        last = path.rstrip("/").split("/")[-1] if path else ""
        terms.append(f'({_q(host_only)} {_q(last)})' if last else _q(host_only))
    spl = (
        f"{scope} earliest={earliest} latest=now\n"
        f"    ({' OR '.join(terms)})\n"
        f"| rex field=_raw max_match=0 \"(?i)(?<ioc_hit>{_rx(stripped)})\"\n"
        "| fillnull value=\"(host+path term match - check _raw)\" ioc_hit\n"
        "| mvexpand ioc_hit\n"
        "| stats count AS hits min(_time) AS first_seen max(_time) AS last_seen values(index) AS index "
        "values(sourcetype) AS sourcetype values(src) AS src values(user) AS user BY ioc_hit\n"
        "| convert ctime(first_seen) ctime(last_seen)\n"
        "| sort - hits"
    )
    return [{
        "title": "Broad sweep: proxy / web / EDR logs for these URLs",
        "spl": spl,
        "note": "Searches host + last path segment so it still matches when proxies log host and path separately.",
    }]


def _q_emails(items, scope, earliest):
    vals = [i["value"] for i in items]
    return [{
        "title": "Broad sweep: mail / O365 / gateway logs for these addresses",
        "spl": _broad(vals, scope, earliest),
        "note": "Ransom-negotiation contact addresses. Any internal mail to or from them is significant.",
    }, {
        "title": "CIM Email (accelerated)",
        "spl": (
            f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(All_Email.subject) AS subject "
            f"from datamodel=Email where earliest={earliest} (All_Email.src_user IN {_in(vals)} OR All_Email.recipient IN {_in(vals)}) "
            "by All_Email.src_user All_Email.recipient\n"
            "| rename All_Email.* AS *\n"
            "| convert ctime(first_seen) ctime(last_seen)"
        ),
        "note": "",
    }]


def _q_hashes(items, scope, earliest, label):
    vals = [i["value"] for i in items]
    return [{
        "title": f"Broad sweep: EDR / Sysmon / AV logs for these {label}",
        "spl": _broad(vals, scope, earliest, pre=r"(?<![0-9a-f])", post=r"(?![0-9a-f])"),
        "note": "Catches Sysmon 'Hashes=SHA256=...' as well as EDR hash fields. Case-insensitive." + _size_note(len(vals)),
    }]


def _q_all_hashes(cats, scope, earliest):
    vals = []
    for k in ("sha256", "sha1", "md5", "sha512"):
        vals += [i["value"] for i in cats.get(k, [])]
    if not vals:
        return None
    return {
        "title": "All hash types in one search",
        "spl": _broad(vals, scope, earliest, pre=r"(?<![0-9a-f])", post=r"(?![0-9a-f])"),
        "note": "SHA-256 + SHA-1 + MD5 combined." + _size_note(len(vals)),
    }


def _q_filenames(items, scope, earliest):
    vals = [i["value"] for i in items]
    generic = [v for v in vals if re.fullmatch(r"(?i)(main|command|cmd|run|setup|update|j|a|b|1|test|svchost|install)\.\w{2,4}", v)]
    return [{
        "title": "Broad sweep: any log mentioning these file names",
        "spl": _broad(vals, scope, earliest, pre=r"(?<![\w.-])", post=r"(?![\w.-])"),
        "note": ("Generic names like " + ", ".join(generic) + " will be noisy. Pivot on the related hash or path." if generic else "")
                + _size_note(len(vals)),
    }, {
        "title": "CIM Endpoint Processes + Filesystem (accelerated)",
        "spl": (
            f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Processes.process) AS command_line "
            f"values(Processes.parent_process_name) AS parent from datamodel=Endpoint.Processes where earliest={earliest} "
            f"Processes.process_name IN {_in(vals)} by Processes.dest Processes.user Processes.process_name\n"
            "| rename Processes.* AS *\n"
            "| eval source_dm=\"Processes\"\n"
            f"| append [| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Filesystem.file_path) AS file_path "
            f"from datamodel=Endpoint.Filesystem where earliest={earliest} Filesystem.file_name IN {_in(vals)} "
            "by Filesystem.dest Filesystem.file_name | rename Filesystem.* AS * | eval source_dm=\"Filesystem\"]\n"
            "| convert ctime(first_seen) ctime(last_seen)"
        ),
        "note": "Shows the host, user, parent process and full command line for each hit.",
    }]


def _q_tools(items, scope, earliest):
    precise, noisy, keywords, domains, labels = [], [], [], [], []
    for i in items:
        t = lib.lookup_tool(i["value"])
        if t:
            (noisy if t.get("noisy") else precise).extend(t["processes"])
            keywords.extend(t.get("keywords", []))
            if not t.get("noisy"):
                domains.extend(t.get("domains", []))
            labels.append(t["label"])
        else:
            precise.append(re.sub(r"[^\w.-]", "", i["value"]) + ".exe")
    precise = list(dict.fromkeys(precise))
    noisy = list(dict.fromkeys(noisy))
    keywords = list(dict.fromkeys(keywords))
    domains = list(dict.fromkeys(domains))
    out = []
    if precise or keywords:
        terms = precise + keywords
        out.append({
            "title": "Broad sweep: execution of named tools (process names and keywords)",
            "spl": _broad(terms, scope, earliest, pre=r"(?<![\w-])", post=r"(?![\w])"),
            "note": "RMM, exfil and credential tools named in the advisory. Check every hit against approved software.",
        })
        out.append({
            "title": "CIM Endpoint Processes: who ran them, where (accelerated)",
            "spl": (
                f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Processes.process) AS command_line "
                f"values(Processes.parent_process_name) AS parent from datamodel=Endpoint.Processes where earliest={earliest} "
                f"Processes.process_name IN {_in(precise)} by Processes.dest Processes.user Processes.process_name\n"
                "| rename Processes.* AS *\n"
                "| convert ctime(first_seen) ctime(last_seen)\n"
                "| sort - count"
            ),
            "note": "",
        })
    if domains:
        out.append({
            "title": "Network: tool / cloud-storage domains (RMM check-ins, exfil endpoints)",
            "spl": _broad(domains, scope, earliest, pre=r"(?<![\w-])", post=r"(?![\w-])"),
            "note": "Proxy/DNS evidence of these tools even when endpoint telemetry is missing.",
        })
    if noisy:
        out.append({
            "title": "Rare usage of common admin tools (baseline outliers)",
            "spl": (
                f"| tstats summariesonly=false count dc(Processes.dest) AS host_count values(Processes.dest) AS hosts "
                f"values(Processes.parent_process_name) AS parents from datamodel=Endpoint.Processes where earliest={earliest} "
                f"Processes.process_name IN {_in(noisy)} by Processes.process_name Processes.user\n"
                "| rename Processes.* AS *\n"
                "| where host_count <= 3\n"
                "| sort host_count"
            ),
            "note": f"{', '.join(noisy)} are legitimate and everywhere, so this looks for users running them on only a few hosts. "
                    "The ATT&CK queries cover malicious use of these more precisely.",
        })
    return out


def _q_names(items, scope, earliest, what):
    vals = []
    for i in items:
        v = re.sub(r"(?i)\s+ransomware$", "", i["value"]).strip()
        vals.append(v)
        vals.extend(a for a in i.get("related", []) if a)
    seen, uniq = set(), []
    for v in vals:
        if v.lower() not in seen:
            seen.add(v.lower())
            uniq.append(v)
    vals = uniq
    out = [{
        "title": f"Broad sweep: AV / EDR / IDS detections naming these {what}",
        "spl": _broad(vals, scope, earliest, pre=r"(?<![a-z])", post=r"(?![a-z])"),
        "note": "Keyword hunt across detection logs. Common words can be noisy, so narrow the scope to security indexes if needed.",
    }]
    if what == "malware families":
        out.append({
            "title": "CIM Malware / IDS signatures (accelerated)",
            "spl": (
                f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen values(Malware_Attacks.dest) AS dest "
                f"from datamodel=Malware where earliest={earliest} Malware_Attacks.signature IN {_in(['*' + v + '*' for v in vals])} "
                "by Malware_Attacks.signature Malware_Attacks.action\n"
                "| rename Malware_Attacks.* AS *\n"
                f"| append [| tstats summariesonly=false count from datamodel=Intrusion_Detection where earliest={earliest} "
                f"IDS_Attacks.signature IN {_in(['*' + v + '*' for v in vals])} by IDS_Attacks.signature IDS_Attacks.src IDS_Attacks.dest "
                "| rename IDS_Attacks.* AS *]\n"
                "| convert ctime(first_seen) ctime(last_seen)"
            ),
            "note": "",
        })
    return out


def _q_cves(items, scope, earliest):
    vals = [i["value"] for i in items]
    sts = []
    for v in vals:
        sts.extend(lib.CVES.get(v, {}).get("sourcetypes", []))
    sts = list(dict.fromkeys(sts))
    out = [{
        "title": "Broad sweep: IDS / WAF / vuln scanner / EDR events referencing these CVEs",
        "spl": _broad(vals, scope, earliest, pre=r"(?<![\w-])", post=r"(?!\d)", lower=False),
        "note": "Picks up IDS signatures, Tenable/Qualys findings, firewall threat logs, etc.",
    }, {
        "title": "CIM Vulnerabilities: which assets are vulnerable (accelerated)",
        "spl": (
            f"| tstats summariesonly=false count latest(_time) AS last_scanned values(Vulnerabilities.severity) AS severity "
            f"values(Vulnerabilities.signature) AS signature from datamodel=Vulnerabilities where earliest={earliest} "
            f"Vulnerabilities.cve IN {_in(vals)} by Vulnerabilities.dest Vulnerabilities.cve\n"
            "| rename Vulnerabilities.* AS *\n"
            "| convert ctime(last_scanned)\n"
            "| sort cve dest"
        ),
        "note": "Requires scanner data (Tenable, Qualys, Rapid7) mapped to CIM Vulnerabilities.",
    }, {
        "title": "Threat signatures for these CVEs (CIM Intrusion_Detection, accelerated)",
        "spl": (
            f"| tstats summariesonly=false count min(_time) AS first_seen max(_time) AS last_seen "
            f"from datamodel=Intrusion_Detection where earliest={earliest} "
            f"IDS_Attacks.signature IN {_in(['*' + v + '*' for v in vals])} "
            "by IDS_Attacks.signature IDS_Attacks.src IDS_Attacks.dest IDS_Attacks.action\n"
            "| rename IDS_Attacks.* AS *\n"
            "| convert ctime(first_seen) ctime(last_seen)\n"
            "| sort - count"
        ),
        "note": "Exploit attempts against your perimeter. Check whether action=allowed.",
    }]
    if sts:
        out.append({
            "title": "Do we even log the affected products? (log source inventory)",
            "spl": (
                "| tstats count latest(_time) AS last_event where index=* ("
                + " OR ".join(f"sourcetype={s}" for s in sts)
                + ") by index sourcetype\n| convert ctime(last_event)"
            ),
            "note": "Lists log sources for the affected products (SonicWall, Cisco ASA, Fortinet, Veeam...) so you know where to hunt for exploitation.",
        })
    return out


def _q_registry(items, scope, earliest):
    vals = [i["value"] for i in items]
    return [{"title": "Broad sweep: registry keys", "spl": _broad(vals, scope, earliest), "note": "Sysmon 12/13/14 or EDR registry telemetry."}]


def _q_generic(items, scope, earliest):
    vals = [i["value"] for i in items]
    return [{"title": "Broad sweep", "spl": _broad(vals, scope, earliest), "note": ""}]


def _technique_queries(items, scope, earliest):
    for i in items:
        tid = i["value"]
        qs = lib.technique_queries(tid) or lib.technique_queries(tid.split(".")[0])
        if qs:
            i["extra"]["hunts"] = [
                {"title": q["title"], "note": q["note"],
                 "spl": q["spl"].replace("{scope}", scope).replace("{earliest}", earliest)}
                for q in qs
            ]
        else:
            ptr = lib.TECHNIQUE_POINTERS.get(tid) or lib.TECHNIQUE_POINTERS.get(tid.split(".")[0])
            i["extra"]["pointer"] = ptr or "No canned hunt. Use the ATT&CK page for detection ideas."
    return []


def _master(cats, scope, earliest):
    vals = []
    for k in ("ipv4", "domain", "sha256", "sha1", "md5", "email"):
        vals += [i["value"] for i in cats.get(k, [])]
    if not vals:
        return None
    return {
        "title": "Master sweep: every atomic IOC (IPs, domains, hashes, emails) in one search",
        "spl": _broad(vals, scope, earliest),
        "note": "Quick first pass. Use the per-category searches below to triage hits." + _size_note(len(vals)),
    }


def build(result: dict, scope: str = "index=*", earliest: str = "-90d"):
    """Attach SPL to the extraction result; returns list of category dicts for the UI."""
    scope = (scope or "index=*").strip()
    earliest = re.sub(r"[^\w@+\-:/]", "", earliest or "-90d") or "-90d"
    iocs = result["iocs"]
    out = []
    builders = {
        "ipv4": _q_ips, "ipv6": _q_ips, "domain": _q_domains, "url": _q_urls, "email": _q_emails,
        "filename": _q_filenames, "tool": _q_tools, "cve": _q_cves, "registry": _q_registry,
        "technique": _technique_queries,
    }
    for key, (label, group) in CATEGORIES.items():
        items = iocs.get(key) or []
        if not items:
            continue
        if key in ("sha256", "sha1", "md5", "sha512"):
            queries = _q_hashes(items, scope, earliest, label)
        elif key == "ssdeep":
            queries = []
        elif key == "malware":
            queries = _q_names(items, scope, earliest, "malware families")
        elif key == "actor":
            queries = _q_names(items, scope, earliest, "threat actors")
        elif key == "other":
            queries = []
        else:
            queries = builders.get(key, _q_generic)(items, scope, earliest)
        note = None
        if key == "ssdeep":
            note = "SSDEEP fuzzy hashes can't be searched directly in Splunk. Use them in VirusTotal, your EDR or a malware sandbox."
        out.append({"key": key, "label": label, "group": group, "items": items, "splunk": queries, "note": note})
    master = [q for q in (_master(iocs, scope, earliest), _q_all_hashes(iocs, scope, earliest)) if q]
    return out, master
