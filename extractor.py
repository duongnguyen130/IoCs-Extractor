"""
Parse CISA STIX 2.x bundles (and plain-text IOC lists as a fallback) into
de-duplicated, categorized IOC lists.
"""

import ipaddress
import json
import re
from collections import OrderedDict

from . import hunt_library as lib

# Category registry: key -> (label, group). Order here is display order.
CATEGORIES = OrderedDict([
    ("ipv4",        ("IPv4 Addresses", "Network")),
    ("ipv6",        ("IPv6 Addresses", "Network")),
    ("domain",      ("Domains", "Network")),
    ("url",         ("URLs", "Network")),
    ("email",       ("Email Addresses", "Network")),
    ("sha256",      ("SHA-256 Hashes", "Hashes")),
    ("sha1",        ("SHA-1 Hashes", "Hashes")),
    ("md5",         ("MD5 Hashes", "Hashes")),
    ("sha512",      ("SHA-512 Hashes", "Hashes")),
    ("ssdeep",      ("SSDEEP (fuzzy) Hashes", "Hashes")),
    ("filename",    ("File Names", "Host Artifacts")),
    ("commandline", ("Command Lines", "Host Artifacts")),
    ("registry",    ("Registry Keys", "Host Artifacts")),
    ("mutex",       ("Mutexes", "Host Artifacts")),
    ("tool",        ("Tools & Software", "Tools & Malware")),
    ("malware",     ("Malware / Ransomware Families", "Tools & Malware")),
    ("actor",       ("Threat Actors", "Tools & Malware")),
    ("cve",         ("CVEs", "Vulnerabilities")),
    ("technique",   ("MITRE ATT&CK Techniques", "Behaviors (TTPs)")),
    ("other",       ("Other Observables", "Other")),
])

HASH_TYPES = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha512": "sha512", "ssdeep": "ssdeep"}

# STIX pattern comparison:  object-type:path  OP  'value'
PATTERN_RE = re.compile(
    r"([a-z0-9][a-z0-9-]*):([A-Za-z0-9_.'\-\[\]\*]+?)\s*(?:=|LIKE|MATCHES)\s*'((?:[^'\\]|\\.)*)'",
    re.IGNORECASE,
)
TECH_NAME_RE = re.compile(r"^(?P<tactic>.+?)\s*/\s*(?P<name>.+?)\s*\[(?P<id>T\d{4}(?:\.\d{3})?)\]")
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
AA_RE = re.compile(r"\bAA\d{2}-\d{3}[A-Z]?\b", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>\]\[)]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b", re.IGNORECASE)
FILENAME_RE = re.compile(
    r"(?<![\w.-])[\w\-]{1,80}\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|msi|scr|lnk|jar|sys|py|sh|elf|iso|img|zip|rar|7z)\b",
    re.IGNORECASE,
)
# Extensions that make a "domain" match actually a file name
FILE_EXTS = {"exe", "dll", "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "msi", "scr", "lnk", "jar",
             "sys", "py", "sh", "elf", "iso", "img", "zip", "rar", "7z", "txt", "log", "json", "xml", "csv", "pdf",
             "doc", "docx", "xls", "xlsx", "ppt", "pptx", "dat", "tmp", "ini", "cfg", "conf", "html", "htm", "php",
             "aspx", "asp", "png", "jpg", "gif", "bin", "db", "md"}

SKIP_NAMES = {"unknown", "", "n/a", "none"}


def refang(text: str) -> str:
    return (text.replace("hxxps", "https").replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
            .replace("[dot]", ".").replace("[:]", ":").replace("[@]", "@").replace("[at]", "@"))


def _ip_note(ip_str: str):
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
    except ValueError:
        return None
    if net.is_private or net.is_loopback or net.is_reserved or net.is_link_local:
        return "Private/reserved address, likely victim-internal"
    for cidr, owner in lib.SHARED_INFRA:
        try:
            if net.version == 4 and net.subnet_of(ipaddress.ip_network(cidr)):
                return f"Shared infrastructure ({owner}), expect benign hits"
        except (TypeError, ValueError):
            continue
    return None


class IOCStore:
    def __init__(self):
        self.data = OrderedDict((k, OrderedDict()) for k in CATEGORIES)

    def add(self, cat, value, source, context=None, related=None, extra=None):
        if value is None:
            return
        value = str(value).strip()
        if not value or len(value) > 4096:
            return
        if cat in HASH_TYPES or cat in ("domain", "email"):
            value = value.lower()
        key = value.lower()
        bucket = self.data[cat]
        item = bucket.get(key)
        if item is None:
            item = {"value": value, "context": [], "related": [], "sources": [], "extra": {}}
            bucket[key] = item
        if source and source not in item["sources"]:
            item["sources"].append(source)
        if context and context not in item["context"]:
            item["context"].append(context)
        for r in related or []:
            if r and r != value and r not in item["related"]:
                item["related"].append(r)
        if extra:
            item["extra"].update(extra)

    def has(self, cat, value):
        return str(value).strip().lower() in self.data[cat]

    def as_dict(self):
        return {k: list(v.values()) for k, v in self.data.items()}


# --------------------------------------------------------------------------- #
# STIX handling
# --------------------------------------------------------------------------- #
def _hash_cat(path: str):
    # path like: hashes.'SHA-256' / hashes.MD5 / hashes.SSDEEP
    m = re.search(r"hashes\.'?([A-Za-z0-9-]+)'?", path)
    if not m:
        return None
    return HASH_TYPES.get(m.group(1).lower().replace("-", ""))


def _classify_comparison(obj_type: str, path: str):
    obj_type = obj_type.lower()
    path_l = path.lower()
    if obj_type == "ipv4-addr":
        return "ipv4"
    if obj_type == "ipv6-addr":
        return "ipv6"
    if obj_type == "domain-name":
        return "domain"
    if obj_type == "url":
        return "url"
    if obj_type == "email-addr" or (obj_type == "email-message" and "value" in path_l):
        return "email"
    if obj_type in ("file", "artifact"):
        if path_l.startswith("hashes"):
            return _hash_cat(path) or "other"
        if path_l in ("name", "parent_directory_ref.path"):
            return "filename" if path_l == "name" else "other"
    if obj_type == "process":
        if path_l in ("name", "image_ref.name", "binary_ref.name"):
            return "filename"
        if "command_line" in path_l:
            return "commandline"
    if obj_type == "windows-registry-key":
        return "registry"
    if obj_type == "mutex":
        return "mutex"
    return "other"


def _parse_pattern(pattern: str):
    """Yield (category, value, obj_type, path) for each comparison in a STIX pattern."""
    for m in PATTERN_RE.finditer(pattern or ""):
        obj_type, path, raw = m.group(1), m.group(2), m.group(3)
        value = raw.replace("\\'", "'").replace("\\\\", "\\").strip()
        yield _classify_comparison(obj_type, path), value, obj_type, path


def _add_ip(store, value, source, context=None):
    note = _ip_note(value)
    try:
        ver = ipaddress.ip_network(value, strict=False).version
    except ValueError:
        store.add("other", value, source, "Unparseable IP")
        return
    store.add("ipv4" if ver == 4 else "ipv6", value, source, context=note or context)


def _add_domain(store, value, source, context=None):
    v = value.lower().rstrip(".")
    ctx = "Tor hidden service, only visible in proxy/DNS logs" if v.endswith(".onion") else context
    store.add("domain", v, source, ctx)


def _add_cve(store, cve, source):
    cve = cve.upper()
    info = lib.CVES.get(cve)
    ctx = f"{info['product']}: {info['issue']}" if info else "See NVD for affected product"
    store.add("cve", cve, source, ctx, extra={
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "kev": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
    })


def _add_software(store, name, source, stix_type, malware_types=None, aliases=None):
    if not name or name.strip().lower() in SKIP_NAMES:
        return
    name = name.strip()
    malware_types = [t.lower() for t in (malware_types or [])]
    tool = lib.lookup_tool(name)
    if tool and "ransomware" not in malware_types:
        procs = ", ".join(tool["processes"]) if tool["processes"] else "keyword hunt"
        store.add("tool", name, source, f"{tool['kind']} ({procs})",
                  extra={"noisy": bool(tool.get("noisy")), "label": tool["label"]})
    elif stix_type == "tool":
        store.add("tool", name, source, "Tool named in advisory (process name unverified)",
                  extra={"noisy": False, "guess": True})
    else:
        ctx = ", ".join(malware_types) if malware_types else "Malware family named in advisory"
        store.add("malware", name, source, ctx, related=aliases)


def _text_sweep(store, text, source, deep=False):
    """Regex extraction from free text. `deep` also pulls domains/URLs/file names."""
    if not text:
        return
    text = refang(text)
    for ip in IPV4_RE.findall(text):
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            continue
        if not store.has("ipv4", ip) and not store.has("ipv6", ip):
            _add_ip(store, ip, source, "From description text" if not deep else None)
    for h in HEX_RE.findall(text):
        cat = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}[len(h)]
        store.add(cat, h, source, None if (deep or store.has(cat, h)) else "From description text")
    for c in CVE_RE.findall(text):
        _add_cve(store, c, source)
    for e in EMAIL_RE.findall(text):
        store.add("email", e, source)
    if deep:
        for t in TECH_ID_RE.findall(text):
            store.add("technique", t.upper(), source, extra={"url": _mitre_url(t)})
        urls = URL_RE.findall(text)
        for u in urls:
            store.add("url", u.rstrip(".,;"), source)
        emails = {e.lower() for e in EMAIL_RE.findall(text)}
        for d in DOMAIN_RE.findall(text):
            dl = d.lower()
            tld = dl.rsplit(".", 1)[-1]
            if tld in FILE_EXTS or IPV4_RE.fullmatch(dl) or any(dl in e for e in emails):
                continue
            if re.fullmatch(r"[\d.]+", dl):
                continue
            _add_domain(store, dl, source)
        for f in FILENAME_RE.findall(text):
            store.add("filename", f.strip(), source)


def _mitre_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.upper().replace(".", "/") + "/"


def _report_label(bundle_objs, filename):
    aa = None
    m = AA_RE.search(filename or "")
    if m:
        aa = m.group(0).upper()
    reports = [o for o in bundle_objs if o.get("type") == "report"]
    title = reports[0].get("name") if reports else None
    if not aa and title:
        m = AA_RE.search(title)
        aa = m.group(0).upper() if m else None
    short = aa or (filename or "upload").rsplit(".", 1)[0][:40]
    full = title or filename
    if aa and full and aa not in full.upper():
        full = f"{aa} {full}"
    published = reports[0].get("published", "")[:10] if reports else ""
    return short, full, published


def parse_stix(bundle: dict, filename: str, store: IOCStore):
    objs = bundle.get("objects") or []
    if bundle.get("type") != "bundle" and not objs:
        objs = [bundle]
    source, title, published = _report_label(objs, filename)
    counts = {"indicators": 0, "objects": len(objs)}

    for o in objs:
        t = (o.get("type") or "").lower()
        desc = o.get("description") or ""

        if t == "indicator":
            counts["indicators"] += 1
            comps = list(_parse_pattern(o.get("pattern", "")))
            names = [v for c, v, *_ in comps if c == "filename"]
            hashes = [v.lower() for c, v, *_ in comps if c in HASH_TYPES]
            ind_ctx = desc.strip() if desc and not IPV4_RE.fullmatch(desc.strip()) and len(desc) < 200 else None
            if o.get("name") and len(o["name"]) < 200:
                ind_ctx = ind_ctx or o["name"]
            for cat, val, obj_type, path in comps:
                if cat in ("ipv4", "ipv6"):
                    _add_ip(store, val, source, ind_ctx)
                elif cat == "domain":
                    _add_domain(store, val, source, ind_ctx)
                elif cat in HASH_TYPES:
                    ctx = ind_ctx
                    if names:
                        ctx = "File: " + ", ".join(names) + (f" ({ind_ctx})" if ind_ctx else "")
                    store.add(cat, val, source, ctx, related=[h for h in hashes if h != val.lower()] + names)
                elif cat == "filename":
                    store.add(cat, val, source, ind_ctx or ("Has hash IOC" if hashes else None), related=hashes)
                elif cat == "other":
                    store.add(cat, f"{obj_type}:{path} = {val}", source, ind_ctx)
                else:
                    store.add(cat, val, source, ind_ctx)
            if not comps and o.get("pattern"):
                _text_sweep(store, o["pattern"], source, deep=True)
            # descriptions sometimes hold extra IOCs (e.g. "SHA256 of <sha1>")
            _text_sweep(store, desc, source)

        elif t == "vulnerability":
            name = o.get("name") or ""
            for c in CVE_RE.findall(name):
                _add_cve(store, c, source)
            for ref in o.get("external_references") or []:
                if (ref.get("source_name") or "").lower() == "cve" and ref.get("external_id"):
                    _add_cve(store, ref["external_id"], source)

        elif t in ("malware", "tool"):
            _add_software(store, o.get("name"), source, t, o.get("malware_types") or o.get("tool_types"), o.get("aliases"))

        elif t in ("threat-actor", "intrusion-set", "campaign"):
            name = o.get("name")
            if name and name.lower() not in SKIP_NAMES:
                store.add("actor", name, source, t.replace("-", " ").title(), related=o.get("aliases"))

        elif t == "attack-pattern":
            name = o.get("name") or ""
            m = TECH_NAME_RE.match(name)
            tid = None
            ctx = name
            if m:
                tid = m.group("id")
                ctx = f"{m.group('tactic').strip()}: {m.group('name').strip()}"
            else:
                for ref in o.get("external_references") or []:
                    if (ref.get("source_name") or "").startswith("mitre") and ref.get("external_id"):
                        tid = ref["external_id"]
                if not tid:
                    mm = TECH_ID_RE.search(name)
                    tid = mm.group(0) if mm else None
            if tid:
                store.add("technique", tid.upper(), source, ctx, extra={"url": _mitre_url(tid)})

        # STIX Cyber Observables embedded directly in the bundle
        elif t in ("ipv4-addr", "ipv6-addr"):
            _add_ip(store, o.get("value"), source)
        elif t == "domain-name":
            _add_domain(store, o.get("value", ""), source)
        elif t == "url":
            store.add("url", o.get("value"), source)
        elif t == "email-addr":
            store.add("email", o.get("value"), source)
        elif t == "file":
            hashes = {k: v for k, v in (o.get("hashes") or {}).items()}
            fname = o.get("name")
            for k, v in hashes.items():
                cat = HASH_TYPES.get(k.lower().replace("-", ""))
                if cat:
                    store.add(cat, v, source, f"File: {fname}" if fname else None, related=[fname] if fname else None)
            if fname:
                store.add("filename", fname, source, related=[v.lower() for v in hashes.values()])
        elif t == "windows-registry-key":
            store.add("registry", o.get("key"), source)
        elif t == "mutex":
            store.add("mutex", o.get("name"), source)
        elif t in ("report", "note", "observed-data", "opinion"):
            _text_sweep(store, desc or o.get("content", ""), source)

    return {"source": source, "title": title, "published": published, "file": filename, **counts}


def extract_from_files(files):
    """files: list of {"name": str, "content": str}. Returns dict."""
    store = IOCStore()
    reports, errors = [], []
    for f in files:
        name = str(f.get("name") or "upload")[:200]
        content = f.get("content") or ""
        if not isinstance(content, str):
            errors.append(f"{name}: unsupported content")
            continue
        try:
            data = json.loads(content)
        except ValueError:
            data = None
        try:
            if isinstance(data, dict) and (data.get("type") == "bundle" or "objects" in data or "pattern" in data):
                reports.append(parse_stix(data, name, store))
            else:
                source = (AA_RE.search(name).group(0).upper() if AA_RE.search(name) else name.rsplit(".", 1)[0][:40])
                _text_sweep(store, content, source, deep=True)
                reports.append({"source": source, "title": name, "published": "", "file": name,
                                "indicators": 0, "objects": 0, "note": "Parsed as plain text (regex)"})
        except Exception as exc:  # keep going on a bad file
            errors.append(f"{name}: {exc}")
    return {"reports": reports, "errors": errors, "iocs": store.as_dict()}
