"""
Generate one broad Splunk search per IOC category:

    index=* ("ioc1" OR "ioc2" OR ...)

No time modifiers or pipes. Set the time range in the Splunk time picker.
"""

import re

from . import hunt_library as lib
from .extractor import CATEGORIES

# Categories with no searchable value (fuzzy hashes, ATT&CK IDs) get no search
NO_SEARCH = {"ssdeep", "technique", "other"}


def _q(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _dedupe(values):
    seen, out = set(), []
    for v in values:
        v = (v or "").strip()
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    return out


def _search_terms(key, items):
    """Values to search for a category."""
    if key == "tool":
        # search the executable names, not the product names
        # (noisy built-ins like powershell.exe / 7z.exe are left out: they'd match everything)
        terms = []
        for i in items:
            t = lib.lookup_tool(i["value"])
            if t and t.get("noisy"):
                continue
            terms.extend(t["processes"] + t.get("keywords", []) if t else [i["value"]])
        return _dedupe(terms)
    if key == "malware":
        return _dedupe(re.sub(r"(?i)\s+ransomware$", "", i["value"]) for i in items)
    return _dedupe(i["value"] for i in items)


def search(scope, values):
    return f"{scope} (" + " OR ".join(_q(v) for v in values) + ")"


def build(result: dict, scope: str = "index=*"):
    """Return the category list for the UI, each with at most one search."""
    scope = (scope or "index=*").strip()
    out = []
    for key, (label, group) in CATEGORIES.items():
        items = result["iocs"].get(key) or []
        if not items:
            continue
        spl = None
        if key not in NO_SEARCH:
            terms = _search_terms(key, items)
            if terms:
                spl = search(scope, terms)
        note = None
        if key == "ssdeep":
            note = "SSDEEP fuzzy hashes can't be searched in Splunk. Use them in VirusTotal, your EDR or a sandbox."
        if key == "tool":
            noisy = [i["value"] for i in items if (lib.lookup_tool(i["value"]) or {}).get("noisy")]
            if noisy:
                note = ("Left out of the search because they're legitimate and on every host: "
                        + ", ".join(noisy) + ".")
        out.append({"key": key, "label": label, "group": group, "items": items, "spl": spl, "note": note})
    return out
