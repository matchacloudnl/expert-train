#!/usr/bin/env python3
"""Fetch impactful CVEs for Windows, macOS and Linux and write data/cves.json.

Sources (no API key needed):
  * CISA Known Exploited Vulnerabilities (KEV): CVEs that are exploited in the wild.
  * NVD API 2.0: newly published CVEs with a CRITICAL CVSS v3 rating.

Existing entries are kept for KEEP_DAYS days so the page builds up a history.
"""
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "cves.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEEP_DAYS = 90
NVD_WINDOW_DAYS = 30

NVD_PLATFORMS = {
    "windows": "cpe:2.3:o:microsoft:windows",
    "macos": "cpe:2.3:o:apple:macos",
    "linux": "cpe:2.3:o:linux:linux_kernel",
}


def get_json(url, tries=4):
    req = urllib.request.Request(url, headers={"User-Agent": "cve-feed-script"})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            print(f"  retry {i + 1} for {url[:80]}: {e}", file=sys.stderr)
            time.sleep(10 * (i + 1))
    raise RuntimeError("giving up on " + url)


def kev_platform(vendor, product):
    v, p = vendor.lower(), product.lower()
    if "microsoft" in v and "windows" in p:
        return "windows"
    if "apple" in v and re.search(r"mac ?os", p):
        return "macos"
    if "linux" in p or "linux" in v:
        return "linux"
    return None


def merge(entries, cve_id, **fields):
    e = entries.setdefault(cve_id, {"id": cve_id, "platforms": [], "sources": []})
    for key in ("platforms", "sources"):
        for v in fields.pop(key, []):
            if v not in e[key]:
                e[key].append(v)
    for k, v in fields.items():
        if v not in (None, ""):
            e[k] = v
    return e


def main():
    now = datetime.now(timezone.utc)
    entries = {}

    # keep previous entries
    if OUT.exists():
        for e in json.loads(OUT.read_text(encoding="utf-8")).get("cves", []):
            entries[e["id"]] = e

    # --- CISA KEV ---
    print("Fetching CISA KEV")
    kev = get_json(KEV_URL)
    cutoff = (now - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
    for v in kev.get("vulnerabilities", []):
        plat = kev_platform(v.get("vendorProject", ""), v.get("product", ""))
        if not plat or v.get("dateAdded", "") < cutoff:
            continue
        merge(
            entries, v["cveID"],
            platforms=[plat], sources=["CISA KEV"],
            title=v.get("vulnerabilityName"),
            description=v.get("shortDescription"),
            product=f'{v.get("vendorProject")} {v.get("product")}',
            kev=True,
            ransomware=v.get("knownRansomwareCampaignUse") == "Known",
            added=v.get("dateAdded"),
            due=v.get("dueDate"),
        )

    # --- NVD critical ---
    start = (now - timedelta(days=NVD_WINDOW_DAYS)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    for plat, cpe in NVD_PLATFORMS.items():
        print("Fetching NVD for", plat)
        index = 0
        while True:
            q = urllib.parse.urlencode({
                "virtualMatchString": cpe,
                "cvssV3Severity": "CRITICAL",
                "pubStartDate": start,
                "pubEndDate": end,
                "resultsPerPage": 200,
                "startIndex": index,
            })
            data = get_json(f"{NVD_URL}?{q}")
            for item in data.get("vulnerabilities", []):
                c = item["cve"]
                desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
                score = None
                for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                    if c.get("metrics", {}).get(key):
                        score = c["metrics"][key][0]["cvssData"]["baseScore"]
                        break
                merge(
                    entries, c["id"],
                    platforms=[plat], sources=["NVD"],
                    description=desc, score=score,
                    published=c.get("published", "")[:10],
                )
            index += data.get("resultsPerPage", 0)
            if index >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
                break
            time.sleep(7)
        time.sleep(7)  # NVD rate limit without API key: 5 requests / 30 s

    # --- prune, sort, write ---
    keep_from = (now - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
    cves = []
    for e in entries.values():
        date = e.get("added") or e.get("published") or ""
        e["date"] = date
        if date >= keep_from:
            cves.append(e)
    cves.sort(key=lambda e: (e["date"], e.get("score") or 0), reverse=True)

    out = {"updated": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "cves": cves}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(cves)} CVEs")


if __name__ == "__main__":
    main()
