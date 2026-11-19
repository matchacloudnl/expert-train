#!/usr/bin/env python3
"""Fetch impactful CVEs and write data/cves.json. Runs hourly via GitHub Actions.

Sources (no API key needed):
  * CISA Known Exploited Vulnerabilities (KEV): every CVE that is exploited in the wild.
  * NVD API 2.0: CRITICAL CVEs for Windows, macOS and Linux.
  * Security.nl headlines: the software that is in the news is detected automatically
    (product names and CVE numbers in the headlines) and looked up in the NVD.
    Nobody has to maintain a list of software.

Existing entries are kept for KEEP_DAYS days so the page builds up a history.
"""
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "cves.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEEP_DAYS = 90
NVD_WINDOW_DAYS = 30

# platform -> (CPE prefixes, CVSS v3 severities to include)
# To watch more software, add an entry here and a matching tab in cve/index.html.
NVD_PLATFORMS = {
    "windows": (["cpe:2.3:o:microsoft:windows"], ["CRITICAL"]),
    "macos": (["cpe:2.3:o:apple:macos"], ["CRITICAL"]),
    "linux": (["cpe:2.3:o:linux:linux_kernel"], ["CRITICAL"]),
}


# Fresh CVEs have no CPE data in the NVD until they are analysed, so the CPE search above misses
# the newest ones. This keyword search covers the last KEYWORD_DAYS days instead.
# platform -> (search keywords, regex the description must match, minimum CVSS score)
KEYWORD_DAYS = 14
NEWS_URL = "https://www.security.nl/rss/headlines.xml"
NEWS_MIN_SCORE = 7.0   # CVSS needed for a CVE found via the news
NEWS_MAX_TERMS = 20    # product names looked up per run (NVD rate limit)
NEWS_MAX_PER_TERM = 5  # newest CVEs kept per product name
KEYWORDS = {
    "windows": (["windows"], r"microsoft windows|windows (server|\d+|kernel)", 9.0),
    "macos": (["macos"], r"\bmac ?os\b", 9.0),
    "linux": (["linux kernel"], r"linux kernel", 9.0),
}


def best_score(cve):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in cve.get("metrics", {}).get(key, []):
            if "cvssData" in m:
                return m["cvssData"]["baseScore"]
    return None


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
    return "software"  # every other exploited product is shown under the Software tab


STOP = set("""
het een van voor met die dat wordt zijn niet door ook meer naar over bij kan nog als aan maar uit dan tot
nederland nederlandse nederlandstalige europese europa duitse franse britse amerikaanse russische chinese
ncsc security hackers hacker onderzoekers onderzoeker aanvallers criminelen bedrijven bedrijf gebruikers
kwetsbaarheid kwetsbaarheden beveiligingsupdate beveiligingsupdates updates update lek lekt misbruik
cyberaanval ransomware malware phishing maandag dinsdag woensdag donderdag vrijdag zaterdag zondag
januari februari maart april mei juni juli augustus september oktober november december
the and for with this that from have new fbi cisa ddos origin scattered spider
""".split())
TECH_WORDS = re.compile(r"kwetsbaar|lek\|lekt|beveiligingsupdate|zero.?day|misbruik|patch|update|exploit|aanval|bug|cve-", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def news_items():
    req = urllib.request.Request(NEWS_URL, headers={"User-Agent": "Mozilla/5.0 cve-feed-script"})
    with urllib.request.urlopen(req, timeout=60) as r:
        root = ET.fromstring(r.read())
    return [((i.findtext("title") or ""), (i.findtext("description") or "")) for i in root.iter("item")]


def news_terms(items):
    """Product names (and CVE ids) that the security headlines are talking about."""
    counts, cves = Counter(), set()
    for title, desc in items:
        text = f"{title} {desc}"
        cves.update(c.upper() for c in CVE_RE.findall(text))
        if not TECH_WORDS.search(text):
            continue
        for n, tok in enumerate(re.findall(r"[A-Za-z][A-Za-z0-9.+#]*", title)):
            tok = tok.strip(".-")
            low = tok.lower()
            if len(tok) < 3 or low in STOP:
                continue
            shouty = tok.isupper() or bool(re.search(r"\d", tok)) or bool(re.search(r"[a-z][A-Z]", tok))
            if shouty or (tok[0].isupper() and n > 0):
                counts[low] += 1
    return [w for w, _ in counts.most_common(NEWS_MAX_TERMS)], sorted(cves)


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
            software=v.get("product") if plat == "software" else None,
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
    for plat, (cpes, severities) in NVD_PLATFORMS.items():
        for cpe in cpes:
            for severity in severities:
                print("Fetching NVD for", plat, cpe, severity)
                index = 0
                while True:
                    q = urllib.parse.urlencode({
                        "virtualMatchString": cpe,
                        "cvssV3Severity": severity,
                        "pubStartDate": start,
                        "pubEndDate": end,
                        "resultsPerPage": 200,
                        "startIndex": index,
                    })
                    data = get_json(f"{NVD_URL}?{q}")
                    for item in data.get("vulnerabilities", []):
                        c = item["cve"]
                        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
                        score = best_score(c)
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

    # --- NVD keyword search for the newest CVEs ---
    kstart = (now - timedelta(days=KEYWORD_DAYS)).strftime("%Y-%m-%dT00:00:00.000")
    for plat, (words, pattern, min_score) in KEYWORDS.items():
        for word in words:
            print("Keyword search for", word)
            index = 0
            while True:
                q = urllib.parse.urlencode({
                    "keywordSearch": word,
                    "pubStartDate": kstart,
                    "pubEndDate": end,
                    "resultsPerPage": 200,
                    "startIndex": index,
                })
                data = get_json(f"{NVD_URL}?{q}")
                for item in data.get("vulnerabilities", []):
                    c = item["cve"]
                    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
                    score = best_score(c)
                    if score is None or score < min_score or not re.search(pattern, desc, re.I):
                        continue
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
            time.sleep(7)

    # --- software in the news (Security.nl): detected automatically ---
    try:
        terms, news_cves = news_terms(news_items())
    except Exception as e:  # noqa: BLE001
        print("Security.nl unavailable:", e, file=sys.stderr)
        terms, news_cves = [], []
    print("News terms:", terms, "CVEs:", news_cves)
    for cid in news_cves:
        data = get_json(f"{NVD_URL}?" + urllib.parse.urlencode({"cveId": cid}))
        time.sleep(7)
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            merge(entries, c["id"], platforms=["software"], sources=["NVD", "Security.nl"],
                  description=desc, score=best_score(c), published=c.get("published", "")[:10])
    for term in terms:
        print("News search for", term)
        data = get_json(f"{NVD_URL}?" + urllib.parse.urlencode({
            "keywordSearch": term, "pubStartDate": kstart, "pubEndDate": end, "resultsPerPage": 200}))
        time.sleep(7)
        found = []
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            score = best_score(c)
            if score is None or score < NEWS_MIN_SCORE or not re.search(r"\b" + re.escape(term) + r"\b", desc, re.I):
                continue
            found.append((c.get("published", ""), c["id"], desc, score))
        for published, cid, desc, score in sorted(found, reverse=True)[:NEWS_MAX_PER_TERM]:
            merge(entries, cid, platforms=["software"], sources=["NVD", "Security.nl"],
                  software=term.upper() if len(term) <= 4 else term.capitalize(),
                  description=desc, score=score, published=published[:10])

    # --- prune, sort, write ---
    keep_from = (now - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
    cves = []
    for e in entries.values():
        date = e.get("added") or e.get("published") or ""
        e["date"] = date
        if date >= keep_from:
            cves.append(e)
    cves.sort(key=lambda e: (e["date"], e.get("score") or 0), reverse=True)

    if OUT.exists():
        try:
            if json.loads(OUT.read_text(encoding="utf-8")).get("cves") == cves:
                print("No changes")
                return
        except ValueError:
            pass
    out = {"updated": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "cves": cves}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(cves)} CVEs")


if __name__ == "__main__":
    main()
