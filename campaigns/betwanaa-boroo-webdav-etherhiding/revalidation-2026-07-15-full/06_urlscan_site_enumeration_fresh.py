#!/usr/bin/env python3
"""
Phase 2: independently re-derive the total compromised-site count from
scratch via urlscan.io, using the exact query from report.md section 9.4:

    domain:bsc-testnet-rpc.publicnode.com AND NOT page.apexDomain:publicnode.com

Uses corrected pagination (search_after cursor, iterating until an empty
page is returned) rather than trusting the API's `has_more` flag - the same
lesson learned and documented in the prior EtherHiding investigation
(etherhiding-ecosystem-mapped/revalidation-2026-07-11-full).

API key read from a local scratchpad file path (never embedded in this
script or committed to any repo).
"""
import json
import time
import urllib.request
import urllib.error
import urllib.parse

KEY_PATH = r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key"
with open(KEY_PATH, encoding="utf-8") as f:
    API_KEY = f.read().strip()

QUERY = "domain:bsc-testnet-rpc.publicnode.com AND NOT page.apexDomain:publicnode.com"
BASE = "https://urlscan.io/api/v1/search/"
HEADERS = {"API-Key": API_KEY, "User-Agent": "blueteam.cool-revalidation/1.0"}


def fetch_page(search_after=None):
    params = {"q": QUERY, "size": "100"}
    if search_after:
        params["search_after"] = search_after
    url = BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=HEADERS)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"  rate limited, sleeping 5s (attempt {attempt+1})")
                time.sleep(5)
                continue
            raise
    raise RuntimeError("exhausted retries")


all_results = []
apex_domains = set()
search_after = None
page_num = 0

while True:
    page_num += 1
    data = fetch_page(search_after)
    results = data.get("results", [])
    print(f"page {page_num}: {len(results)} results, total so far: {len(all_results) + len(results)}")
    if not results:
        break
    all_results.extend(results)
    for r in results:
        apex = r.get("page", {}).get("apexDomain") or r.get("page", {}).get("domain")
        if apex:
            apex_domains.add(apex.lower())
    last = results[-1]
    sort_vals = last.get("sort")
    if not sort_vals:
        print("  no sort field on last result - cannot paginate further, stopping")
        break
    search_after = ",".join(str(v) for v in sort_vals)
    time.sleep(0.5)

print()
print(f"Total scan events: {len(all_results)}")
print(f"Total unique apex domains: {len(apex_domains)}")

with open("06_urlscan_site_enumeration_fresh_apex_domains.txt", "w", encoding="utf-8") as f:
    for d in sorted(apex_domains):
        f.write(d + "\n")

with open("06_urlscan_site_enumeration_fresh_RAW.json", "w", encoding="utf-8") as f:
    json.dump({"total_scan_events": len(all_results), "total_unique_apex_domains": len(apex_domains),
               "results": all_results}, f)

print()
print("Apex domain list saved to 06_urlscan_site_enumeration_fresh_apex_domains.txt")
print("Raw results saved to 06_urlscan_site_enumeration_fresh_RAW.json")
