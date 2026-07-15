#!/usr/bin/env python3
"""
Resolves every task.url-vs-page.apexDomain mismatch found by
13_redirect_attribution_check.py (70 distinct apex domains, 99 scan records)
by fetching each scan's full result JSON and finding the actual `documentURL`
of the eth_call request to bsc-testnet-rpc.publicnode.com - i.e. which page
in the redirect chain actually executed the injected script that made the
call. This is definitive: it doesn't matter what page the browser eventually
landed on, only which document actually ran the malicious JS.

Confirmed manually for the amazon.com case: documentURL was
https://hajighani-sons.com/ - meaning hajighani-sons.com is the truly
compromised site and amazon.com is an unrelated affiliate-redirect artifact
that has nothing to do with this campaign.
"""
import json
import time
from urllib.parse import urlparse

import requests

KEY_PATH = r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key"
with open(KEY_PATH, encoding="utf-8") as f:
    API_KEY = f.read().strip()

HEADERS = {"API-Key": API_KEY, "User-Agent": "blueteam.cool-revalidation/1.0"}

with open("13_redirect_attribution_mismatches.json", encoding="utf-8") as f:
    mismatches = json.load(f)

session = requests.Session()
session.headers.update(HEADERS)

results = {}
for page_apex, records in mismatches.items():
    # only need to resolve once per distinct scan uuid within this apex group
    seen_uuids = set()
    resolutions = []
    for rec in records:
        uuid = rec["uuid"]
        if uuid in seen_uuids:
            continue
        seen_uuids.add(uuid)
        try:
            resp = session.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=20)
        except requests.RequestException as e:
            resolutions.append({"uuid": uuid, "error": str(e)})
            continue
        if resp.status_code != 200:
            resolutions.append({"uuid": uuid, "error": f"HTTP {resp.status_code}"})
            continue
        try:
            data = resp.json()
        except Exception as e:
            resolutions.append({"uuid": uuid, "error": f"json error: {e}"})
            continue

        doc_urls = set()
        for r in data.get("data", {}).get("requests", []):
            url = r.get("request", {}).get("request", {}).get("url", "")
            if "bsc-testnet-rpc.publicnode.com" in url:
                doc = r.get("request", {}).get("documentURL", "")
                if doc and "bsc-testnet" not in doc:
                    doc_urls.add(urlparse(doc).hostname or doc)
        resolutions.append({"uuid": uuid, "eth_call_document_hosts": sorted(doc_urls)})
        time.sleep(0.3)

    results[page_apex] = {
        "task_hosts_seen": sorted(set(r["task_host"] for r in records)),
        "resolutions": resolutions,
    }
    hosts = set()
    for r in resolutions:
        hosts.update(r.get("eth_call_document_hosts", []))
    print(f"{page_apex}  ->  eth_call actually ran on: {sorted(hosts) if hosts else 'UNRESOLVED'}")

with open("14_resolve_redirect_attribution_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print()
print("Full results saved to 14_resolve_redirect_attribution_RESULTS.json")
