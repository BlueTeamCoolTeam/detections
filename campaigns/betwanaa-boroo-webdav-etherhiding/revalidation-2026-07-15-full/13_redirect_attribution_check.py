#!/usr/bin/env python3
"""
Investigates a user-caught accuracy issue: amazon.com appears in the clean
1,739-site confirmed list, which is implausible (Amazon does not run
WordPress and does not match this campaign's victim profile). Root cause,
confirmed by fetching that scan's full result JSON: urlscan's `page.apexDomain`
field records the FINAL landed page after any redirect chain, not the
originally-submitted/scanned URL. For scan 019ef154-48d0-757f-99a5-c950dc466e64,
`task.url` was `https://hajighani-sons.com` (the actual compromised site) but
`page.url`/`page.apexDomain` show an Amazon Associates affiliate redirect
(`amazon.com/?...tag=mntzr-20&linkCode=ur2...`) - the injected script's
monetization behaviour, not evidence Amazon itself is compromised.

The original report.md's enumeration query, and this session's Step 6 fresh
re-enumeration, both grouped by `page.apexDomain` - meaning this
misattribution risk was present in BOTH the original 1,815 figure and this
session's corrected 1,739 figure alike. This script checks the full fresh
dataset (06_urlscan_site_enumeration_fresh_RAW.json) for every record where
`task.url`'s domain differs from `page.apexDomain`, flagging genuine
redirect-attribution cases for removal/correction.
"""
import json
import re
from urllib.parse import urlparse

with open("06_urlscan_site_enumeration_fresh_RAW.json", encoding="utf-8") as f:
    raw = json.load(f)

with open("10_false_positive_sites_ALL.txt", encoding="utf-8") as f:
    already_removed_fp = set(line.strip().lower() for line in f if line.strip())


# Rather than re-implementing public-suffix-list-aware apex extraction (the
# first version of this script naively took the last 2 labels, which breaks
# on multi-part TLDs like .co.uk/.com.au/.com.br/.cn.com and produced ~350
# false mismatches that were just that bug, not real redirects), trust
# urlscan's own page.apexDomain computation and simply check whether that
# exact string appears anywhere in the ORIGINALLY SUBMITTED task.url's
# hostname. If it does, task and page are the same site (or a subdomain) -
# not a mismatch. If page.apexDomain appears nowhere in task_host, the final
# landed page is a genuinely different site from what was scanned - a real
# redirect-attribution case.
mismatches = {}
checked = 0
for r in raw["results"]:
    page_apex = (r.get("page", {}).get("apexDomain") or "").lower()
    task_url = r.get("task", {}).get("url", "")
    if not page_apex or page_apex in already_removed_fp:
        continue
    checked += 1
    task_host = (urlparse(task_url).hostname or "").lower()
    if task_host and page_apex not in task_host:
        mismatches.setdefault(page_apex, []).append({
            "task_url": task_url,
            "task_host": task_host,
            "page_url": r.get("page", {}).get("url"),
            "redirected": r.get("page", {}).get("redirected"),
            "uuid": r.get("task", {}).get("uuid"),
        })

print(f"Checked {checked} clean (non-already-false-positive) records")
print(f"Records where task.url's domain != page.apexDomain: {sum(len(v) for v in mismatches.values())}")
print(f"Distinct page.apexDomain values affected: {len(mismatches)}")
print()

for page_apex, records in sorted(mismatches.items()):
    print(f"page.apexDomain = {page_apex}")
    for rec in records[:3]:
        print(f"  task.url={rec['task_url']}  task_host={rec['task_host']}  redirected={rec['redirected']}")
    print()

with open("13_redirect_attribution_mismatches.json", "w", encoding="utf-8") as f:
    json.dump(mismatches, f, indent=2)

print("Full results saved to 13_redirect_attribution_mismatches.json")
