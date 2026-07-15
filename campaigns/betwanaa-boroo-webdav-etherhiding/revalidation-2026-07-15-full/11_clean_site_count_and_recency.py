#!/usr/bin/env python3
"""
Phase 2/3 final correction: recompute the compromised-site total, recency
segmentation, and TLD spread with the 77 confirmed false-positive sites
(10_false_positive_sites_ALL.txt) removed from the fresh 1,816-site
enumeration (06_urlscan_site_enumeration_fresh_RAW.json).

This is the headline correction of this revalidation: all 77 false-positive
sites were already present in the ORIGINAL report's 1,815-site figure (see
09/10 script output) - the false-positive contamination was not introduced
by this session's wider net, it was always there, uncaught until this
contract-level verification pass.
"""
import json
from collections import Counter
from datetime import datetime, timezone

with open("06_urlscan_site_enumeration_fresh_RAW.json", encoding="utf-8") as f:
    raw = json.load(f)

with open("10_false_positive_sites_ALL.txt", encoding="utf-8") as f:
    false_positive_sites = set(line.strip().lower() for line in f if line.strip())

last_seen = {}
for r in raw["results"]:
    apex = (r.get("page", {}).get("apexDomain") or r.get("page", {}).get("domain") or "").lower()
    if not apex or apex in false_positive_sites:
        continue
    ts = r.get("task", {}).get("time")
    if not ts:
        continue
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if apex not in last_seen or dt > last_seen[apex]:
        last_seen[apex] = dt

print(f"Fresh total (raw urlscan match): 1816")
print(f"Confirmed false positives removed: {len(false_positive_sites)}")
print(f"CLEAN total confirmed compromised sites: {len(last_seen)}")
print()

last_seen_july = sum(1 for dt in last_seen.values() if dt.year == 2026 and dt.month == 7)
last_seen_since_june = sum(1 for dt in last_seen.values() if dt.year == 2026 and dt.month >= 6)
last_seen_in_2026 = sum(1 for dt in last_seen.values() if dt.year == 2026)
last_seen_2024_2025_only = sum(1 for dt in last_seen.values() if dt.year < 2026)
print("=== Cumulative recency windows (clean, false positives removed) ===")
print(f"  Last seen July 2026 (active wave): {last_seen_july}")
print(f"  Last seen since June 2026: {last_seen_since_june}")
print(f"  Last seen in 2026: {last_seen_in_2026}")
print(f"  Last seen 2024-2025 only: {last_seen_2024_2025_only}")

tld_counter = Counter()
for apex in last_seen:
    parts = apex.rsplit(".", 1)
    if len(parts) == 2:
        tld_counter["." + parts[1]] += 1
print()
print("=== TLD spread (top 15, clean) ===")
for tld, count in tld_counter.most_common(15):
    print(f"  {tld}: {count}")

with open("11_clean_confirmed_sites.txt", "w", encoding="utf-8") as f:
    for s in sorted(last_seen.keys()):
        f.write(s + "\n")

with open("11_clean_site_count_and_recency_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump({
        "fresh_raw_total": 1816,
        "false_positives_removed": len(false_positive_sites),
        "clean_total": len(last_seen),
        "recency": {
            "last_seen_july_2026": last_seen_july,
            "last_seen_since_june_2026": last_seen_since_june,
            "last_seen_in_2026": last_seen_in_2026,
            "last_seen_2024_2025_only": last_seen_2024_2025_only,
        },
        "tld_spread_top15": tld_counter.most_common(15),
    }, f, indent=2)

print()
print("Clean site list saved to 11_clean_confirmed_sites.txt")
print("Full results saved to 11_clean_site_count_and_recency_RESULTS.json")
