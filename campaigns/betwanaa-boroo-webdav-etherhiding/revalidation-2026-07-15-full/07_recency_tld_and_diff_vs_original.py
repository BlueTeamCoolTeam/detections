#!/usr/bin/env python3
"""
Phase 3: recency segmentation + TLD spread, recomputed fresh from
06_urlscan_site_enumeration_fresh_RAW.json, plus a direct diff against the
original report's site list
(blogs/drafts/cduh-betwanaa-pcalua-webdav/cduh-betwanaa-pcalua-webdav/artifacts/18_compromised_sites_1815_apex.txt)
to see exactly which domains are new vs remediated since report.md was written.
"""
import json
from collections import Counter
from datetime import datetime, timezone

with open("06_urlscan_site_enumeration_fresh_RAW.json", encoding="utf-8") as f:
    data = json.load(f)

results = data["results"]

# per-apex-domain last-seen timestamp (max across all scan events for that apex)
last_seen = {}
for r in results:
    apex = (r.get("page", {}).get("apexDomain") or r.get("page", {}).get("domain") or "").lower()
    if not apex:
        continue
    ts = r.get("task", {}).get("time")
    if not ts:
        continue
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if apex not in last_seen or dt > last_seen[apex]:
        last_seen[apex] = dt

now = datetime(2026, 7, 15, tzinfo=timezone.utc)


def bucket(dt):
    if dt.year == 2026 and dt.month == 7:
        return "2026-07 (active wave)"
    if dt.year == 2026 and dt.month == 6:
        return "2026-06"
    if dt.year == 2026:
        return "2026 (other months)"
    return "2024-2025 only"


buckets = Counter(bucket(dt) for dt in last_seen.values())
print("=== Recency segmentation (fresh, 2026-07-15) ===")
for k in ["2026-07 (active wave)", "2026-06", "2026 (other months)", "2024-2025 only"]:
    print(f"  {k}: {buckets.get(k, 0)}")

# cumulative buckets matching report.md's framing (last seen July / since June / in 2026 / 2024-2025 only)
last_seen_july = sum(1 for dt in last_seen.values() if dt.year == 2026 and dt.month == 7)
last_seen_since_june = sum(1 for dt in last_seen.values() if dt.year == 2026 and dt.month >= 6)
last_seen_in_2026 = sum(1 for dt in last_seen.values() if dt.year == 2026)
last_seen_2024_2025_only = sum(1 for dt in last_seen.values() if dt.year < 2026)
print()
print("=== Cumulative windows (matching report.md's table framing) ===")
print(f"  Last seen July 2026 (active wave): {last_seen_july}")
print(f"  Last seen since June 2026: {last_seen_since_june}")
print(f"  Last seen in 2026: {last_seen_in_2026}")
print(f"  Last seen 2024-2025 only: {last_seen_2024_2025_only}")

# TLD spread
tld_counter = Counter()
for apex in last_seen:
    parts = apex.rsplit(".", 1)
    if len(parts) == 2:
        tld_counter["." + parts[1]] += 1
print()
print("=== TLD spread (top 15, fresh) ===")
for tld, count in tld_counter.most_common(15):
    print(f"  {tld}: {count}")

# diff vs original report's list
ORIGINAL_LIST = (
    r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\blogs\drafts\cduh-betwanaa-pcalua-webdav"
    r"\cduh-betwanaa-pcalua-webdav\artifacts\18_compromised_sites_1815_apex.txt"
)
with open(ORIGINAL_LIST, encoding="utf-8") as f:
    original_set = set(line.strip().lower() for line in f if line.strip())

fresh_set = set(last_seen.keys())

only_in_original = sorted(original_set - fresh_set)
only_in_fresh = sorted(fresh_set - original_set)
in_both = original_set & fresh_set

print()
print("=== Diff vs original report.md list (artifacts/18) ===")
print(f"  Original list size: {len(original_set)}")
print(f"  Fresh list size: {len(fresh_set)}")
print(f"  In both: {len(in_both)}")
print(f"  Only in original (possibly remediated since): {len(only_in_original)}")
print(f"  Only in fresh (newly compromised / newly surfaced since): {len(only_in_fresh)}")

with open("07_recency_tld_and_diff_vs_original_RESULTS.json", "w", encoding="utf-8") as f:
    json.dump({
        "fresh_total_unique_apex_domains": len(fresh_set),
        "original_total_unique_apex_domains": len(original_set),
        "in_both": len(in_both),
        "only_in_original": only_in_original,
        "only_in_fresh": only_in_fresh,
        "recency_cumulative": {
            "last_seen_july_2026": last_seen_july,
            "last_seen_since_june_2026": last_seen_since_june,
            "last_seen_in_2026": last_seen_in_2026,
            "last_seen_2024_2025_only": last_seen_2024_2025_only,
        },
        "tld_spread_top15": tld_counter.most_common(15),
    }, f, indent=2)

print()
print("Full results saved to 07_recency_tld_and_diff_vs_original_RESULTS.json")
