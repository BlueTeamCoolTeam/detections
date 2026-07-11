#!/usr/bin/env python3
"""
Part A - light candidate-pool consistency check for Operator 1 ("xdav" /
authorization-cdn EtherHiding operator).

Re-runs a urlscan.io domain: search for each of the operator's 18 historical
C2 domains (as published in the 2026-07-08 post's IOC table / updateDomain
history), with CORRECT pagination (search_after loop, does not trust
has_more - a previously-documented bug on this account tier means has_more
can be False even when a full page of 100 results came back).

Dedupes candidate sites by page.domain, excludes the 18 C2 domains
themselves, and reports the resulting candidate pool size.

The urlscan.io API key is read at runtime from a file path (never embedded
in this script or printed to any output).
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEY_FILE = r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key"

# 18 historical C2 domains for Operator 1, per the 2026-07-08 post's
# on-chain updateDomain history / IOC table.
C2_DOMAINS = [
    "authorization-cdn-press-enter.info",
    "authorization-code.beer",
    "authorization-id-code.info",
    "codeverificatrorcl.info",
    "authorization-code.info",
    "idverification-cdn.info",
    "verificationscodes.beer",
    "code.verification-claude-cdn.beer",
    "claudverification-id.beer",
    "idverification-code.beer",
    "codecerification.beer",
    "code-verification-js.beer",
    "verification-code-js.beer",
    "svs-verificationdate.beer",
    "verification-js-cdn.boats",
    "framework-css-styles-js.beer",
    "ethercdnns.beer",
    "xdavnode.pro",
]

assert len(C2_DOMAINS) == 18, f"expected 18 C2 domains, got {len(C2_DOMAINS)}"

API_BASE = "https://urlscan.io/api/v1/search/"
PAGE_SIZE = 100


def load_key(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def api_search(query, api_key, search_after=None):
    url = f"{API_BASE}?q={urllib.parse.quote(query)}&size={PAGE_SIZE}"
    if search_after:
        url += f"&search_after={search_after}"
    req = urllib.request.Request(url, headers={"API-Key": api_key})
    max_attempts = 8
    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                # rate-limited or transient server-side error (e.g. 503) - back off and retry
                if attempt == max_attempts - 1:
                    raise
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except Exception:
            if attempt == max_attempts - 1:
                raise
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("api_search: exhausted retries")


def search_all_pages(domain, api_key):
    """Page through ALL results for domain:<domain>, ignoring has_more
    (documented unreliable) - keep paging via search_after as long as a
    full PAGE_SIZE page comes back; stop when a short/empty page arrives."""
    query = f"domain:{domain}"
    results = []
    search_after = None
    page_num = 0
    while True:
        page_num += 1
        data = api_search(query, api_key, search_after)
        items = data.get("results", [])
        results.extend(items)
        if len(items) < PAGE_SIZE:
            break
        last = items[-1]
        sort_vals = last.get("sort")
        if not sort_vals:
            break
        search_after = ",".join(str(v) for v in sort_vals)
        time.sleep(0.3)
        if page_num > 500:
            print(f"  [WARN] {domain}: aborting after 500 pages, something is off")
            break
    return results


def main():
    api_key = load_key(KEY_FILE)
    c2_set = set(d.lower() for d in C2_DOMAINS)

    candidate_domains = set()
    per_domain_counts = {}

    for i, c2 in enumerate(C2_DOMAINS, 1):
        print(f"[{i}/18] searching domain:{c2} ...")
        try:
            hits = search_all_pages(c2, api_key)
        except Exception as e:
            print(f"  [ERROR] {c2}: {e}")
            per_domain_counts[c2] = f"ERROR: {e}"
            continue
        seen_for_this_c2 = set()
        for item in hits:
            page = item.get("page", {}) or {}
            pd = page.get("domain")
            if not pd:
                continue
            pd = pd.lower()
            seen_for_this_c2.add(pd)
        per_domain_counts[c2] = len(hits)
        print(f"  -> {len(hits)} raw scan results, {len(seen_for_this_c2)} unique page.domain values")
        candidate_domains |= seen_for_this_c2
        time.sleep(0.5)

    # exclude the 18 C2 domains themselves from the candidate pool
    candidate_domains -= c2_set

    print(f"\n{'='*60}")
    print(f"Raw scan-result counts per C2 domain search:")
    for c2, n in per_domain_counts.items():
        print(f"  {c2}: {n}")
    print(f"{'='*60}")
    print(f"TOTAL unique candidate domains (excluding the 18 C2 domains): {len(candidate_domains)}")
    print(f"{'='*60}")

    out_file = "op1_A_candidate_pool_recheck_OUTPUT.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("Part A - Operator 1 candidate pool recheck\n")
        f.write("=" * 60 + "\n")
        f.write("Raw scan-result counts per C2 domain search:\n")
        for c2, n in per_domain_counts.items():
            f.write(f"  {c2}: {n}\n")
        f.write("=" * 60 + "\n")
        f.write(f"TOTAL unique candidate domains (excluding the 18 C2 domains): {len(candidate_domains)}\n")
        f.write("=" * 60 + "\n\n")
        f.write("Full candidate domain list:\n")
        for d in sorted(candidate_domains):
            f.write(d + "\n")

    print(f"\nWrote {out_file}")


if __name__ == "__main__":
    main()
