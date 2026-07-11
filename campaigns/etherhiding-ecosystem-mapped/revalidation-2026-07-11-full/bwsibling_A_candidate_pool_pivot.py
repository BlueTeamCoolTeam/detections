#!/usr/bin/env python3
"""
Part A -- full candidate-pool re-derivation for the BW-sibling EtherHiding
operator (Family A, selector 0xb68d1809, 87 contracts / 90 C2 domains).

Unlike Operator 1/2/3 (spot-checked only), this operator's candidate pool was
never exhaustively re-derived, so this does the full rebuild: a urlscan.io
`domain:<c2>` search against ALL 90 known C2 domains, with CORRECT pagination
(search_after loop; `has_more` is documented-unreliable on this account tier
and is never trusted -- we keep paging as long as a full 100-result page came
back, and only stop on a short/empty page).

Dedupes candidate sites by page.domain across all 90 domains, excluding the
90 C2 domains themselves. Also persists, per candidate host, the urlscan
page_url/result_uuid/time/pivot-c2 metadata so Part C (checking freshly-found
candidates) can reuse the same urlscan-telemetry-first confirmation strategy
as the Part B checker.

The urlscan.io API key is read at runtime from a file path and is never
printed or embedded in this script or any output file.
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEY_FILE = r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key"
DOMAINS_FILE = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\family_a_bwsibling_all_c2_domains.txt"

API_BASE = "https://urlscan.io/api/v1/search/"
PAGE_SIZE = 100

OUT_HOSTS_TXT = "bwsibling_A_candidate_hosts.txt"
OUT_RAW_JSON = "bwsibling_A_candidate_hosts_raw.json"
OUT_REPORT_TXT = "bwsibling_A_candidate_pool_pivot_OUTPUT.txt"


def load_key(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def load_domains(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]


def api_search(query, api_key, search_after=None):
    url = f"{API_BASE}?q={urllib.parse.quote(query)}&size={PAGE_SIZE}"
    if search_after:
        url += f"&search_after={search_after}"
    req = urllib.request.Request(url, headers={"API-Key": api_key})
    last_err = None
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                wait = min(60, 5 * (attempt + 1))
                print(f"    [429] rate limited, backing off {wait}s...", flush=True)
                time.sleep(wait)
                continue
            if e.code >= 500:
                time.sleep(3 * (attempt + 1))
                continue
            raise
        except Exception as e:
            last_err = e
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"api_search: exhausted retries for query={query!r}: {last_err}")


def search_all_pages(domain, api_key):
    """Page through ALL results for domain:<domain>. Ignores has_more
    (documented unreliable on this account tier) -- keeps paging via
    search_after as long as a full PAGE_SIZE page came back; only stops on a
    short/empty page."""
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
            print(f"  [WARN] {domain}: aborting after 500 pages, something is off", flush=True)
            break
    return results


def main():
    api_key = load_key(KEY_FILE)
    c2_domains = load_domains(DOMAINS_FILE)
    assert len(c2_domains) == 90, f"expected 90 C2 domains, got {len(c2_domains)}"
    c2_set = set(c2_domains)

    # host -> list of {page_url, result_uuid, urlscan_time, c2}
    candidates_raw = {}
    per_domain_counts = {}
    per_domain_unique = {}
    errors = {}

    for i, c2 in enumerate(c2_domains, 1):
        print(f"[{i}/90] searching domain:{c2} ...", flush=True)
        try:
            hits = search_all_pages(c2, api_key)
        except Exception as e:
            print(f"  [ERROR] {c2}: {e}", flush=True)
            errors[c2] = str(e)
            per_domain_counts[c2] = 0
            per_domain_unique[c2] = 0
            continue

        seen_for_this_c2 = set()
        for item in hits:
            page = item.get("page", {}) or {}
            pd = page.get("domain")
            if not pd:
                continue
            pd = pd.lower()
            if pd in c2_set:
                continue  # exclude the C2 domains themselves
            seen_for_this_c2.add(pd)
            entry = {
                "page_url": page.get("url"),
                "result_uuid": item.get("task", {}).get("uuid") or item.get("_id"),
                "urlscan_time": item.get("task", {}).get("time") or item.get("indexedAt"),
                "c2": c2,
            }
            candidates_raw.setdefault(pd, []).append(entry)

        per_domain_counts[c2] = len(hits)
        per_domain_unique[c2] = len(seen_for_this_c2)
        print(f"  -> {len(hits)} raw scan results, {len(seen_for_this_c2)} unique page.domain values "
              f"(running total unique candidates: {len(candidates_raw)})", flush=True)
        time.sleep(0.4)

    candidate_hosts = sorted(candidates_raw.keys())

    print(f"\n{'='*70}")
    print(f"TOTAL unique candidate domains across all 90 C2 searches "
          f"(excluding the 90 C2 domains themselves): {len(candidate_hosts)}")
    print(f"{'='*70}")

    with open(OUT_HOSTS_TXT, "w", encoding="utf-8") as f:
        for h in candidate_hosts:
            f.write(h + "\n")

    with open(OUT_RAW_JSON, "w", encoding="utf-8") as f:
        json.dump(candidates_raw, f, indent=2, default=str)

    with open(OUT_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("Part A -- BW-sibling candidate pool pivot\n")
        f.write("=" * 70 + "\n")
        f.write(f"90 known C2 domains searched (domain:<c2>, full pagination, has_more not trusted)\n")
        f.write("=" * 70 + "\n")
        f.write("Raw scan-result counts per C2 domain search (raw hits / unique page.domain values):\n")
        for c2 in c2_domains:
            n = per_domain_counts.get(c2, 0)
            u = per_domain_unique.get(c2, 0)
            err = f"  [ERROR: {errors[c2]}]" if c2 in errors else ""
            f.write(f"  {c2}: {n} raw / {u} unique{err}\n")
        f.write("=" * 70 + "\n")
        f.write(f"Domains with errors after retries: {len(errors)}\n")
        f.write(f"TOTAL unique candidate domains (excluding the 90 C2 domains): {len(candidate_hosts)}\n")
        f.write("=" * 70 + "\n\n")
        f.write("Full candidate domain list:\n")
        for h in candidate_hosts:
            f.write(h + "\n")

    print(f"\nWrote {OUT_HOSTS_TXT}, {OUT_RAW_JSON}, {OUT_REPORT_TXT}")
    if errors:
        print(f"WARNING: {len(errors)} domain searches errored after retries: {sorted(errors.keys())}")


if __name__ == "__main__":
    main()
