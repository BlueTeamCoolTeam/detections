#!/usr/bin/env python3
"""
PART A - full candidate-pool re-derivation for the mamkor/merabs EtherHiding
operator (Polygon eth_call selector 0x38bcdc1c, contract
0x08207B087F61d7e95E441E15fd6d40BEfd6eD308).

For every historical C2 domain this operator has ever rotated the contract
to, run a urlscan.io Search API `domain:` pivot and collect every DISTINCT
website (page.domain) that has ever loaded/redirected through that C2 domain.
This is the "candidate pool" of possibly-compromised sites - a superset that
still needs live re-confirmation (done separately in Part B).

Pagination correctness note (per prior sibling-campaign incident): urlscan's
`has_more` field on the search endpoint is NOT reliable on this account tier.
The only trustworthy signal that more results exist is "did this page come
back completely full (== size)?". So we keep paging via `search_after` as
long as a full page (100 results) is returned, and only stop on a partial or
empty page - regardless of what `has_more` claims.

Resilience notes (added after a live run hit sustained 429 rate-limiting
partway through, on domain #7 of 108 - a domain with 6377 total results that
alone needed 64 pages):
  - Per-domain checkpointing: results for each domain are appended to a JSONL
    checkpoint file as soon as that domain finishes, so a crash/interrupt does
    not lose already-completed domains - a re-run skips domains already
    checkpointed.
  - Partial-result preservation: if a domain's pagination fails partway
    through (e.g. retries exhausted on a later page), the pages already
    fetched for that domain are still kept and checkpointed (flagged
    "partial") rather than discarded.
  - Longer/more patient backoff on 429: exponential backoff up to 60s, 10
    attempts, since the account's rate limit did not clear within a first
    attempt at 3..18s backoff.

The API key is read from disk at runtime and is never printed, logged, or
embedded in any output file.
"""
import json
import os
import re
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

KEY_PATH = r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key_2"
DOMAINS_PATH = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\family_b_mamkor_all_c2_domains.txt"
OUT_DIR = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\revalidation-2026-07-11-full"
CHECKPOINT_PATH = OUT_DIR + r"\mamkor_A_checkpoint.jsonl"

SEARCH_URL = "https://urlscan.io/api/v1/search/"
PAGE_SIZE = 100
REQUEST_SLEEP = 1.5           # base pacing between successful page requests
MAX_RETRIES = 10              # per-page retry budget on 429/5xx/transient errors
MAX_BACKOFF = 60              # seconds, cap for exponential backoff


def load_key():
    with open(KEY_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()


def normalize_domain(line):
    l = line.strip()
    if not l:
        return None
    l = re.sub(r"^https?://", "", l, flags=re.I)
    l = l.split("/")[0]
    l = l.strip().lower().rstrip(".")
    return l or None


def load_c2_domains():
    raw = [l for l in open(DOMAINS_PATH, "r", encoding="utf-8") if l.strip()]
    normed = sorted(set(filter(None, (normalize_domain(l) for l in raw))))
    return raw, normed


def load_checkpoint():
    """Return {domain: record} for domains already fully completed (non-partial)."""
    done = {}
    if os.path.exists(CHECKPOINT_PATH):
        with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                # keep the LATEST record for a domain (later lines override earlier ones)
                done[rec["domain"]] = rec
    return done


def append_checkpoint(record):
    with open(CHECKPOINT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def api_get(url, api_key):
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers={
                "API-Key": api_key,
                "User-Agent": "btct-revalidation/1.0",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace")), None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            if e.code == 429:
                wait = min(MAX_BACKOFF, 3 * (attempt + 1))
                print(f"    [429 rate-limited] backing off {wait}s (attempt {attempt+1}/{MAX_RETRIES})", flush=True)
                time.sleep(wait)
                last_err = f"429: {body[:200]}"
                continue
            elif e.code in (500, 502, 503, 504):
                wait = min(MAX_BACKOFF, 2 * (attempt + 1))
                print(f"    [{e.code}] server error, retrying in {wait}s: {body[:200]}", flush=True)
                time.sleep(wait)
                last_err = f"{e.code}: {body[:200]}"
                continue
            else:
                print(f"    [HTTPError {e.code}] {url} -> {body[:300]}", flush=True)
                return None, f"HTTPError {e.code}: {body[:300]}"
        except Exception as e:
            wait = min(MAX_BACKOFF, 2 * (attempt + 1))
            print(f"    [error] {e} - retrying in {wait}s (attempt {attempt+1}/{MAX_RETRIES})", flush=True)
            time.sleep(wait)
            last_err = str(e)
    return None, f"giving up after {MAX_RETRIES} attempts: {last_err}"


def search_domain_all_pages(domain, api_key):
    """Return (results, error_or_None). On a mid-pagination failure, whatever
    pages were already successfully fetched are still returned (error is set
    to describe what went wrong so it's recorded, but data is NOT discarded).
    """
    results = []
    search_after = None
    page_num = 0
    while True:
        page_num += 1
        q = f"domain:{domain}"
        url = f"{SEARCH_URL}?q={urllib.parse.quote(q)}&size={PAGE_SIZE}"
        if search_after:
            url += f"&search_after={search_after}"
        data, err = api_get(url, api_key)
        if err:
            return results, f"failed on page {page_num}: {err}"

        page_results = data.get("results", [])
        total = data.get("total", "?")
        has_more_flag = data.get("has_more")
        print(f"    page {page_num}: got {len(page_results)} results (total={total}, "
              f"has_more(unreliable)={has_more_flag})", flush=True)
        results.extend(page_results)
        time.sleep(REQUEST_SLEEP)

        if len(page_results) < PAGE_SIZE:
            break  # partial (or empty) page -> genuinely done

        last = page_results[-1]
        sort_vals = last.get("sort")
        if not sort_vals:
            print("    [warn] full page but no 'sort' field on last result - stopping pagination here", flush=True)
            break
        search_after = ",".join(str(v) for v in sort_vals)

    return results, None


def main():
    api_key = load_key()
    raw_lines, c2_domains = load_c2_domains()
    checkpoint = load_checkpoint()

    print(f"Revalidation timestamp (UTC): {datetime.now(timezone.utc).isoformat()}", flush=True)
    print(f"Raw lines in {DOMAINS_PATH}: {len(raw_lines)}", flush=True)
    print(f"Unique normalized C2 domains (search terms): {len(c2_domains)}", flush=True)
    already_done = sum(1 for d in c2_domains if d in checkpoint and not checkpoint[d].get("partial"))
    print(f"Resuming from checkpoint: {already_done}/{len(c2_domains)} domains already fully completed", flush=True)
    print("Search terms:", flush=True)
    for d in c2_domains:
        print(f"  {d}", flush=True)
    print(flush=True)

    c2_set = set(c2_domains)

    for i, dom in enumerate(c2_domains, 1):
        if dom in checkpoint and not checkpoint[dom].get("partial"):
            print(f"[{i}/{len(c2_domains)}] domain:{dom} -- SKIP (already checkpointed: "
                  f"{checkpoint[dom]['raw_results']} raw, {len(checkpoint[dom]['unique_page_domains'])} unique)", flush=True)
            continue

        print(f"[{i}/{len(c2_domains)}] domain:{dom}", flush=True)
        results, err = search_domain_all_pages(dom, api_key)

        found_here = set()
        for r in results:
            pd = (((r.get("page") or {}).get("domain")) or "").strip().lower().rstrip(".")
            if pd:
                found_here.add(pd)

        record = {
            "domain": dom,
            "raw_results": len(results),
            "unique_page_domains": sorted(found_here),
            "partial": bool(err),
            "error": err,
        }
        append_checkpoint(record)
        checkpoint[dom] = record

        if err:
            print(f"  -> PARTIAL: {len(results)} raw results, {len(found_here)} unique page.domain values "
                  f"before failure ({err})", flush=True)
        else:
            print(f"  -> {len(results)} raw results, {len(found_here)} unique page.domain values this domain", flush=True)

    # ---- Aggregate from checkpoint (covers this run + any prior resumed runs) ----
    candidate_domains = set()
    per_domain_counts = {}
    all_raw_results = 0
    any_partial = []

    for dom in c2_domains:
        rec = checkpoint.get(dom)
        if not rec:
            per_domain_counts[dom] = {"error": "never completed"}
            continue
        per_domain_counts[dom] = {
            "raw_results": rec["raw_results"],
            "unique_page_domains": len(rec["unique_page_domains"]),
            "partial": rec.get("partial", False),
        }
        all_raw_results += rec["raw_results"]
        candidate_domains.update(rec["unique_page_domains"])
        if rec.get("partial"):
            any_partial.append((dom, rec.get("error")))

    candidate_pool = sorted(candidate_domains - c2_set)
    excluded_self_hits = sorted(candidate_domains & c2_set)

    print("\n=== Per-domain result counts ===", flush=True)
    for dom in c2_domains:
        info = per_domain_counts.get(dom, {})
        print(f"  {dom}: {info}", flush=True)

    if any_partial:
        print(f"\n=== WARNING: {len(any_partial)} domain(s) only partially paginated (data may be incomplete) ===", flush=True)
        for dom, err in any_partial:
            print(f"  {dom}: {err}", flush=True)

    print(f"\n=== Aggregate ===", flush=True)
    print(f"Total raw urlscan results across all {len(c2_domains)} C2 domain searches: {all_raw_results}", flush=True)
    print(f"Total distinct page.domain values seen (incl. C2 domains themselves): {len(candidate_domains)}", flush=True)
    print(f"C2 domains that showed up as page.domain of their own scans (excluded from pool): {len(excluded_self_hits)}", flush=True)
    for d in excluded_self_hits:
        print(f"    {d}", flush=True)
    print(f"\nFINAL CANDIDATE POOL SIZE (unique third-party page.domain values, C2 domains excluded): {len(candidate_pool)}", flush=True)

    with open(f"{OUT_DIR}\\mamkor_A_candidate_hosts.txt", "w", encoding="utf-8") as f:
        for d in candidate_pool:
            f.write(d + "\n")

    with open(f"{OUT_DIR}\\mamkor_A_candidate_hosts.json", "w", encoding="utf-8") as f:
        json.dump({
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "c2_search_terms": c2_domains,
            "candidate_pool_size": len(candidate_pool),
            "candidate_pool": candidate_pool,
            "per_domain_counts": per_domain_counts,
            "excluded_self_hits": excluded_self_hits,
            "total_raw_results": all_raw_results,
            "partial_domains": any_partial,
        }, f, indent=1)

    print(f"\nWrote {OUT_DIR}\\mamkor_A_candidate_hosts.txt and .json", flush=True)


if __name__ == "__main__":
    main()
