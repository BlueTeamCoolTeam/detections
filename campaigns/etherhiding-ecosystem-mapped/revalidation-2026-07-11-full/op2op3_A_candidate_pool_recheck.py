#!/usr/bin/env python3
"""
PART A - light candidate-pool consistency check for Operator 2 and Operator 3.

For each of Operator 2's 3 domains and Operator 3's 4 domains (pulled from the
IOC table in site/_posts/2026-07-08-authorization-cdn-etherhiding-clickfix.md),
re-run a urlscan.io Search API `domain:` search with CORRECT pagination
(search_after cursor, not the unreliable `has_more` flag) and report the
resulting deduped candidate-pool size (by page.domain), excluding the
operators' own C2 domains.

The urlscan API key is read at runtime from a file path given on argv[1] (or
the default below). The key is NEVER printed or embedded in this script or in
any output file - only used in the API-Key request header.
"""
import json
import sys
import time
import urllib.error
import urllib.request

KEY_FILE = sys.argv[1] if len(sys.argv) > 1 else (
    r"C:\Users\bob\AppData\Local\Temp\claude\C--Users-bob-Documents-Tools-BlueTeamCoolTeam"
    r"\eb03ed5f-0b05-4492-92cb-b207e59eece9\scratchpad\urlscan_key"
)
OUT_FILE = "op2op3_A_candidate_pool_recheck_OUTPUT.txt"

with open(KEY_FILE, "r", encoding="utf-8") as f:
    API_KEY = f.read().strip()

OPERATOR2_DOMAINS = [
    "iwannagetmoremoney.beer",
    "hahletsgoagain.beer",
    "letsgomakemoneyoncaptcha.beer",
]
OPERATOR3_DOMAINS = [
    "hilacbatoriaaa.cc",
    "pluhabovra.info",
    "huishuvish.cc",
    "errrkotmlkpoy.xyz",
]

SEARCH_URL = "https://urlscan.io/api/v1/search/"
PAGE_SIZE = 100
MAX_PAGES_SAFETY = 200  # hard stop so a runaway loop can't hammer the API forever


import urllib.parse


def do_search(query, search_after=None):
    params = {"q": query, "size": str(PAGE_SIZE)}
    if search_after is not None:
        params["search_after"] = search_after
    url = SEARCH_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"API-Key": API_KEY, "User-Agent": "btct-revalidation/1.0"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 5 * (attempt + 1)
                print(f"    429 rate-limited, backing off {wait}s...")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"Failed after retries: {query}")


def search_all_pages(domain):
    """Page a urlscan domain: search via search_after, ignoring has_more,
    stopping only when a page returns fewer than PAGE_SIZE results."""
    query = f"domain:{domain}"
    all_results = []
    search_after = None
    page_num = 0
    while True:
        page_num += 1
        if page_num > MAX_PAGES_SAFETY:
            print(f"    !! hit safety page cap ({MAX_PAGES_SAFETY}) for {domain}, stopping")
            break
        data = do_search(query, search_after)
        results = data.get("results", [])
        all_results.extend(results)
        print(f"    page {page_num}: {len(results)} results (has_more={data.get('has_more')}, running total={len(all_results)})")
        if len(results) < PAGE_SIZE:
            break
        last = results[-1]
        sort_vals = last.get("sort")
        if not sort_vals:
            print("    !! no sort cursor on last result, cannot page further, stopping")
            break
        search_after = ",".join(str(v) for v in sort_vals)
        time.sleep(1.0)  # be polite to the API between pages
    return all_results


def extract_domains(results):
    domains = set()
    for r in results:
        d = r.get("page", {}).get("domain")
        if d:
            domains.add(d.lower())
    return domains


def run_operator(name, domains_to_query, own_domains):
    print(f"\n{'='*70}\n{name}\n{'='*70}")
    union = set()
    per_domain = {}
    for d in domains_to_query:
        print(f"  Searching domain:{d} ...")
        results = search_all_pages(d)
        found = extract_domains(results)
        per_domain[d] = found
        union |= found
        print(f"  -> {len(found)} distinct page.domain values for domain:{d}")
        time.sleep(1.0)
    own_lower = {o.lower() for o in own_domains}
    candidate_pool = union - own_lower
    return per_domain, union, candidate_pool


def main():
    lines = []
    lines.append("PART A - Candidate pool consistency recheck (urlscan.io Search API)")
    lines.append(f"Run timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    lines.append(f"Query domains - Operator 2 ({len(OPERATOR2_DOMAINS)}): {', '.join(OPERATOR2_DOMAINS)}")
    lines.append(f"Query domains - Operator 3 ({len(OPERATOR3_DOMAINS)}): {', '.join(OPERATOR3_DOMAINS)}")
    lines.append("Pagination method: search_after cursor, page repeated until a page returns")
    lines.append("fewer than 100 results (has_more flag NOT trusted per task instructions).")
    lines.append("")

    all_own = set(d.lower() for d in OPERATOR2_DOMAINS) | set(d.lower() for d in OPERATOR3_DOMAINS)

    op2_per_domain, op2_union, op2_pool = run_operator("OPERATOR 2", OPERATOR2_DOMAINS, all_own)
    op3_per_domain, op3_union, op3_pool = run_operator("OPERATOR 3", OPERATOR3_DOMAINS, all_own)

    lines.append("\n" + "=" * 70)
    lines.append("RESULTS - OPERATOR 2")
    lines.append("=" * 70)
    for d, found in op2_per_domain.items():
        lines.append(f"domain:{d} -> {len(found)} distinct page.domain values")
    lines.append(f"Union of distinct page.domain across all 3 Operator-2 domains: {len(op2_union)}")
    lines.append(f"Candidate pool (union minus operators' own C2 domains): {len(op2_pool)}")
    lines.append("Previously published candidate pool size (2026-07-08 post): 150")
    lines.append("")
    lines.append("Candidate pool members (Operator 2):")
    for h in sorted(op2_pool):
        lines.append(f"  {h}")

    lines.append("\n" + "=" * 70)
    lines.append("RESULTS - OPERATOR 3")
    lines.append("=" * 70)
    for d, found in op3_per_domain.items():
        lines.append(f"domain:{d} -> {len(found)} distinct page.domain values")
    lines.append(f"Union of distinct page.domain across all 4 Operator-3 domains: {len(op3_union)}")
    lines.append(f"Candidate pool (union minus operators' own C2 domains): {len(op3_pool)}")
    lines.append("Previously published candidate pool size (2026-07-08 post): 4")
    lines.append("")
    lines.append("Candidate pool members (Operator 3):")
    for h in sorted(op3_pool):
        lines.append(f"  {h}")

    out_text = "\n".join(lines)
    print("\n" + out_text)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(out_text + "\n")
    print(f"\nWrote {OUT_FILE}")


if __name__ == "__main__":
    main()
