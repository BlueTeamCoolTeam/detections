"""
Step 1 - candidate list build, all three operators, single run.

For each known historical/current C2 domain across all three operators, queries
urlscan.io's Search API (q=domain:<X>) with CORRECTED pagination: continues
paging via search_after as long as a full 100-result page comes back, and
cross-checks the running raw-result count against the API's own reported
`total` field. The `has_more` field is intentionally never consulted -- it was
proven unreliable on this account tier in the prior 2026-07-08 pass (returns
false even when hundreds of further results exist).

Every domain's per-page progress is printed. The full, deduplicated hostname
list per operator is written to <operator>_candidates_raw.txt (this is the
RAW list, before self-match filtering -- see step 2).

Usage: python 01_candidate_search_all_operators.py <URLSCAN_API_KEY>
"""
import json, sys, time, urllib.request, urllib.error, os

API_KEY = sys.argv[1]
PAGE_SIZE = 100
MAX_PAGES = 20  # safety cap = up to 2000 results per domain

HERE = os.path.dirname(__file__)

OPERATORS = {
    "operator1": [
        "authorization-cdn-press-enter.info", "authorization-code.beer", "authorization-id-code.info",
        "codeverificatrorcl.info", "authorization-code.info", "idverification-cdn.info",
        "verificationscodes.beer", "code.verification-claude-cdn.beer", "claudverification-id.beer",
        "idverification-code.beer", "codecerification.beer", "code-verification-js.beer",
        "verification-code-js.beer", "svs-verificationdate.beer", "verification-js-cdn.boats",
        "framework-css-styles-js.beer", "ethercdnns.beer", "xdavnode.pro",
    ],
    "operator2": [
        "letsgomakemoneyoncaptcha.beer", "hahletsgoagain.beer", "iwannagetmoremoney.beer",
    ],
    "operator3": [
        "errrkotmlkpoy.xyz", "huishuvish.cc", "pluhabovra.info", "hilacbatoriaaa.cc",
    ],
}


def fetch_page(domain, search_after=None):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={PAGE_SIZE}"
    if search_after:
        url += f"&search_after={search_after}"
    req = urllib.request.Request(url, headers={"API-Key": API_KEY})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())


def search(domain):
    hostnames = set()
    search_after = None
    pages = 0
    total_reported = None
    raw_seen = 0
    for _ in range(MAX_PAGES):
        try:
            data = fetch_page(domain, search_after)
        except urllib.error.HTTPError as e:
            print(f"    ERROR page {pages + 1} for {domain}: HTTP {e.code} {e.read().decode()[:300]}")
            break
        except Exception as e:
            print(f"    ERROR page {pages + 1} for {domain}: {e}")
            break
        results = data.get("results", [])
        total_reported = data.get("total", total_reported)
        has_more_reported = data.get("has_more")
        pages += 1
        raw_seen += len(results)
        for r in results:
            d = r.get("page", {}).get("domain")
            if d:
                hostnames.add(d)
        print(f"      page {pages}: {len(results)} results  (api total={total_reported}  has_more_field={has_more_reported}  cumulative_raw={raw_seen}  cumulative_unique={len(hostnames)})")
        if len(results) < PAGE_SIZE:
            print(f"      -> partial page, genuinely done")
            break
        if total_reported is not None and raw_seen >= total_reported:
            print(f"      -> raw_seen ({raw_seen}) reached api total ({total_reported}), done")
            break
        last = results[-1]
        sort = last.get("sort")
        if not sort:
            print(f"      -> no sort value on last result, cannot page further, stopping")
            break
        search_after = ",".join(str(s) for s in sort)
        time.sleep(0.4)
    else:
        print(f"      *** HIT {MAX_PAGES}-PAGE SAFETY CAP -- RESULTS MAY BE TRUNCATED ***")
    return hostnames, total_reported, pages, raw_seen


print(f"SESSION START (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
print(f"Querying {sum(len(v) for v in OPERATORS.values())} domains across 3 operators\n")

all_results = {}
for op, domains in OPERATORS.items():
    print(f"{'=' * 76}\n{op.upper()} -- {len(domains)} domains\n{'=' * 76}")
    op_hosts = set()
    op_summary = []
    for d in domains:
        print(f"  {d}")
        hosts, total_reported, pages, raw_seen = search(d)
        op_hosts |= hosts
        op_summary.append((d, len(hosts), total_reported, raw_seen, pages))
        time.sleep(0.3)
    print(f"\n  --- {op} per-domain summary ---")
    for d, uniq, total, raw, pages in op_summary:
        print(f"    {d:45s} unique={uniq:5d}  api_total={str(total):<6}  raw_fetched={raw:<5}  pages={pages}")
    print(f"\n  {op} TOTAL UNIQUE (raw, before self-match filter): {len(op_hosts)}")
    all_results[op] = op_hosts
    outfile = os.path.join(HERE, f"{op}_candidates_raw.txt")
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(op_hosts)))
    print(f"  wrote {outfile} ({len(op_hosts)} hostnames)\n")
    time.sleep(0.5)

print(f"{'=' * 76}\nCROSS-OPERATOR OVERLAP (raw, before self-match filter)\n{'=' * 76}")
o1, o2, o3 = all_results["operator1"], all_results["operator2"], all_results["operator3"]
print(f"operator1 ^ operator2: {len(o1 & o2)}")
print(f"operator1 ^ operator3: {len(o1 & o3)}")
print(f"operator2 ^ operator3: {len(o2 & o3)}")
print(f"union of all three (raw): {len(o1 | o2 | o3)}")
print(f"\nSESSION END (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
