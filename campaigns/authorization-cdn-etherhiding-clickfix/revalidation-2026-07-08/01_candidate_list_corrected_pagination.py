import json, sys, time, urllib.request, urllib.error

API_KEY = sys.argv[1]
PAGE_SIZE = 100
MAX_PAGES = 15  # safety cap = up to 1500 results per domain

OP1_DOMAINS = [
    "authorization-cdn-press-enter.info", "authorization-code.beer", "authorization-id-code.info",
    "codeverificatrorcl.info", "authorization-code.info", "idverification-cdn.info",
    "verificationscodes.beer", "code.verification-claude-cdn.beer", "claudverification-id.beer",
    "idverification-code.beer", "codecerification.beer", "code-verification-js.beer",
    "verification-code-js.beer", "svs-verificationdate.beer", "verification-js-cdn.boats",
    "framework-css-styles-js.beer", "ethercdnns.beer", "xdavnode.pro",
]
OP2_DOMAINS = ["letsgomakemoneyoncaptcha.beer", "hahletsgoagain.beer", "iwannagetmoremoney.beer"]

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
            print(f"    ERROR page {pages+1} for {domain}: HTTP {e.code} {e.read().decode()[:200]}")
            break
        except Exception as e:
            print(f"    ERROR page {pages+1} for {domain}: {e}")
            break
        results = data.get("results", [])
        total_reported = data.get("total", total_reported)
        pages += 1
        raw_seen += len(results)
        for r in results:
            d = r.get("page", {}).get("domain")
            if d:
                hostnames.add(d)
        # Ignore has_more (confirmed unreliable on this account tier) -- paginate
        # as long as a full page was returned, or until total_reported is covered.
        if len(results) < PAGE_SIZE:
            break
        if total_reported is not None and raw_seen >= total_reported:
            break
        last = results[-1]
        sort = last.get("sort")
        if not sort:
            break
        search_after = ",".join(str(s) for s in sort)
        time.sleep(0.4)
    return hostnames, total_reported, pages, raw_seen

def run(label, domains, baseline_file):
    print(f"\n{'='*72}\n{label}\n{'='*72}")
    all_hosts = set()
    for d in domains:
        hosts, total_reported, pages, raw_seen = search(d)
        all_hosts |= hosts
        flag = "  <-- more raw results than page-1 alone would show" if pages > 1 else ""
        print(f"  {d:45s} unique={len(hosts):4d}  api_total={total_reported:<6} raw_fetched={raw_seen:<5} pages={pages}{flag}")
        time.sleep(0.3)
    print(f"\n  TOTAL UNIQUE (corrected re-run): {len(all_hosts)}")
    try:
        with open(baseline_file, encoding="utf-8", errors="replace") as f:
            baseline = set(x.strip() for x in f if x.strip())
        print(f"  BASELINE ({baseline_file}): {len(baseline)}")
        only_new = all_hosts - baseline
        only_old = baseline - all_hosts
        print(f"  New vs baseline: {len(only_new)}   Dropped vs baseline: {len(only_old)}")
    except FileNotFoundError:
        print(f"  (no baseline file at {baseline_file})")
    return all_hosts

op1 = run("OPERATOR 1 (18 domains) -- CORRECTED PAGINATION", OP1_DOMAINS, "artifacts/compromised_sites_all.txt")
op2 = run("OPERATOR 2 (3 domains) -- CORRECTED PAGINATION", OP2_DOMAINS, "artifacts/operator2_candidate_sites.txt")

with open("artifacts/revalidate_op1_hosts_v2.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(op1)))
with open("artifacts/revalidate_op2_hosts_v2.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(op2)))
overlap = op1 & op2
print(f"\nOverlap between op1 and op2 candidate sets (corrected): {len(overlap)}")
print(f"Combined unique across both operators: {len(op1 | op2)}")
print("\nWrote artifacts/revalidate_op1_hosts_v2.txt and artifacts/revalidate_op2_hosts_v2.txt")
