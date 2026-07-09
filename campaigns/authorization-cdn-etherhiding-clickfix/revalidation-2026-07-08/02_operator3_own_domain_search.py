import json, sys, time, urllib.request, urllib.error

API_KEY = sys.argv[1]
PAGE_SIZE = 100
MAX_PAGES = 15

DOMAINS = ["errrkotmlkpoy.xyz", "huishuvish.cc", "pluhabovra.info", "hilacbatoriaaa.cc"]

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
            print(f"    ERROR {domain}: HTTP {e.code} {e.read().decode()[:200]}")
            break
        except Exception as e:
            print(f"    ERROR {domain}: {e}")
            break
        results = data.get("results", [])
        total_reported = data.get("total", total_reported)
        pages += 1
        raw_seen += len(results)
        for r in results:
            d = r.get("page", {}).get("domain")
            if d:
                hostnames.add(d)
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

print("OPERATOR 3 (4 newly-discovered domains)")
all_hosts = set()
for d in DOMAINS:
    hosts, total_reported, pages, raw_seen = search(d)
    all_hosts |= hosts
    print(f"  {d:30s} unique={len(hosts):4d} api_total={total_reported} raw_fetched={raw_seen} pages={pages}")
    time.sleep(0.3)
print(f"\nTOTAL UNIQUE candidates for operator 3: {len(all_hosts)}")
print(sorted(all_hosts))

with open("revalidate_op3_hosts.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(all_hosts)))
