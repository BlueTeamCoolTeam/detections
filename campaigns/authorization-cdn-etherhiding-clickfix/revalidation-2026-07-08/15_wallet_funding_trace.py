import json, urllib.request, time, sys

WALLETS = {
    "operator1": "0xCaf2C54E400437da717cF215181B170F65187aBf",
    "operator2": "0xf1940DDBDA56074ce29bB0b6eA8D62db974870a5",
    "operator3": "0x2F9091AB4Ec91c0dAa67a7660c81A922328A8096",
}

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())

for label, addr in WALLETS.items():
    print(f"\n{'='*70}\n{label}: {addr}\n{'='*70}")
    # Get the EARLIEST incoming native-token transfer to establish funding source.
    # Blockscout internal-transactions + transactions filter=to, sorted oldest first isn't
    # directly available via a single param, so pull the wallet's counter / first page and
    # also check internal transactions (in case funded via a contract/exchange withdrawal).
    try:
        data = get(f"https://polygon.blockscout.com/api/v2/addresses/{addr}/transactions?filter=to")
        items = data.get("items", [])
        print(f"  Incoming txs (filter=to): {len(items)} on this page")
        # sort by timestamp ascending to find the earliest
        items_sorted = sorted(items, key=lambda x: x.get("timestamp") or "")
        for it in items_sorted[:5]:
            print(f"    {it.get('timestamp')}  from={it.get('from',{}).get('hash')}  value={it.get('value')}  method={it.get('method')}")
    except Exception as e:
        print("  ERROR fetching transactions:", e)
    time.sleep(0.5)

    try:
        data2 = get(f"https://polygon.blockscout.com/api/v2/addresses/{addr}/internal-transactions")
        items2 = data2.get("items", [])
        print(f"  Internal txs: {len(items2)} on this page")
        items2_sorted = sorted(items2, key=lambda x: x.get("timestamp") or "")
        for it in items2_sorted[:5]:
            print(f"    {it.get('timestamp')}  from={it.get('from',{}).get('hash')}  to={it.get('to',{}).get('hash')}  value={it.get('value')}")
    except Exception as e:
        print("  ERROR fetching internal transactions:", e)
    time.sleep(0.5)

    try:
        data3 = get(f"https://polygon.blockscout.com/api/v2/addresses/{addr}/counters")
        print(f"  Counters: {data3}")
    except Exception as e:
        print("  ERROR fetching counters:", e)
    time.sleep(0.5)
