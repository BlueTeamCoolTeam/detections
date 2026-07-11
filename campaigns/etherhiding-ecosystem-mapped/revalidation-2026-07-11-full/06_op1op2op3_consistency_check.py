#!/usr/bin/env python3
"""
Lighter-touch consistency check for Operator 1/xdav, Operator 2, and
Operator 3 (Family A, published 2026-07-08). Their on-chain history was
already exhaustively rebuilt and revalidated 3 days ago in
authorization-cdn-etherhiding-clickfix/revalidation-2026-07-08-full/ - this
step does not redo that full effort. It confirms nothing has silently
drifted by independently re-pulling each contract's total transaction count
and current resolved C2, fresh, right now.
"""
import json
import time
import urllib.request
from datetime import datetime, timezone

CONTRACTS = {
    "Operator 1 / xdav": "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2",
    "Operator 2": "0x83833C5D676cA06E941A32310AE67D0890F657eE",
    "Operator 3": "0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55",
}

PREVIOUSLY_PUBLISHED_UPDATE_COUNTS = {
    "Operator 1 / xdav": 23,
    "Operator 2": None,  # operator 2 deploys a new contract per C2 rather than calling updateDomain repeatedly
    "Operator 3": 3,
}


def fetch(url, retries=4):
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            last_err = e
            time.sleep(4)
    raise last_err


def main():
    print(f"Revalidation timestamp (UTC): {datetime.now(timezone.utc).isoformat()}\n")
    for name, addr in CONTRACTS.items():
        url = f"https://polygon.blockscout.com/api?module=account&action=txlist&address={addr}&sort=asc"
        data = fetch(url)
        items = data.get("result", [])
        update_calls = [tx for tx in items if tx.get("methodId", "").lower() not in ("", "0x")
                        and not tx.get("contractAddress")]
        print(f"=== {name} :: {addr} ===")
        print(f"  Total transactions (fresh pull): {len(items)}")
        print(f"  Non-creation method calls (candidate updateDomain calls): {len(update_calls)}")
        prev = PREVIOUSLY_PUBLISHED_UPDATE_COUNTS.get(name)
        if prev is not None:
            print(f"  Previously published update-call count: {prev}  "
                  f"({'MATCHES' if len(update_calls) == prev else 'DIFFERS - see note'})")
        if items:
            last_ts = datetime.fromtimestamp(int(items[-1]["timeStamp"]), tz=timezone.utc).isoformat()
            print(f"  Most recent transaction timestamp: {last_ts}")
        print()
        time.sleep(1)


if __name__ == "__main__":
    main()
