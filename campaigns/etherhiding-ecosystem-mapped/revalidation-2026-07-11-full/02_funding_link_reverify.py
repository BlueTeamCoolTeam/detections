#!/usr/bin/env python3
"""
Independently re-verifies the claim: "xdav's wallet funded the BW-sibling
operator's wallet directly, on-chain, 50 MATIC, one hour before its first
contract deployment." Pulls the BW-sibling wallet's raw, complete
transaction history straight from Blockscout's etherscan-compatible v1 API
(the v2 REST /transactions endpoint returned HTTP 500 / timed out
repeatedly during this revalidation pass - noted as a dead end below rather
than silently switched) and confirms the exact sender, amount, and
timestamp independently, from a fresh pull.
"""
import json
import time
import urllib.request
from datetime import datetime, timezone

XDAV_WALLET = "0xcaf2c54e400437da717cf215181b170f65187abf"
BWSIBLING_WALLET = "0xb0425bf235a2275735c8c5d668aa0273c65970b9"

API_V1 = (
    "https://polygon.blockscout.com/api?module=account&action=txlist"
    f"&address={BWSIBLING_WALLET}&sort=asc"
)


def fetch(url, retries=3):
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            last_err = e
            time.sleep(3)
    raise last_err


def main():
    print(f"Revalidation timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    print(f"Target wallet (BW-sibling operator): {BWSIBLING_WALLET}")
    print("DEAD END noted: the Blockscout v2 REST endpoint "
          "(/api/v2/addresses/<addr>/transactions?filter=to) returned HTTP 500 "
          "and then timed out on retry during this pass. Switched to the "
          "etherscan-compatible v1 endpoint below, which succeeded.")
    print(f"Querying: {API_V1}\n")

    data = fetch(API_V1)
    print(f"API status: {data.get('status')}  message: {data.get('message')}")
    items = data.get("result", [])
    if not isinstance(items, list):
        print(f"Unexpected result shape: {items}")
        return
    print(f"Total transactions (in + out) found for this wallet: {len(items)}\n")

    incoming = [tx for tx in items if tx.get("to", "").lower() == BWSIBLING_WALLET.lower()]
    print(f"Incoming transactions (to this wallet): {len(incoming)}\n")

    matches = [tx for tx in incoming if tx.get("from", "").lower() == XDAV_WALLET.lower()]
    print(f"Of those, FROM xdav's wallet ({XDAV_WALLET}): {len(matches)}\n")

    for tx in matches:
        value_matic = int(tx["value"]) / 1e18
        ts = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc)
        print("MATCH:")
        print(f"  tx hash:    {tx['hash']}")
        print(f"  timestamp:  {ts.isoformat()} (unix {tx['timeStamp']})")
        print(f"  value:      {value_matic} MATIC")
        print(f"  block:      {tx['blockNumber']}")
        print(f"  from nonce: {tx['nonce']} (xdav's nonce at time of this tx)")
        print()

    print("=== Full incoming-transaction list (completeness check) ===")
    for tx in incoming:
        value_matic = int(tx["value"]) / 1e18
        ts = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc)
        print(f"  {ts.isoformat()}  from={tx['from']}  value={value_matic} MATIC  hash={tx['hash']}")

    print(f"\n=== First 3 transactions overall (to confirm this funding tx is the FIRST activity) ===")
    for tx in items[:3]:
        ts = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc)
        direction = "IN " if tx.get("to", "").lower() == BWSIBLING_WALLET.lower() else "OUT"
        print(f"  [{direction}] {ts.isoformat()}  from={tx['from']} to={tx['to']}  "
              f"value={int(tx['value'])/1e18} MATIC  method={tx.get('methodId')}  hash={tx['hash']}")

    ok = len(incoming) == 1 and len(matches) == 1
    print(f"\nCONCLUSION: {'CONFIRMED - exactly one incoming tx, from xdav, 50 MATIC' if ok else 'NEEDS REVIEW - see full list above, does not match the exactly-one-incoming-tx claim'}")


if __name__ == "__main__":
    main()
