#!/usr/bin/env python3
"""
Follow-up to 03_bwsibling_full_reenumeration.py: that script's independent
re-derivation found 96 decoded strings against a previously published claim
of 90 domains - MORE than claimed, not fewer. Manual inspection of the raw
output showed at least two contracts (0x8b7bcc472..., 0xffde7e80f...) whose
decoded values are NOT domain-shaped at all - one literally decodes to the
four-character placeholder string "test", others to long base64/hex-looking
blobs with an embedded ':' character, structurally similar to the
"abandoned test-deployment with placeholder data" pattern already documented
for a DIFFERENT operator (xdav/Operator 1) in the authorization-cdn
revalidation.

This script re-parses 03's raw output and classifies every one of the 96
decoded strings as domain-shaped or not, rather than eyeballing a handful.
Re-run of record; does not re-hit the network - operates on the already
independently-decoded data from step 03.
"""
import re

SRC = "03_bwsibling_full_reenumeration_OUTPUT.txt"

DOMAIN_RE = re.compile(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}(/.*)?$")


def classify(value):
    if DOMAIN_RE.match(value):
        return "domain-shaped"
    return "NOT domain-shaped"


def main():
    text = open(SRC, encoding="utf-8").read()
    creation_section = text.split("=== Full decoded creation-tx domain list ===")[1].split(
        "=== Full decoded setter-call domain list")[0]
    setter_section = text.split("=== Full decoded setter-call domain list")[1].split(
        "=== Comparison against")[0]

    creation_entries = [l.strip() for l in creation_section.splitlines() if "->" in l]
    setter_entries = [l.strip() for l in setter_section.splitlines() if "->" in l]

    print(f"Creation-tx decoded entries: {len(creation_entries)}")
    print(f"Setter-call decoded entries: {len(setter_entries)}\n")

    all_domains = set()
    not_domain_shaped = []

    for line in creation_entries:
        addr, val = [p.strip() for p in line.split("->", 1)]
        cls = classify(val)
        if cls == "domain-shaped":
            all_domains.add(val)
        else:
            not_domain_shaped.append(("creation", addr, val))

    for line in setter_entries:
        left, val = [p.strip() for p in line.split("->", 1)]
        addr = left.split("@")[0].strip()
        cls = classify(val)
        if cls == "domain-shaped":
            all_domains.add(val)
        else:
            not_domain_shaped.append(("setter", addr, val))

    print(f"Unique domain-shaped values across creation+setter: {len(all_domains)}")
    print(f"NOT domain-shaped (test/placeholder/garbage) entries: {len(not_domain_shaped)}\n")

    print("=== NOT domain-shaped entries (manual review) ===")
    for kind, addr, val in not_domain_shaped:
        print(f"  [{kind}] {addr}  ->  {val[:80]}{'...' if len(val) > 80 else ''}")

    affected_contracts = sorted(set(addr for _, addr, _ in not_domain_shaped))
    print(f"\nContracts touched by at least one non-domain-shaped value: "
          f"{len(affected_contracts)}")
    for a in affected_contracts:
        print(f"  {a}")

    print(f"\n=== Corrected comparison ===")
    print(f"Previously claimed: 90 domains.")
    print(f"Independently re-derived, ALL decoded strings: 96.")
    print(f"Independently re-derived, domain-SHAPED only: {len(all_domains)}.")
    print(f"Non-domain-shaped (test/placeholder) entries excluded: {len(not_domain_shaped)}, "
          f"across {len(affected_contracts)} contract address(es).")


if __name__ == "__main__":
    main()
