#!/usr/bin/env python3
"""
Formalizes an ad-hoc check run during review of the combined post: does the
"901 unique confirmed compromised sites across 5 operator instances" headline
number actually hold up, or does it double-count any site?

Inputs are the five confirmed-compromised-site lists as published/produced:
  - family_a_operator1_xdav_confirmed.txt   (123 lines - authorization-cdn post, op1)
  - family_a_operator2_confirmed.txt        (27 lines  - authorization-cdn post, op2)
  - family_a_operator3_confirmed.txt        (3 lines   - authorization-cdn post, op3)
  - family_a_bwsibling_confirmed.txt        (111 lines - new investigation)
  - family_b_mamkor_confirmed.txt           (638 lines - new investigation)

Note: a naive `wc -l` on these files undercounts by 1 where the last line has
no trailing newline (true for several of them) - this script counts logical
entries after stripping, not raw newlines, to avoid that off-by-one.

Normalization: lowercase, strip protocol prefix, strip whitespace/CR, drop
blank lines. No other transformation - deliberately NOT stripping "www."
since that is itself a distinct hostname that could resolve to a different
vhost, and collapsing it would risk hiding a real second entry.
"""
from pathlib import Path

HERE = Path(__file__).parent

FILES = {
    "op1_xdav": "family_a_operator1_xdav_confirmed.txt",
    "op2": "family_a_operator2_confirmed.txt",
    "op3": "family_a_operator3_confirmed.txt",
    "bwsibling": "family_a_bwsibling_confirmed.txt",
    "mamkor": "family_b_mamkor_confirmed.txt",
}

FAMILY_A = ["op1_xdav", "op2", "op3", "bwsibling"]
FAMILY_B = ["mamkor"]


def load(name):
    path = HERE / FILES[name]
    hosts = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        h = line.strip().lower()
        if not h:
            continue
        h = h.removeprefix("https://").removeprefix("http://")
        hosts.add(h)
    return hosts


def main():
    sets = {name: load(name) for name in FILES}

    print("=== Per-list counts (logical entries, not raw wc -l) ===")
    for name, hosts in sets.items():
        print(f"  {name}: {len(hosts)}")

    print("\n=== Family A internal overlap check (should be zero - each is a distinct operator wallet) ===")
    for i, a in enumerate(FAMILY_A):
        for b in FAMILY_A[i + 1:]:
            overlap = sets[a] & sets[b]
            print(f"  {a} vs {b}: {len(overlap)}" + (f"  -> {sorted(overlap)}" if overlap else ""))

    family_a_union = set().union(*(sets[n] for n in FAMILY_A))
    family_b_union = set().union(*(sets[n] for n in FAMILY_B))
    print(f"\nFamily A union (b68d1809 'BW panel' kit, 4 operators): {len(family_a_union)}")
    print(f"Family B union (38bcdc1c mamkor/merabs kit, 1 operator): {len(family_b_union)}")

    print("\n=== Cross-family overlap (Family A vs Family B) ===")
    cross = family_a_union & family_b_union
    print(f"  Shared victims: {len(cross)}")
    for host in sorted(cross):
        owners = [n for n, s in sets.items() if host in s]
        print(f"    {host}  ->  confirmed in: {owners}")

    grand_union = family_a_union | family_b_union
    print(f"\n=== Grand total ===")
    print(f"  Family A + Family B raw sum: {len(family_a_union) + len(family_b_union)}")
    print(f"  Cross-family duplicates removed: {len(cross)}")
    print(f"  GRAND TOTAL UNIQUE CONFIRMED COMPROMISED SITES: {len(grand_union)}")


if __name__ == "__main__":
    main()
