#!/usr/bin/env python3
"""
Supersedes 08_final_cross_family_dedup.py now that mamkor/merabs's Part A
candidate-pool rebuild has completed (with a second urlscan.io API key,
after the first one's daily quota ran out) and Part D (the additive confirm
check against the 4,355 newly-found candidates not in the original 638-site
list) is done. 08's numbers used only mamkor's Part B (629 sites, reconfirmed
from the original 638) - this version adds mamkor's Part D result (871 new
sites, confirmed independently, zero overlap with Part B by construction)
for a like-for-like comparison against Family A, which already had its own
"newly discovered via a rebuilt candidate pool" component (BW-sibling's 167)
folded in at the 08 stage.

Inputs: same as 08, except mamkor is now the union of:
  - mamkor_B_final_confirmed_union.txt      (629, 3-pass reconfirmed of the original 638)
  - mamkor_D_new_confirmed_hosts.txt        (871, single-pass confirmed, NEW candidates only)
"""
import re
from pathlib import Path

HERE = Path(__file__).parent


def norm(host):
    h = host.strip().lower()
    if not h:
        return None
    h = h.removeprefix("https://").removeprefix("http://")
    return h


def load_plain_list(filename):
    path = HERE / filename
    hosts = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        h = norm(line)
        if h:
            hosts.add(h)
    return hosts


def load_bwsibling_reconfirmed():
    path = HERE / "bwsibling_B_final_confirmed_union.txt"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    idx = next(i for i, l in enumerate(lines) if l.strip() == "Full union list (hosts CONFIRMED as this operator in at least 1 of 3 passes):")
    hosts = set()
    for line in lines[idx + 1:]:
        h = norm(line)
        if h:
            hosts.add(h)
    return hosts


def load_bwsibling_new():
    path = HERE / "bwsibling_C_new_candidates_confirm_results.txt"
    own_hosts = set()
    cross = {"op1": set(), "op2": set(), "op3": set(), "other": set()}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "\t" not in line or "verdict=" not in line:
            continue
        host = line.split("\t")[0].strip()
        m_verdict = re.search(r"verdict=(\S+)", line)
        m_sibling = re.search(r"sibling=(\[.*?\]|\S+)", line)
        verdict = m_verdict.group(1) if m_verdict else None
        sibling_raw = m_sibling.group(1) if m_sibling else "None"
        h = norm(host)
        if not h:
            continue
        if verdict == "confirmed" and sibling_raw == "None":
            own_hosts.add(h)
        elif verdict == "sibling":
            key = sibling_raw.lower()
            if "xdav" in key or "operator 1" in key:
                cross["op1"].add(h)
            elif "operator 2" in key:
                cross["op2"].add(h)
            elif "operator 3" in key:
                cross["op3"].add(h)
            else:
                cross["other"].add(h)
    return own_hosts, cross


def main():
    op1 = load_plain_list("op1_B_final_confirmed_union.txt")
    op2 = load_plain_list("op2op3_B_final_confirmed_union_op2.txt")
    op3 = load_plain_list("op2op3_B_final_confirmed_union_op3.txt")
    bwsibling_reconfirmed = load_bwsibling_reconfirmed()
    bwsibling_new, cross_attributed = load_bwsibling_new()
    mamkor_b = load_plain_list("mamkor_B_final_confirmed_union.txt")
    mamkor_d = load_plain_list("mamkor_D_new_confirmed_hosts.txt")

    overlap_bd = mamkor_b & mamkor_d
    mamkor = mamkor_b | mamkor_d

    op1_plus = op1 | cross_attributed["op1"]
    op2_plus = op2 | cross_attributed["op2"]
    op3_plus = op3 | cross_attributed["op3"]

    print("=== Per-list counts (fresh, 2026-07-11 revalidation, mamkor Part D included) ===")
    print(f"  Operator 1/xdav (3-pass reconfirmed, of original 123): {len(op1)}"
          f"  [+{len(cross_attributed['op1'])} newly found via BW-sibling's pivot -> {len(op1_plus)}]")
    print(f"  Operator 2 (3-pass reconfirmed, of original 27):       {len(op2)}"
          f"  [+{len(cross_attributed['op2'])} newly found via BW-sibling's pivot -> {len(op2_plus)}]")
    print(f"  Operator 3 (3-pass reconfirmed, of original 3):        {len(op3)}"
          f"  [+{len(cross_attributed['op3'])} newly found via BW-sibling's pivot -> {len(op3_plus)}]")
    print(f"  BW-sibling (3-pass reconfirmed, of original 111):      {len(bwsibling_reconfirmed)}")
    print(f"  BW-sibling (NEW, own contract, from freshly rebuilt candidate pool): {len(bwsibling_new)}")
    print(f"  mamkor/merabs Part B (3-pass reconfirmed, of original 638):  {len(mamkor_b)}")
    print(f"  mamkor/merabs Part D (NEW, single-pass confirmed from freshly rebuilt candidate pool): {len(mamkor_d)}")
    print(f"  mamkor/merabs Part B/D overlap check: {len(overlap_bd)} (expected 0, disjoint by construction)")
    print(f"  mamkor/merabs combined: {len(mamkor)}")
    if cross_attributed["other"]:
        print(f"  Unattributed 'sibling' hits (not matching any known operator label, "
              f"needs manual review): {len(cross_attributed['other'])} -> {sorted(cross_attributed['other'])}")

    family_a_lists = {
        "op1": op1_plus, "op2": op2_plus, "op3": op3_plus,
        "bwsibling_reconfirmed": bwsibling_reconfirmed,
        "bwsibling_new": bwsibling_new,
    }

    print("\n=== Family A internal overlap check (pairwise) ===")
    names = list(family_a_lists.keys())
    any_overlap = False
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            overlap = family_a_lists[a] & family_a_lists[b]
            if overlap:
                any_overlap = True
                print(f"  {a} vs {b}: {len(overlap)} -> {sorted(overlap)}")
            else:
                print(f"  {a} vs {b}: 0")
    if not any_overlap:
        print("  (no overlaps found among any pair)")

    family_a_union = set().union(*family_a_lists.values())
    family_b_union = mamkor

    print(f"\nFamily A union (all 4 operators, freshly reconfirmed + newly discovered): {len(family_a_union)}")
    print(f"Family B union (mamkor/merabs, Part B + Part D): {len(family_b_union)}")

    cross = family_a_union & family_b_union
    print(f"\n=== Cross-family overlap (Family A vs Family B), re-checked fresh with expanded mamkor list ===")
    print(f"  Shared victims: {len(cross)}")
    for host in sorted(cross):
        print(f"    {host}")

    grand_union = family_a_union | family_b_union
    print(f"\n=== Grand total (fresh revalidation, 2026-07-11, mamkor Part D included) ===")
    print(f"  Family A + Family B raw sum: {len(family_a_union) + len(family_b_union)}")
    print(f"  Cross-family duplicates removed: {len(cross)}")
    print(f"  GRAND TOTAL UNIQUE CONFIRMED COMPROMISED SITES: {len(grand_union)}")

    print(f"\n=== Progression across this revalidation session ===")
    print(f"  Original combined-post claim (pre-revalidation): 901")
    print(f"  After 08 (mamkor Part B only, Part A quota-blocked): 969")
    print(f"  After 09 (mamkor Part A/D completed with fresh key): {len(grand_union)}")
    print(f"  Note: the jump from 969 to {len(grand_union)} is almost entirely mamkor's Part D - "
          f"871 newly-confirmed sites from a candidate pool that could not be built until a second "
          f"API key was supplied. This is not re-litigating the same claim differently; it's the "
          f"same claim with a previously-missing piece of evidence now in hand.")


if __name__ == "__main__":
    main()
