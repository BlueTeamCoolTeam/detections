#!/usr/bin/env python3
"""
Final synthesis: re-runs the cross-family dedup/union check (the same
methodology as reproduction-log/02_cross_family_dedup_check.py) against the
FRESHLY reconfirmed site lists produced by the 4 parallel revalidation
agents in this folder, not the original (2026-07-08 / 2026-07-11-morning)
lists.

Inputs:
  - op1_B_final_confirmed_union.txt          (Operator 1/xdav, 3-pass reconfirmed against original 123)
  - op2op3_B_final_confirmed_union_op2.txt   (Operator 2, 3-pass reconfirmed against original 27)
  - op2op3_B_final_confirmed_union_op3.txt   (Operator 3, 3-pass reconfirmed against original 3)
  - bwsibling_B_final_confirmed_union.txt    (BW-sibling, 3-pass reconfirmed against original 111 -
                                               has a 12-line text header before the hostname list)
  - bwsibling_C_new_candidates_confirm_results.txt (BW-sibling, additive: NEW sites found via the
                                               freshly-rebuilt 1265-host candidate pool, not in the
                                               original 111 - only rows with verdict=confirmed AND
                                               sibling=None count as this operator's own)
  - mamkor_B_final_confirmed_union.txt       (mamkor/merabs, 3-pass reconfirmed against original 638)

mamkor's own candidate-pool rediscovery (Part A) did not complete this
session - it hit the urlscan.io account's hard daily search-API quota
(1000/day) partway through, after BW-sibling's candidate-pool rebuild and
the smaller operators' rechecks had already spent most of it. This does not
affect the numbers below - mamkor's CONFIRMED-site reconfirmation (Part B,
the actual claim being revalidated) completed fully and is included in full.
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
    """
    Returns (bwsibling_own_hosts, cross_attributed_hosts_by_operator).
    'sibling' rows are genuine NEW confirmed-compromised sites too - they
    just belong to a DIFFERENT Family A operator, discovered as a byproduct
    of BW-sibling's much larger freshly-rebuilt candidate pool. These are
    real confirmed sites and must be counted in the Family A union (tagged
    by which operator they actually belong to), not silently dropped.
    """
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
    mamkor = load_plain_list("mamkor_B_final_confirmed_union.txt")

    # Cross-attributed hosts are genuine confirmed sites found via BW-sibling's
    # candidate pool but belonging to a different Family A operator - fold them
    # into that operator's set (deduped automatically if already present).
    op1_plus = op1 | cross_attributed["op1"]
    op2_plus = op2 | cross_attributed["op2"]
    op3_plus = op3 | cross_attributed["op3"]

    print("=== Per-list counts (fresh, 2026-07-11 revalidation) ===")
    print(f"  Operator 1/xdav (3-pass reconfirmed, of original 123): {len(op1)}"
          f"  [+{len(cross_attributed['op1'])} newly found via BW-sibling's pivot -> {len(op1_plus)}]")
    print(f"  Operator 2 (3-pass reconfirmed, of original 27):       {len(op2)}"
          f"  [+{len(cross_attributed['op2'])} newly found via BW-sibling's pivot -> {len(op2_plus)}]")
    print(f"  Operator 3 (3-pass reconfirmed, of original 3):        {len(op3)}"
          f"  [+{len(cross_attributed['op3'])} newly found via BW-sibling's pivot -> {len(op3_plus)}]")
    print(f"  BW-sibling (3-pass reconfirmed, of original 111):      {len(bwsibling_reconfirmed)}")
    print(f"  BW-sibling (NEW, own contract, from freshly rebuilt candidate pool): {len(bwsibling_new)}")
    print(f"  mamkor/merabs (3-pass reconfirmed, of original 638):    {len(mamkor)}")
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
    print(f"Family B union (mamkor/merabs, freshly reconfirmed): {len(family_b_union)}")

    cross = family_a_union & family_b_union
    print(f"\n=== Cross-family overlap (Family A vs Family B), re-checked fresh ===")
    print(f"  Shared victims: {len(cross)}")
    for host in sorted(cross):
        print(f"    {host}")

    grand_union = family_a_union | family_b_union
    print(f"\n=== Grand total (fresh revalidation, 2026-07-11) ===")
    print(f"  Family A + Family B raw sum: {len(family_a_union) + len(family_b_union)}")
    print(f"  Cross-family duplicates removed: {len(cross)}")
    print(f"  GRAND TOTAL UNIQUE CONFIRMED COMPROMISED SITES (fresh, this revalidation): {len(grand_union)}")

    print(f"\n=== Comparison against the combined post's original claim ===")
    print(f"  Original post claim (pre-revalidation): 901 unique confirmed sites.")
    print(f"  Fresh revalidation result: {len(grand_union)} unique confirmed sites.")
    print(f"  Note: these numbers are NOT directly comparable apples-to-apples - the original 901 came "
          f"from the FULL original lists (123+27+3+111+638) at their original capture times; this fresh "
          f"number reflects (a) which of those original sites STILL show live injection today "
          f"(churn/remediation reduces this), offset by (b) newly discovered BW-sibling sites from a "
          f"freshly rebuilt, much larger candidate pool (which increases this). Both effects are real "
          f"and expected for an active campaign - see 00_REVALIDATION_LOG.md for the full breakdown.")


if __name__ == "__main__":
    main()
