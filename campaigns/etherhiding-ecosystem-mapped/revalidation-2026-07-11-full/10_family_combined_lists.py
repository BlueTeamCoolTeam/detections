#!/usr/bin/env python3
"""
Writes out the combined, deduplicated Family A and Family B lists that
were previously only computed in-memory by 09_final_cross_family_dedup_with_mamkor_partD.py
and printed as summary counts, not saved as reviewable files.

Produces four new files:
  - family_a_confirmed_FINAL.txt   (348 hosts - same union 09 reported)
  - family_b_confirmed_FINAL.txt   (1500 hosts - same union 09 reported)
  - family_a_candidates_FINAL.txt  (union of every Family A operator's candidate pool)
  - family_b_candidates_FINAL.txt  (mamkor's 4,993-host candidate pool - already one
                                     clean file; copied here under a consistent name)

Every number printed at the end must match 09's own console output exactly -
this script re-derives from the same source files, it does not recompute
anything differently.
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


# --- Candidate-pool extraction (messier source formats, log-style files) ---

DOMAIN_LINE = re.compile(r"^\s*([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})\s*$")


def extract_trailing_host_list(filename, stop_markers=()):
    """
    op1's and op2op3's candidate-pool recheck outputs are console-style logs
    with a per-domain breakdown followed by a flat list of candidate
    hostnames (op1: one list at the end; op2op3: two separate lists, one
    per operator, each preceded by a 'Candidate pool members (Operator N):'
    header). This walks every line, keeps only lines that are bare,
    domain-shaped hostnames, and skips known non-host lines (headers,
    counts, 'domain:x -> N values' summary lines).
    """
    path = HERE / filename
    hosts = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or "->" in stripped or ":" in stripped and not DOMAIN_LINE.match(stripped):
            continue
        m = DOMAIN_LINE.match(stripped)
        if m:
            hosts.add(m.group(1).lower())
    return hosts


def main():
    # --- Confirmed sites ---
    op1 = load_plain_list("op1_B_final_confirmed_union.txt")
    op2 = load_plain_list("op2op3_B_final_confirmed_union_op2.txt")
    op3 = load_plain_list("op2op3_B_final_confirmed_union_op3.txt")
    bwsibling_reconfirmed = load_bwsibling_reconfirmed()
    bwsibling_new, cross_attributed = load_bwsibling_new()
    mamkor_b = load_plain_list("mamkor_B_final_confirmed_union.txt")
    mamkor_d = load_plain_list("mamkor_D_new_confirmed_hosts.txt")

    op1_plus = op1 | cross_attributed["op1"]
    op2_plus = op2 | cross_attributed["op2"]
    op3_plus = op3 | cross_attributed["op3"]

    family_a_confirmed = op1_plus | op2_plus | op3_plus | bwsibling_reconfirmed | bwsibling_new
    family_b_confirmed = mamkor_b | mamkor_d

    # Data-hygiene pass: a bare IP and its AWS EC2 reverse-DNS hostname for
    # the SAME host both slipped into mamkor's Part D confirmed list as if
    # they were two different sites. Found by inspection while building
    # this combined file - not caught by the original per-pass checker,
    # since it only dedupes by exact string match, not by IP-vs-hostname
    # identity. Confirmed via reverse-DNS pattern match (ec2-A-B-C-D.*
    # decodes to IP A.B.C.D), not just a naming coincidence.
    ec2_pattern = re.compile(r"^ec2-(\d+)-(\d+)-(\d+)-(\d+)\.")
    ip_to_hostname = {}
    for h in family_b_confirmed:
        m = ec2_pattern.match(h)
        if m:
            ip_to_hostname[".".join(m.groups())] = h
    duplicate_ips = set(family_b_confirmed) & set(ip_to_hostname.keys())
    if duplicate_ips:
        print(f"Data-hygiene fix: removing {len(duplicate_ips)} bare-IP entr{'y' if len(duplicate_ips)==1 else 'ies'} "
              f"that duplicate an EC2 reverse-DNS hostname already in the list:")
        for ip in sorted(duplicate_ips):
            print(f"  removing '{ip}' (same host as '{ip_to_hostname[ip]}', kept)")
        family_b_confirmed -= duplicate_ips

    (HERE / "family_a_confirmed_FINAL.txt").write_text(
        "\n".join(sorted(family_a_confirmed)) + "\n", encoding="utf-8")
    (HERE / "family_b_confirmed_FINAL.txt").write_text(
        "\n".join(sorted(family_b_confirmed)) + "\n", encoding="utf-8")

    print("\n=== CONFIRMED COMPROMISED SITES ===")
    print(f"family_a_confirmed_FINAL.txt: {len(family_a_confirmed)} unique hosts")
    print(f"family_b_confirmed_FINAL.txt: {len(family_b_confirmed)} unique hosts "
          f"({len(mamkor_b | mamkor_d)} before the IP/hostname dedup above)")
    cross = family_a_confirmed & family_b_confirmed
    print(f"Cross-family overlap: {len(cross)}")
    print(f"Grand total union: {len(family_a_confirmed | family_b_confirmed)}")
    print("\nRemaining bare-IP entries left in family_b_confirmed_FINAL.txt "
          "(no matching hostname alias found in the same list, so not removed - "
          "kept as-is, genuinely IP-identified confirmed hosts):")
    remaining_ips = [h for h in family_b_confirmed if re.match(r"^\d+\.\d+\.\d+\.\d+$", h)]
    for ip in sorted(remaining_ips):
        print(f"  {ip}")

    # --- Candidate pools ---
    op1_candidates = extract_trailing_host_list("op1_A_candidate_pool_recheck_OUTPUT.txt")
    op2op3_candidates = extract_trailing_host_list("op2op3_A_candidate_pool_recheck_OUTPUT.txt")
    bwsibling_candidates = load_plain_list("bwsibling_A_candidate_hosts.txt")
    mamkor_candidates = load_plain_list("mamkor_A_candidate_hosts.txt")

    family_a_candidates = op1_candidates | op2op3_candidates | bwsibling_candidates
    family_b_candidates = mamkor_candidates

    (HERE / "family_a_candidates_FINAL.txt").write_text(
        "\n".join(sorted(family_a_candidates)) + "\n", encoding="utf-8")
    (HERE / "family_b_candidates_FINAL.txt").write_text(
        "\n".join(sorted(family_b_candidates)) + "\n", encoding="utf-8")

    print("\n=== CANDIDATE POOLS ===")
    print(f"  op1 candidates extracted: {len(op1_candidates)} (expected ~925)")
    print(f"  op2+op3 candidates extracted: {len(op2op3_candidates)} (expected ~167+9=176)")
    print(f"  bwsibling candidates: {len(bwsibling_candidates)} (expected 1265)")
    print(f"family_a_candidates_FINAL.txt: {len(family_a_candidates)} unique hosts (union of the three above)")
    print(f"family_b_candidates_FINAL.txt: {len(family_b_candidates)} unique hosts (expected 4993)")


if __name__ == "__main__":
    main()
