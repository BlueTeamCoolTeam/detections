#!/usr/bin/env python3
"""Part C step 1 -- compute the set of Part-A candidate hostnames that are
NOT already in the existing 111-site confirmed list. Writes
bwsibling_C_new_candidates_hosts.txt (input to the Part C confirm run)."""
import sys

CANDIDATES_FILE = "bwsibling_A_candidate_hosts.txt"
EXISTING_FILE = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\reproduction-log\family_a_bwsibling_confirmed.txt"
OUT_FILE = "bwsibling_C_new_candidates_hosts.txt"


def main():
    with open(CANDIDATES_FILE, "r", encoding="utf-8") as f:
        candidates = set(line.strip().lower() for line in f if line.strip())
    with open(EXISTING_FILE, "r", encoding="utf-8") as f:
        existing = set(line.strip().lower() for line in f if line.strip())

    new = sorted(candidates - existing)

    print(f"Part-A candidate pool size: {len(candidates)}")
    print(f"Existing 111-site confirmed list size: {len(existing)}")
    print(f"Overlap (candidates already in the 111 list): {len(candidates & existing)}")
    print(f"NEW candidates (in Part A pool, not in the 111 list): {len(new)}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for h in new:
            f.write(h + "\n")
    print(f"Wrote {OUT_FILE}")


if __name__ == "__main__":
    main()
