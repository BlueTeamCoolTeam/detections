# BW-sibling operator -- full revalidation summary (2026-07-11)

Operator: Family A "BW panel" kit (selector `0xb68d1809`), BW-sibling instance
(seed contract `0x926d6454...`, deployer wallet `0xb0425bf2...`), 87 contract
addresses / 90 C2 domains per
`family_a_bwsibling_all_contracts.txt` / `family_a_bwsibling_all_c2_domains.txt`.

Every number below is read directly from an output file in this directory --
no estimating, no rounding.

## Part A -- candidate pool re-derivation

Script: `bwsibling_A_candidate_pool_pivot.py` -> `bwsibling_A_candidate_pool_pivot_OUTPUT.txt`,
`bwsibling_A_candidate_hosts.txt`, `bwsibling_A_candidate_hosts_raw.json`

Ran a urlscan.io `domain:<c2>` search against all 90 known C2 domains, with
full `search_after` pagination (has_more not trusted -- kept paging any
domain that returned a full 100-result page).

- **Candidate pool size: 1265 unique hostnames** (deduped by `page.domain`
  across all 90 C2 domain searches, excluding the 90 C2 domains themselves).
- Of the 111 hostnames in the previously-published confirmed list, 106
  reappeared in this fresh pivot; 5 did not (see "Comparison" below -- this
  does not affect Part B, which checks the 111 directly regardless of
  whether they resurface in a fresh urlscan search).
- This differs substantially from the originally-reported ~285-candidate
  figure (39+4+68 confirmed + 20 sibling + 235 unconfirmed across 3 original
  batches). No attempt was made to force a match -- the true, independently
  re-derived number is 1265.

## Part B -- 3-pass live re-confirmation of the existing 111-site list

Script: `bwsibling_B_confirm_checker.py` (adapted from
`reproduction-log/06_bwsibling_confirmed_site_validator.py`; decode logic --
cleartext, atob+sub-then-XOR, plain single-byte XOR, 256-byte S-box, bare
`var k=N,d="..."` -- reused as-is). The one deliberate change: decoded
content is checked against **all 87** of this operator's contract-address
prefixes (first 8 hex chars after `0x`, verified collision-free against each
other and against the 3 known sibling-operator prefixes), not just the single
seed contract the original script's inline decode path used.

Outputs: `bwsibling_B_pass{1,2,3}_results.txt` (+ `.json`),
`bwsibling_B_pass{1,2,3}_console_OUTPUT.txt`, `bwsibling_B_final_confirmed_union.txt`
(via `bwsibling_B_compute_union.py`).

Each of the 3 independent passes fetched all 111 existing hosts fresh, live,
over separate runs:

| Pass | confirmed | clean | unconfirmed-suspicious | unreachable |
|------|-----------|-------|-------------------------|-------------|
| 1    | 56        | 45    | 7                       | 3           |
| 2    | 56        | 45    | 7                       | 3           |
| 3    | 56        | 45    | 7                       | 3           |

All 3 passes are byte-for-byte identical in verdict per host (0 disagreements
across the 3 runs -- see `bwsibling_B_final_confirmed_union.txt`).

- **3-pass union confirmed count (against the original 111): 56**
  (intersection == union == 56; every one of these 56 decoded live to one of
  this operator's 87 contract-address prefixes on all 3 passes).
- 45 no longer decode-confirm live (clean root page -- consistent with an
  active campaign where sites get cleaned/patched over time; this does NOT
  mean the original confirmation was wrong, only that the injection is no
  longer present today).
- 7 show only a cleartext reference to one of this operator's assigned C2
  domains (mostly `verification-cdn-cloud.beer`) with the domain itself now
  dead/unreachable, so no fresh contract/content could be independently
  recovered -- classified `unconfirmed-suspicious`, not confirmed, per the
  same conservative rule the original script used (domain co-occurrence
  alone is not proof).
- 3 hosts are genuinely unreachable (DNS resolution failure -- domains no
  longer resolve at all). Note: an SSL-fallback fix was added mid-run (see
  `bwsibling_B_confirm_checker.py`, `INSECURE_CTX`) after discovering that 4
  hosts with expired/self-signed TLS certs were being misclassified as
  unreachable by the default cert-verifying fetch -- all 3 passes reported
  here already include that fix (an initial pre-fix run was discarded and
  redone for consistency).

## Part C -- additive check: new Part-A candidates not in the existing 111

Script: `bwsibling_C_new_candidates_diff.py` (set difference) +
`bwsibling_B_confirm_checker.py` (same decode logic, single pass) ->
`bwsibling_C_new_candidates_hosts.txt`, `bwsibling_C_new_candidates_confirm_results.txt` (+ `.json`)

- Part-A candidate pool: 1265; overlap with existing 111: 106; **new
  candidates checked: 1159**.
- Verdict breakdown across all 1159: `{'clean': 861, 'confirmed': 167,
  'unreachable': 91, 'unconfirmed-suspicious': 29, 'sibling': 11}` (sums to
  1159).
- **New-candidate confirmed count (this operator, not previously in the
  111-site list): 167.**
- 11 of the new candidates decoded to a *different*, already-known Family A
  operator's contract (not this operator) -- correctly classified `sibling`,
  not `confirmed`:
  - 9 sites -> Operator 1 / xdav (`0xB6bC9e1D...`): betty-hensel.de,
    hoopsandhabits.com, kacmazbilisim.com, maisonmichelet.com,
    operaitaliana-sa.com, realtechengineeringltd.com, rnceducation.com,
    tvigroupe.com, vagandopormundopolis.com
  - 2 sites -> Operator 2 (`0x83833C5D...`): demarches.quebec,
    ssfeshipping.com

## Combined picture (informational, not asserted as a fixed count)

- 56 of the original 111 reconfirmed live, identically, across 3 independent
  passes.
- 167 additional sites, never in the original list, freshly confirmed
  compromised by this same operator.
- Combining the historical 111-site list (as previously published) with the
  167 newly-found confirmations gives 278 distinct hostnames ever confirmed
  compromised by this operator across the two capture sessions -- a floor,
  not a ceiling, on an active campaign, consistent with the framing already
  used in `README.md` for the rest of this pack.

## Comparison to the previously published 111

The previously published 111-site confirmed list is **not reproduced
unchanged** by a live re-check today:
- 56/111 (50%) reconfirm live via decode against the full 87-contract set.
- 45/111 no longer show the injection (site cleaned, or campaign rotated
  away from that host).
- 7/111 show only a now-dead C2 domain reference (can't independently
  confirm the contract anymore).
- 3/111 no longer resolve at all.

This is expected and reported as-is, not forced to match: EtherHiding
site-compromise campaigns rotate and get remediated continuously, and the
original 111 was itself a point-in-time capture. Separately, the fresh
candidate-pool pivot (Part A/C) found 167 previously-undocumented compromised
sites for this same operator -- the true confirmed-site count for this
operator, right now, is neither 111 nor a simple re-run of 111; it is 56
(reconfirmed) + 167 (newly found) = 223 sites independently reconfirmed live
in this revalidation pass, plus the 55 from the original list that are no
longer live-decodable but were not disproven.

## Files written (all in this directory)

- `bwsibling_A_candidate_pool_pivot.py`
- `bwsibling_A_candidate_pool_pivot_OUTPUT.txt`
- `bwsibling_A_candidate_hosts.txt` (1265 deduped candidate hostnames)
- `bwsibling_A_candidate_hosts_raw.json` (per-host urlscan page_url/result_uuid/c2 metadata)
- `bwsibling_A_run_console.log` (full console transcript of the Part A run)
- `bwsibling_B_confirm_checker.py`
- `bwsibling_B_pass1_results.txt` / `.json`
- `bwsibling_B_pass2_results.txt` / `.json`
- `bwsibling_B_pass3_results.txt` / `.json`
- `bwsibling_B_pass1_console_OUTPUT.txt`
- `bwsibling_B_pass2_console_OUTPUT.txt`
- `bwsibling_B_pass3_console_OUTPUT.txt`
- `bwsibling_B_compute_union.py`
- `bwsibling_B_final_confirmed_union.txt`
- `bwsibling_B_results_to_text.py` (JSON -> plain-text report helper, used for all pass/summary text outputs)
- `bwsibling_C_new_candidates_diff.py`
- `bwsibling_C_new_candidates_hosts.txt` (1159 new candidates)
- `bwsibling_C_console_OUTPUT.txt`
- `bwsibling_C_new_candidates_confirm_results.txt` / `.json`
- `bwsibling_SUMMARY.md` (this file)
