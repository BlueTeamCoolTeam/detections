# Operator 2 / Operator 3 revalidation summary - 2026-07-11

Scope: light candidate-pool consistency check (Part A) plus a full 3-pass
live re-confirmation (Part B) of the EtherHiding ClickFix post's Operator 2
and Operator 3 confirmed-compromise lists. All numbers below are read directly
from the output files in this directory - none are estimated.

## Part A - candidate pool consistency recheck

Method: urlscan.io Search API, `q=domain:<domain>&size=100`, paginated via the
`search_after` cursor (NOT the `has_more` flag, which is unreliable on this
account tier - pagination continued until a page returned fewer than 100
results). Candidate pool = union of distinct `page.domain` values across an
operator's own C2 domains, minus those C2 domains themselves.

Script: `op2op3_A_candidate_pool_recheck.py`
Full output: `op2op3_A_candidate_pool_recheck_OUTPUT.txt`

| Operator | Domains queried | Per-domain hit counts | Union (page.domain) | Candidate pool (own domains excluded) | Previously published |
|---|---|---|---|---|---|
| Operator 2 | iwannagetmoremoney[.]beer, hahletsgoagain[.]beer, letsgomakemoneyoncaptcha[.]beer | 65 / 32 / 80 | 170 | **167** | 150 |
| Operator 3 | hilacbatoriaaa[.]cc, pluhabovra[.]info, huishuvish[.]cc, errrkotmlkpoy[.]xyz | 8 / 2 / 2 / 0 | 12 | **9** | 4 |

Both counts differ from the previously published figures. Per the task's
expectations this is fine - candidate pools drift over time as urlscan's
index gains/loses scans and as sites get re-crawled - and the true, freshly
observed number is reported above rather than reconciled to the old one.

Observation worth flagging: none of Operator 3's 9 freshly observed candidate
domains overlap with the *existing* Operator 3 confirmed list re-verified in
Part B below (`greencoalition.pl`, `www.motorbeam.com`,
`www.realoptionsvaluation.com`). This is expected given Operator 3's own
footprint "was never fully mapped" per the task background, and it does not
call the Part B confirmations into question - it just means urlscan's index
for Operator 3's 4 C2 domains does not currently surface the same hosts that
were confirmed by live kit-fingerprint detection.

## Part B - 3-pass live re-confirmation of existing confirmed lists

Method: reused, without changing detection semantics, the decode/detection
logic from the already-proven checker at
`detections/campaigns/authorization-cdn-etherhiding-clickfix/revalidation-2026-07-08-full/03_live_verification_checker.py`
(https-then-http fetch with a realistic browser UA; cleartext
`api.php?s=...`+polygon/1rpc.io/matic check; brute-force every `atob(...)`
blob against all 256 single-byte XOR keys; a hit requires the run-once guard
`window['_<hex>']` plus 2+ of {polygon, eth_call, api.php} among the decoded
text). Combined script: `op2op3_B_live_verification_checker.py`. Fetches both
operators' existing confirmed-host lists (27 + 3 = 30 hosts) in a single run,
tags each row OP2/OP3, and was executed three independent times.

| Pass | OP2 CONFIRMED | OP2 CLEAN | OP2 UNREACHABLE | OP3 CONFIRMED | OP3 CLEAN | OP3 UNREACHABLE |
|---|---|---|---|---|---|---|
| 1 | 23 | 2 | 2 | 2 | 1 | 0 |
| 2 | 23 | 2 | 2 | 2 | 1 | 0 |
| 3 | 24 | 2 | 1 | 2 | 1 | 0 |

Full labeled per-pass results: `op2op3_B_pass1_results.txt`,
`op2op3_B_pass2_results.txt`, `op2op3_B_pass3_results.txt`. Console logs:
`op2op3_B_pass1_console_OUTPUT.txt`, `op2op3_B_pass2_console_OUTPUT.txt`,
`op2op3_B_pass3_console_OUTPUT.txt`.

### Per-host detail across the 3 passes

**Operator 2 (27 hosts in the existing list):**
- 23 hosts CONFIRMED (kit fingerprint matched) in all 3 passes, consistently
  decoding to Operator 2's contract `0x83833C5D676cA06E941A32310AE67D0890F657eE`.
- `youmeandtrends.com` - UNREACHABLE in pass 1 and pass 2, CONFIRMED in pass 3
  (xor=73, same Operator-2 contract). Treated as CONFIRMED in the union
  (transient network/host availability, not a detection failure - the kit
  fingerprint matched cleanly once the host responded).
- `heeleuropa.com` - UNREACHABLE in all 3 passes. Not counted as confirmed;
  the site could not be reached on any attempt (https or http) across three
  independent runs.
- `tinkers.co.za` and `www.mjblawchicago.com` - CLEAN in all 3 passes (site
  reachable, no kit fingerprint found). Not counted as confirmed.

**Operator 3 (3 hosts in the existing list):**
- `greencoalition.pl` - CONFIRMED in all 3 passes, but decodes to
  **`0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2`, which is Operator 1's
  contract**, not Operator 3's current contract
  (`0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55`) or any of Operator 2's
  contracts. This is a genuine anomaly worth flagging for follow-up: the site
  is confirmed running the shared EtherHiding kit (guard variable present,
  2+ of polygon/eth_call/api.php matched) but the specific decoded contract
  ties it to Operator 1, not Operator 3. Possible explanations (not resolved
  by this task's scope, which only re-runs the kit-fingerprint decode/detect
  logic, not contract-to-operator attribution): the site could be
  double-compromised by both operators, or the original list-building step
  matched on kit-family presence rather than exact contract identity. This
  is reported as-is per the "no fabrication, no smoothing over" integrity
  rule - it is CONFIRMED as running the kit, with a contract-identity caveat.
- `www.realoptionsvaluation.com` - CONFIRMED in all 3 passes, decodes to
  Operator 3's own contract `0x0C7Cb01C83203aC0a50Abc3a9AFF3c9Ca727eF55`
  (xor=59). Clean confirmation, no caveats.
- `www.motorbeam.com` - CLEAN in all 3 passes. Not counted as confirmed.

## Final 3-pass union (a host counts if CONFIRMED in at least one of the 3 passes)

| Operator | Existing list size | Final union confirmed | Not confirmed (breakdown) | Previously published |
|---|---|---|---|---|
| Operator 2 | 27 | **24** | 2 CLEAN (`tinkers.co.za`, `www.mjblawchicago.com`), 1 persistently UNREACHABLE (`heeleuropa.com`) | 27 |
| Operator 3 | 3 | **2** | 1 CLEAN (`www.motorbeam.com`) | 3 |

Final union files:
- `op2op3_B_final_confirmed_union_op2.txt` (24 hosts)
- `op2op3_B_final_confirmed_union_op3.txt` (2 hosts: `greencoalition.pl`,
  `www.realoptionsvaluation.com` - see the contract-identity caveat on
  `greencoalition.pl` above)

## Bottom line

- Operator 2: 24 of the previously published 27 confirmed hosts re-confirmed
  live via 3 independent passes (89%). The 3 non-confirmations are one
  persistently-unreachable host and two hosts that are reachable but no
  longer (or never did, on this decode logic) serve the kit fingerprint -
  consistent with normal compromised-site cleanup/rotation over time, not a
  detection-logic failure (23 of 27 matched identically and immediately on
  every single pass).
- Operator 3: 2 of the previously published 3 confirmed hosts re-confirmed
  live via 3 independent passes (67%). `www.motorbeam.com` is clean on this
  decode logic across all 3 passes. `greencoalition.pl` re-confirms the kit
  fingerprint on all 3 passes but with a contract-identity anomaly (see
  above) that should be reconciled before the next publish cycle.
- Candidate pool sizes (Part A) are provided as freshly measured numbers per
  the task's instructions and are expected to differ from the previously
  published 150 (Operator 2) / 4 (Operator 3): true current values are
  **167** (Operator 2) and **9** (Operator 3).

## Files in this directory

- `op2op3_A_candidate_pool_recheck.py` / `op2op3_A_candidate_pool_recheck_OUTPUT.txt`
- `op2op3_B_live_verification_checker.py`
- `op2op3_B_pass1_results.txt`, `op2op3_B_pass2_results.txt`, `op2op3_B_pass3_results.txt`
- `op2op3_B_pass1_console_OUTPUT.txt`, `op2op3_B_pass2_console_OUTPUT.txt`, `op2op3_B_pass3_console_OUTPUT.txt`
- `op2op3_B_pass{1,2,3}_confirmed_op2.txt`, `op2op3_B_pass{1,2,3}_confirmed_op3.txt` (per-pass CONFIRMED lists, written by the checker script alongside the labeled results file)
- `op2op3_B_final_confirmed_union_op2.txt`, `op2op3_B_final_confirmed_union_op3.txt`
- `op2op3_SUMMARY.md` (this file)
