# Operator 1 ("xdav" / authorization-cdn) - revalidation summary
2026-07-11

## Part A - candidate pool consistency check

Re-ran a `domain:` search (urlscan.io Search API) for each of the operator's
18 historical C2 domains, with corrected pagination (search_after loop,
ignoring the unreliable `has_more` field - kept paging as long as a full
100-result page came back). Deduplicated by `page.domain`, excluded the 18
C2 domains themselves.

**Candidate pool: 925 unique domains** (see `op1_A_candidate_pool_recheck_OUTPUT.txt`
for the full list and per-domain raw/unique counts).

Previously published figure (2026-07-08 post): 851.

This is a difference of +74 (925 vs 851), which is expected and not an error:
this is a live, actively-rotating campaign, urlscan's index keeps growing
between snapshots, and some previously-indexed sites may have also dropped
out while new scans were added. The first run of this recheck hit a
transient `HTTP 503` on the `ethercdnns.beer` search (see below); the script
was fixed to retry on 5xx (not just 429) and re-run cleanly for all 18
domains before this number was finalized.

Per-domain raw scan-result / unique-domain counts are in
`op1_A_candidate_pool_recheck_OUTPUT.txt`.

## Part B - 3-pass live re-confirmation of the 123-site confirmed list

Adapted the proven decode/detection logic from
`authorization-cdn-etherhiding-clickfix/revalidation-2026-07-08-full/03_live_verification_checker.py`
(brute-force every `atob()` blob against all 256 single-byte XOR keys, check
decoded content for the run-once guard `window['_<hex>']` plus 2+ hits among
polygon/eth_call/api.php, or a cleartext `api.php?s=...` gate) into
`op1_B_live_verification_checker.py`, and ran it three independent times
against the same 123-hostname list
(`reproduction-log/family_a_operator1_xdav_confirmed.txt`).

| Pass | CONFIRMED | CLEAN | UNREACHABLE | Total |
|------|-----------|-------|-------------|-------|
| 1 | 106 | 12 | 5 | 123 |
| 2 | 106 | 12 | 5 | 123 |
| 3 | 106 | 12 | 5 | 123 |

All three passes returned exactly the same 106 confirmed hostnames (verified:
pass1 confirmed set == pass2 confirmed set == pass3 confirmed set; 3-pass
union == 3-pass intersection == 106). Every CONFIRMED hit resolved to the
same contract, `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2` (Operator 1's
live EtherHiding contract) - consistent across all three passes.

**3-pass-union confirmed count: 106** (see `op1_B_final_confirmed_union.txt`).

### Comparison to the previously published 123

106 of the 123 previously-published confirmed sites reconfirmed live on
2026-07-11. 17 did not reconfirm in any of the 3 passes - 12 came back
reachable but CLEAN (kit markers no longer present; site presumably
remediated/cleaned since 2026-07-08) and 5 were UNREACHABLE (host down,
DNS/TLS failure, or timeout across all 3 passes). No host outside the
original 123 was newly confirmed by this recheck.

This drop (123 -> 106, -17) is expected for a live, actively-remediated
compromise set over a 3-day window and is not treated as an error - the true
number is reported as-is, not forced to match the prior 123.

Hosts not reconfirmed in any pass (12 CLEAN + 5 UNREACHABLE, full detail with
status/note is in each `op1_B_pass{1,2,3}_results.txt`):

```
1stmeridiancareservices.com
ascendagency.com
atelierspyros.com
carkey4u.com
data-point.us
dunquin-capital.com
getdomus.ai
guvana.com.hk
indiananeurologyandpain.com
seminariodeintegracao.ucam-campos.br
sisi-303.com
thecariangroup.com
www.avisenlegal.com
www.canmoreadventures.com
www.keenanwinery.com
www.lifestyleboardcentre.co.za
www.peakcivil.com.au
```

## Files in this folder

- `op1_A_candidate_pool_recheck.py` - Part A script (urlscan domain: search, corrected pagination, key read from file)
- `op1_A_candidate_pool_recheck_OUTPUT.txt` - Part A full results (925 candidate domains + per-domain counts)
- `op1_A_candidate_pool_recheck_CONSOLE.txt` - Part A console log of the final (successful) run
- `op1_B_live_verification_checker.py` - Part B checker script, adapted from the proven 2026-07-08 checker
- `op1_B_pass1_results.txt`, `op1_B_pass2_results.txt`, `op1_B_pass3_results.txt` - full per-site verdict, all 123 hosts, each pass
- `op1_B_pass1_confirmed.txt`, `op1_B_pass2_confirmed.txt`, `op1_B_pass3_confirmed.txt` - just the CONFIRMED hostnames per pass
- `op1_B_pass1_console_OUTPUT.txt`, `op1_B_pass2_console_OUTPUT.txt`, `op1_B_pass3_console_OUTPUT.txt` - console summary per pass
- `op1_B_final_confirmed_union.txt` - the 106-host 3-pass-union reconfirmed list
- `op1_SUMMARY.md` - this file
