# Reproduction log - mapping the EtherHiding ecosystem

This folder documents the work that turned two new, separate investigations
(`mamkor-pro-iwr-downloader` and `bw-panel-926d6454-sibling`) plus one previously
published post (`authorization-cdn-etherhiding-clickfix`, 2026-07-08) into a single
combined figure: how many distinct EtherHiding operators are being tracked, and how
many confirmed compromised websites they account for in total, without double-counting.

Every number cited in the combined post traces to one of the numbered script + output
pairs below. Nothing here is paraphrased from memory or from chat history - every
script was actually executed and its full console output is saved alongside it.

## Step 1 - resolve a direct contradiction in the source material before writing anything

Script: `01_selector_conflict_check.py` | Output: `01_selector_conflict_check_OUTPUT.txt`

`mamkor-pro-iwr-downloader/REPORT.md` documents its own EtherHiding getter selector as
`0x38bcdc1c` in its IOC table, but a later section of the same report (written after
the sibling investigation) describes mamkor as "one of at least 5 known operator
instances of the same rented 'BW panel' EtherHiding kit (shared selector
`0xb68d1809`)" - the same selector used by the xdav / Operator 2 / Operator 3 /
BW-sibling cluster. Those two statements can't both be literally true of the same
contract implementing one selector interface, so before repeating either claim as fact
in the combined post, this was checked live, on-chain, against all three contracts in
question, with both selectors:

| Contract | `38bcdc1c` | `b68d1809` |
|---|---|---|
| mamkor/merabs `0x08207B08...` | OK -> `mamkor.pro` | **REVERTED** |
| BW-sibling `0x926d6454...` | REVERTED | OK -> `https://ns-claude-js.beer` |
| xdav / Operator 1 `0xB6bC9e1D...` | REVERTED | OK -> `https://auth-code-check.info` |

**Result: the two kit families are genuinely distinct on-chain artifacts, not one
shared kit.** mamkor's contract does not implement the `b68d1809` function at all (it
reverts), and the two `b68d1809` contracts do not implement `38bcdc1c`. The "5
operators of one kit" framing in the mamkor report's own §5a/5b is not supported by its
own evidence and is not carried into the combined post. What both families genuinely
share is only the general EtherHiding *technique* (resolve C2 from a Polygon contract
via `eth_call`), plus one coincidental discovery link (the `cedahr.com` pivot, found
while hunting mamkor's victims, that turned out to belong to the BW-sibling operator)
and one confirmed dual-compromised victim (Step 2, below).

Side finding, not the point of this check but recorded anyway: xdav's Operator-1
contract's live C2 as of this pass is `auth-code-check[.]info` - different from the
`authorization-cdn-press-enter[.]info` recorded in the 2026-07-08 post. The domain has
rotated again in the intervening days, consistent with that post's own framing that
these numbers are a floor on an active campaign, not a fixed fact.

## Step 2 - does the "901 confirmed" headline number actually hold up?

Script: `02_cross_family_dedup_check.py` | Output: `02_cross_family_dedup_check_OUTPUT.txt`
Inputs: `family_a_operator{1_xdav,2,3}_confirmed.txt` (copied unchanged from
`authorization-cdn-etherhiding-clickfix/revalidation-2026-07-08-full/op{1,2,3}_confirmed_final.txt`),
`family_a_bwsibling_confirmed.txt` and `family_b_mamkor_confirmed.txt` (copied unchanged
from the two new investigations' own `confirmed_compromised_MASTER.txt` files).

Naive `wc -l` on several of these files undercounts by 1 (last line has no trailing
newline) - the script counts logical stripped entries, not raw newlines, to avoid that
off-by-one.

| List | Confirmed |
|---|---|
| Family A - Operator 1 / xdav | 123 |
| Family A - Operator 2 | 27 |
| Family A - Operator 3 | 3 |
| Family A - BW-sibling (new) | 111 |
| **Family A union** (checked pairwise, zero overlap between any two of the four) | **264** |
| Family B - mamkor/merabs (new) | 638 |
| **Cross-family overlap** | **1** - `www.beltboutique.co.uk`, confirmed independently by both Operator 1/xdav and mamkor/merabs |
| **Grand total unique** | **901** |

This is the one, single site independently compromised by two different EtherHiding
crews at once - direct, checkable evidence for the "how rampant this is" claim, rather
than an inferred one.

## Step 3 - are the three carried-over (not re-run) numbers from 2026-07-08 still a reasonable floor?

Script: `03_family_a_staleness_spotcheck.py` | Output: `03_family_a_staleness_spotcheck_OUTPUT.txt`

The combined post carries Operator 1/2/3's confirmed counts forward from the
2026-07-08 post as published, rather than re-running the full three-pass verification
against all 153 sites again. To sanity-check that decision, a small, deterministically
selected sample (every Nth line, up to 5 per operator; all 3 for operator 3, which only
has 3 total) was fetched live and checked for the same injection fingerprint the
original post's own checker used (brute-force every `atob()` blob against all 256
single-byte XOR keys, look for the run-once guard variable plus 2+ of
polygon/eth_call/api.php in the decoded text).

| Result | Count | Share |
|---|---|---|
| CONFIRMED (injection still live) | 7 / 13 | 54% |
| REACHABLE_NO_MATCH | 5 / 13 | 38% |
| UNREACHABLE | 1 / 13 | 8% |

Consistent with the original post's own framing: a confirmed count is a floor at the
timestamp it was captured, not a ceiling, and "no match on one fetch" does not mean
remediated - the injection is known to be gated by referrer/geo/cookie on some
backends. A 54% same-injection-visible rate on a random sample 3 days later is not
evidence the original 123/27/3 figures are stale or wrong; it's consistent with the
churn the original investigation already documented. The 123/27/3/153 figures are
carried forward unchanged into the combined post on this basis, with this spot-check
cited rather than a full same-day re-run.

## Step 4 - the two investigations' own key reproducers, carried forward for transparency

These are not new work - they're copied, unmodified except for the file rename, from
the two new investigations' own artifact folders, because a reader who wants to verify
"how it was all discovered" for the new material should be able to run the same code
that actually produced it, not just read a description of it.

- **`04_mamkor_stage3_decrypt_blob.py`** - the reproducer for the mamkor/merabs
  stage-3 payload's 5-round custom cipher, recovered via Ghidra headless decompilation
  of the Go loader (see the source REPORT.md's Methodology steps 18-25 for the full
  discovery path, including the two dead ends - a failed Python Ghidra post-script,
  then a wrong offset/length guess - before landing on the working extraction). This
  script needs the actual `stage1_x.exe` sample to run against, which is a malicious
  binary and is deliberately **not** included in this repo; the script is provided so
  the cipher itself (round order, key derivation) can be independently checked against
  anyone's own copy of the sample, and so the method is documented even without the
  binary.
- **`05_mamkor_confirmed_site_validator.py`** - the final independent re-validator used
  to reconfirm mamkor/merabs's 638 confirmed sites (four decode schemes: cleartext,
  `atob`+sub-then-XOR, plain single-byte XOR, 256-byte S-box). Expects a
  `confirmed_compromised_ALL.txt` input (one hostname per line) in the working
  directory; not included here since the actual 638-site list is `family_b_mamkor_confirmed.txt`
  above.
- **`06_bwsibling_confirmed_site_validator.py`** - the final, most-evolved confirm
  script from the BW-sibling investigation's three-batch urlscan hunt (batch 3, which
  went through three iterations and ended up cross-checking its own `eth_call`
  extraction against a public Polygon RPC before accepting a result - see the source
  REPORT.md §4/Methodology steps 6-9 for the full undercounting-bug story this script
  was rewritten to fix). Expects `candidate_hosts.json` (a urlscan pivot result) as
  input; not included here.

Full narrative detail behind both new investigations - including the on-chain
enumeration of BW-sibling's 87 contracts/90 domains and the methodology correction that
recovered them, and mamkor's 127-setter-call C2 rotation history - remains in each
source REPORT.md and is summarized in the combined post rather than reproduced here.

## Numbers for publication

| | Confirmed compromised sites |
|---|---|
| Family A ("BW panel" kit, selector `b68d1809`) - 4 operators | 264 |
| Family B (mamkor/merabs kit, selector `38bcdc1c`) - 1 operator | 638 |
| Cross-family duplicate removed | -1 |
| **Grand total, unique** | **901** |

Captured: Family A's op1/2/3 counts as published 2026-07-08 21:08-21:28 UTC
(spot-checked, not fully re-run, 2026-07-11 - see Step 3); BW-sibling and mamkor/merabs
counts as produced 2026-07-11 (see each source REPORT.md for exact session timestamps).
This spans two different capture sessions three days apart across five operators - not
one single continuous snapshot the way the 2026-07-08 post's own numbers were. Treat
901 as a floor on a still-active set of campaigns, not a permanent fact - re-running
`02_cross_family_dedup_check.py` against fresh confirmed-site lists later will very
likely show a different (probably higher) number, the same lesson every prior EtherHiding
post in this series has already drawn.

## Files in this folder

| File pattern | Contents |
|---|---|
| `01_*` through `03_*` (`.py` + matching `_OUTPUT.txt`) | New verification work done specifically for the combined post - selector conflict, cross-family dedup, staleness spot-check |
| `04_*` - `06_*` | Key reproducer scripts carried over unmodified from the two new source investigations |
| `family_a_operator{1_xdav,2,3}_confirmed.txt` | Copied unchanged from the authorization-cdn-etherhiding-clickfix campaign's own revalidation folder |
| `family_a_bwsibling_confirmed.txt`, `family_b_mamkor_confirmed.txt` | Copied unchanged from the two new investigations' own `confirmed_compromised_MASTER.txt` |

No API key values are stored in any script or output file (scripts that need one read
it from a local file at invocation time only).
