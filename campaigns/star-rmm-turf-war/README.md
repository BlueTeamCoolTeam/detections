# star-rmm-turf-war

Blog post: https://blueteam.cool/posts/star-rmm-turf-war/

## Summary

A rogue ScreenConnect client -- installed months before the host joined a managed fleet -- was used to deliver PowerShell scripts that harvested browser history for QuickBooks Online credentials, swept for crypto wallet extensions across all user profiles, and exfiltrated results to three separate Telegram bots routing data to different operator channels. A 3,000-line cleanup script (version 3) removed 18 competing ScreenConnect panels and four other RMM tools from victim hosts, then wiped forensic traces including six Windows event logs, PowerShell history, Prefetch entries, and Jump Lists.

OSINT on the three bot tokens surfaced five named operators, confirmed two as Russian-speaking via Telegram `lang_code` metadata, and identified six actor-controlled SC relay domains hosted on bulletproof-adjacent providers (Cloudzy, Proton66, Prospero). Four of the six domains share a single Cloudflare account (NANCY+KELLEN nameserver pair), providing a pivot for tracking future infrastructure expansion.

The campaign tooling includes a versioned browser history scanner (`v35`) with a runtime-compiled C# class that reads SQLite databases via raw byte scan to avoid file lock conflicts, a wallet scanner (22 browser extensions + 9 desktop wallets), and self-deleting scheduled tasks with hash-derived names that leave minimal on-host forensic residue.

```
EXECUTION FLOW
==============

Phishing / fake support page
  |
User installs rogue ScreenConnect client
  |
SC client registers to actor relay (digitalaccessmanagement[.]com:8040 etc.)
  |
Actor pushes PowerShell scripts via SC file transfer
  |
  +-- starQBOv35.ps1       -> @Check12899_bot  -> Checker Channel (-1003277400990)
  +-- Search-BrowserHistory-v35.ps1 -> @botbybost_bot -> APPLY Group (-5212689198)
  +-- findwal_system.ps1   -> @AndrewTateSigma_bot -> DM @sadfewego + @head_exp
  |
Results staged to C:\H\tg_send_<md5>.ps1
  |
SYSTEM scheduled task (TG_Send_<md5>) fires, waits random delay, sends
  |
Task + script self-delete; only C:\H\telegram_bg.log persists
  |
[Optional] Star_v3.ps1 removes 18 competitor SC panels + 4 RMM tools + wipes traces
```

## What is included

| File | Description |
|---|---|
| `iocs.csv` | All indicators: domains, IPs, Telegram infra, SC instance IDs, host artefacts |
| `rule.yar` | Three YARA rules: QBO stealer, competitor eviction script, wallet scanner |
| `sigma-telegram-exfil.yml` | Detects hash-named scheduled task + Telegram exfil pattern |
| `sigma-log-cleared.yml` | Detects Event ID 1102 (security log cleared) |
| `sigma-rogue-sc-panel.yml` | Detects SC service registration matching known STAR instance IDs |
| `kql.md` | Eight KQL queries for Sentinel / Defender XDR including a fleet audit query |
| `README.md` | This file |

## Coverage notes

### What these detections cover

- **Known actor infrastructure** -- the six SC relay domain/IP pairs and three Telegram bot tokens are high-confidence indicators; any hit on these should be treated as confirmed compromise
- **Behavioural patterns** -- the task naming convention (`TG_Send_<md5>`, `BHS_<uid>`) and staging path (`C:\H\`) are consistent campaign artefacts observed in captured samples
- **Trace wipe** -- Event ID 1102 and log-gap detection catch the cleanup phase; real-time forwarding is required for reliability
- **Script content** -- YARA rules on script content catch disk artefacts; Script Block Logging (4104) catches in-memory execution before self-deletion

### What these detections do NOT cover

- **Initial installation method** -- we did not recover the initial phishing lure or SC installer delivery mechanism; no detection for the initial access phase beyond "an unknown SC instance ID appeared"
- **Encrypted payloads** -- if the actor updates scripts to use base64 or other encoding, the content-based YARA rules will miss the new variants; behavioural Sigma rules remain effective
- **New relay infrastructure** -- the six domains and IPs will rotate; the Cloudflare NANCY+KELLEN pivot is the best long-term tracking mechanism but requires external PDNS/NS query monitoring
- **Newer bot tokens** -- bot tokens can be revoked and replaced; existing token matches will become stale if the actor rotates them

## False-positive notes

- **YARA `STAR_QBO_TelegramStealer`**: no known false positives -- the bot token strings are unique to this campaign
- **YARA `STAR_CompetitorEviction_v3`**: `wevtutil cl` alone is common in administrative scripts; the rule requires it alongside the `SimpleHelp|JWrapper|Remote Access|TacticalRMM` protect-pattern or two whitelist instance IDs -- combined FP rate is very low
- **Sigma `sigma-telegram-exfil`**: `TG_Send_` and `BHS_` task names have no known legitimate use; `api.telegram.org` from a scheduled task context is high-confidence
- **Sigma `sigma-log-cleared`**: Event ID 1102 has FPs during legitimate IT maintenance (e.g., log rotation, cleanup scripts); document and exclude expected hosts, treat any unexpected host as high priority
- **Sigma `sigma-rogue-sc-panel`**: no FPs -- these instance IDs are attacker-controlled

## Confidence

- **IOCs (infrastructure)**: High -- all six domains confirmed live as SC relays with matching port fingerprint; all three bot tokens confirmed live via Telegram Bot API; all five operator accounts confirmed live
- **Host artefact patterns**: High -- recovered directly from victim host; multiple captured `tg_send_*.ps1` scripts and `telegram_bg.log` confirm execution
- **Behavioural Sigma rules**: High -- derived from directly observed execution patterns
- **Competitor panel IDs**: Medium -- confirmed present in `Star_v3.ps1` eviction list; not independently verified as active on other victim hosts

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-telegram-exfil.yml](sigma-telegram-exfil.yml)
- [sigma-log-cleared.yml](sigma-log-cleared.yml)
- [sigma-rogue-sc-panel.yml](sigma-rogue-sc-panel.yml)
- [kql.md](kql.md)
