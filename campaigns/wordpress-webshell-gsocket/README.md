# wordpress-webshell-gsocket

Blog post: https://blueteam.cool/posts/wordpress-webshell-gsocket/

## Summary

A WordPress site running on Windows IIS was compromised via an unauthenticated file upload endpoint in an already-installed plugin. The attacker's initial access vector was a `POST` to `/wp-admin/admin-ajax.php` -- consistent with a `wp_ajax_nopriv_` action that accepted file uploads without authentication.

The attack used a two-stage webshell chain. Stage 1 was `toolbar-processor-428.php`, a 460-byte fake WordPress plugin that printed `php_uname()` output and rendered an unauthenticated upload form. Embedded in its output were three Telegram handles (`@WebshellSR`, `@Devco1`, `@BIBIL0DAY`), suggesting a commercial webshell-as-a-service operation. Stage 2 was `byp.php`, a 427KB binary-encoded file manager and RCE platform that obfuscated all dangerous function names using char-code decoding at runtime.

With command execution established, the attacker made six successive attempts to deploy a `gsocket` reverse shell -- an open-source tool that tunnels over TLS to a relay at `gsocket[.]io:443`. The relay architecture means there is no listening C2 IP to block. The entire active exploitation window was 19 minutes.

```
1. Initial access    -- unauthenticated AJAX endpoint -> plugin install via /wp-admin/admin-ajax.php
2. Stage 1 dropper   -- toolbar-processor-428.php: unauthenticated file uploader
3. Stage 2 webshell  -- byp.php: binary-encoded file manager + RCE (12 exec methods)
4. C2 deployment     -- 6 attempts: bash -> backup installer -> WSL -> PowerShell x2 -> wget
5. Objective         -- interactive reverse shell via gsocket[.]io relay (TLS 443 outbound)
                        + manual recon (whoami / pwd / dir)
```

## What is included

| File | Description |
|---|---|
| `iocs.csv` | All indicators: IPs, domains, URLs, filenames, strings, persistence markers |
| `rule.yar` | YARA rules for Stage 1 dropper and Stage 2 webshell (encoded or decoded) |
| `sigma-webshell-iis-query.yml` | Sigma rule for IIS query strings containing webshell parameters |
| `sigma-iis-spawns-shell.yml` | Sigma rule for `w3wp.exe` spawning `cmd.exe`, `bash.exe`, etc. |
| `kql.md` | KQL queries for Sentinel/Defender XDR: process creation, network egress, DNS, file events |

## Coverage notes

**What these detections cover:**
- Stage 1 and Stage 2 webshell files (YARA matches on string fingerprints present in both encoded and decoded forms)
- Webshell C2 traffic via unique query string parameters (`sindikat777`, `c0m99nd`)
- IIS worker process spawning unexpected child processes (the primary host-based indicator)
- Outbound connections and DNS queries to `gsocket[.]io`, `cdn.gsocket[.]io`, and `remotenyasar[.]click`
- gsocket persistence artifacts (crontab marker string, process masquerade names, file paths)

**What they do NOT cover:**
- The initial vulnerable plugin that provided the unauthenticated AJAX endpoint -- that plugin was not identified from the available evidence
- File hashes for either webshell -- hashes were not available in the source evidence; filename-based IOCs should be treated as low-confidence without hash confirmation
- Whether gsocket was successfully deployed -- IIS logs confirmed the commands were submitted but not that they ran to completion; the YARA/Sigma rules will fire regardless of deployment success

## False-positive notes

- **`sindikat_webshell_stage1` (YARA):** The `$up` string (`copy($_FILES...`) could match other PHP upload scripts. The Telegram handle strings (`$tg*`) are specific and high-confidence; prefer matching on those.
- **`sindikat_webshell_stage2` (YARA):** The `$enc` regex for binary-blob encoding is specific. The named parameters (`sindikat777`, `c0m99nd`) match on two-of-four for robustness but could produce FPs on obfuscated code that happens to share strings; tune the `2 of` threshold if needed.
- **`sigma-webshell-iis-query`:** The parameter names `sindikat777` and `c0m99nd` have no known legitimate use. Low FP risk.
- **`sigma-iis-spawns-shell`:** `w3wp.exe` spawning `cmd.exe` occasionally occurs during legitimate IIS module operations or diagnostics. Review `ProcessCommandLine` and `InitiatingProcessCommandLine` for context before escalating.
- **gsocket domain IOCs:** `gsocket[.]io` and `cdn.gsocket[.]io` are legitimate infrastructure. The IOC confidence is medium -- these should be blocked at proxy for servers that have no legitimate need to reach them, but correlate with other indicators before treating as a confirmed incident indicator.

## Confidence

**Overall: Medium-High.**

The webshell code was directly recovered and analysed. The IIS log sequence captures the full exploit chain chronologically. The YARA rules match on strings directly extracted from the webshell source. The Sigma rules match on observable log artifacts confirmed in the incident.

Confidence is not "high" across the board because:
- File hashes are absent (no hash-based confirmation of webshell identity)
- Successful gsocket deployment could not be confirmed from IIS logs alone (HTTP 200 from the webshell != successful command execution)
- Initial access vector (specific vulnerable plugin) was not identified

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-webshell-iis-query.yml](sigma-webshell-iis-query.yml)
- [sigma-iis-spawns-shell.yml](sigma-iis-spawns-shell.yml)
- [kql.md](kql.md)
