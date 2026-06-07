# wmail-service-stego-beacon

Detection artefacts for a campaign using steganographic payload delivery
via a Windows kernel driver disguised as an SSRS diagnostic log filler.

Blog post: https://blueteam.cool/posts/wmail-service-stego-beacon/

---

## Campaign summary

The attacker delivered a trojanised `.sys` file padded with realistic
Microsoft SQL Server Reporting Services (SSRS) diagnostic strings to
reach a size consistent with a legitimate driver. The real payload
was base64-encoded and hidden inside the filler block. A VBScript
wrapper -- named as a bare GUID and executed via `wscript.exe /e:vbscript` --
extracted the embedded PowerShell from the carrier, decoded it, and
executed it in memory. A GUID-named scheduled task ran the wrapper on
a defined interval, providing persistence without writing additional
files to disk.

The PowerShell beacon called back to `counter.wmail-service[.]com` over
HTTPS, polling for commands on a scheduled cadence.

---

## Attack chain

```
Lure / initial access
  -> carrier dropped to System32\drivers\<GUID>\<name>.sys
  -> GUID-named scheduled task (EID 4698) created
  -> task executes: wscript.exe /e:vbscript <GUID-file>
  -> VBScript reads carrier bytes at offset, base64-decodes payload
  -> decoded PowerShell executed via ScriptBlock::Create (in memory)
  -> beacon calls counter.wmail-service[.]com/v1/<GUID>?v=DownloadsCounter_<N>
```

---

## Key techniques

| ATT&CK | Technique | Notes |
|--------|-----------|-------|
| T1036.005 | Match Legitimate Name or Location | .sys extension and SSRS strings mimic real driver |
| T1027.003 | Steganography | Payload hidden in filler padding inside the carrier |
| T1059.005 | Visual Basic | VBScript executes the decoded payload |
| T1053.005 | Scheduled Task/Job | GUID-named task provides persistence |
| T1620 | Reflective Code Loading | ScriptBlock::Create for in-memory execution |
| T1071.001 | Web Protocols | HTTPS beacon to wmail-service.com |

---

## Files in this folder

| File | Purpose |
|------|---------|
| `rule.yar` | YARA rule matching the SSRS filler strings + base64 substrings of the beacon payload |
| `sigma-wscript-vbscript-no-extension.yml` | Sigma (process_creation): wscript.exe /e:vbscript against a non-.vbs/.vbe file |
| `sigma-guid-task-wscript.yml` | Sigma (security EID 4698): scheduled task with bare-GUID name running a script host |
| `iocs.csv` | Indicators of compromise (defanged network IOCs) |
| `kql.md` | Microsoft Sentinel / Defender XDR KQL queries |

---

## Detection notes

- The SSRS filler strings are memorable and extremely low false-positive --
  they should not appear in any legitimate `.sys` binary.
- The wscript /e:vbscript + non-vbs-extension combination catches the
  execution stage without needing the carrier file itself.
- The GUID-named task pattern (EID 4698 + regex match) has a small FP risk
  in environments that generate GUID task names legitimately (some enterprise
  software does). Review EID 4698 data in your environment before alerting.
- Because ETW telemetry from the host is potentially observable by the
  attacker, forward logs off-host before they can be cleared.
