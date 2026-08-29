# KQL Queries -- rcc68-webshell-kit
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/rcc68-webshell-kit/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## IIS Worker Process Spawning cmd.exe or powershell.exe

Covers T1059.001 / T1059.003 / T1505.003 -- web shell command execution.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## IIS Log Requests Carrying the rcc68 Auth Token (Sentinel / W3CIISLog)

Requires IIS W3C logs ingested into Sentinel via the W3CIISLog table, with
custom request headers included in the log field configuration.

```kql
W3CIISLog
| where csUriQuery has_any ("k=rcc68", "sid=rcc68", "token=rcc68")
      or csUriQuery has "rcc68"
| project TimeGenerated, cIP, csUriStem, csUriQuery, scStatus, csUserAgent
| order by TimeGenerated desc
```

---

## New Script Files Written Under a Web Root

Covers initial web shell drop via unrestricted file upload -- requires
file-creation auditing or Sysmon Event ID 11.

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath has_any ("inetpub", "wwwroot")
| where FileName endswith ".aspx" or FileName endswith ".ashx"
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName
| order by Timestamp desc
```

---

## Security Software Discovery via PowerShell (Process / Service / Registry Enumeration)

Covers T1518.001 -- checking for installed AV/EDR/RMM products before proceeding.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Get-Process", "Get-Service", "Uninstall")
      and ProcessCommandLine has_any ("Defender", "CrowdStrike", "Sentinel", "Sophos", "Bitdefender", "Kaseya", "Huntress", "Sysmon", "Veeam")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
```
