# KQL Queries -- wordpress-webshell-gsocket
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/wordpress-webshell-gsocket/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## IIS Worker Spawning Shell or Transfer Processes

Covers T1505.003 / T1059.004 -- PHP webshell executing commands via cmd.exe or bash.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "bash.exe", "wsl.exe", "curl.exe", "wget.exe", "powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Outbound Connections from IIS to gsocket Infrastructure

Covers T1219 -- gsocket relay C2 over TLS 443.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "w3wp.exe"
| where RemoteUrl has_any ("gsocket.io", "cdn.gsocket.io", "remotenyasar.click")
      or RemoteIP in ("182.253.14.138", "103.59.160.93")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemoteUrl, RemotePort, ActionType
| order by Timestamp desc
```

---

## DNS Queries to gsocket or Attacker Infrastructure

Broader hunt -- catches any process resolving these domains, not just IIS.

```kql
DeviceNetworkEvents
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has_any ("gsocket.io", "cdn.gsocket.io", "remotenyasar.click")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Timestamp desc
```

---

## IIS Log Query Strings Containing Webshell Parameters (Sentinel / W3CIISLog)

Requires IIS W3C logs ingested into Sentinel via the W3CIISLog table.

```kql
W3CIISLog
| where csUriQuery has_any ("sindikat777", "c0m99nd", "act=c0m")
| project TimeGenerated, cIP, csUriStem, csUriQuery, scStatus, csUserAgent
| order by TimeGenerated desc
```

---

## New PHP Files Written Under WordPress Plugin Directory

Covers initial webshell drop -- requires file-creation auditing or Sysmon Event ID 11.

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath contains "wp-content\\plugins"
| where FileName endswith ".php"
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName
| order by Timestamp desc
```
