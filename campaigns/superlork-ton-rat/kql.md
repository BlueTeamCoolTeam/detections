# KQL Queries -- superlork-ton-rat

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/superlork-ton-rat/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. node.exe running from LOCALAPPDATA or Temp (BYOI loader)

The campaign drops node.exe into %LOCALAPPDATA%\Nodejs\ (a non-standard path)
and executes the RAT payload from there. Any node.exe executing from a user
profile or temp directory is anomalous -- Windows does not ship Node.js.

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "node.exe"
| where FolderPath has_any (
    @"\AppData\Local\",
    @"\AppData\Roaming\",
    @"\AppData\LocalLow\",
    @"\Users\Public\",
    @"\Windows\Temp\",
    @"\Temp\"
  )
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2. Script Block Logging (4104) -- Add-MpPreference / ExclusionProcess

Detects the Defender exclusion set by the AES loader before spawning the RAT.

```kql
// Microsoft Sentinel -- Event table (EID 4104)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where RenderedDescription has "Add-MpPreference"
  and RenderedDescription has "ExclusionProcess"
| project TimeGenerated, Computer, UserName, RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Add-MpPreference"
  and AdditionalFields has "ExclusionProcess"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
```

---

## 3. TON API and superlork.info network pivots

The RAT checks the TON blockchain for its active C2 endpoint. Alert on
connections to tonapi.io and the campaign domain.

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has_any ("tonapi.io", "superlork.info", "toncenter.com")
  or (RemotePort == 443 and InitiatingProcessFileName =~ "node.exe"
      and not (FolderPath has @"Program Files"))
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

```kql
// Microsoft Sentinel -- CommonSecurityLog
CommonSecurityLog
| where DestinationHostName has_any ("superlork.info", "tonapi.io")
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName, RequestURL
| order by TimeGenerated desc
```

---

## 4. Run key persistence with node.exe (Sysmon EID 13)

The loader writes a Run key containing "node -e" and a path to the RAT payload.
Sysmon EID 13 (RegistryValueSet) surfaces this without requiring 4657 auditing.

```kql
// Microsoft Sentinel -- Sysmon Event ID 13
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| where RenderedDescription has "CurrentVersion\\Run"
  and (RenderedDescription has "node -e" or RenderedDescription has "node.exe")
| project TimeGenerated, Computer, UserName, RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceRegistryEvents
DeviceRegistryEvents
| where RegistryKey has "CurrentVersion\\Run"
| where RegistryValueData has "node"
| project Timestamp, DeviceName, AccountName, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 5. AES loader hash pivot

```kql
// Microsoft Defender XDR -- DeviceFileEvents + DeviceProcessEvents
union DeviceFileEvents, DeviceProcessEvents
| where SHA256 in (
    "f50ebfff5370025b933ced98def534bdce4e27cbbf15dde3e4b79a85944b554e",
    "da24e09777bacc92e5deafb80c446c23810c450871a295166cd54df541e9bf6d"
  )
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath,
          SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

## 6. WebSocket connection from node.exe (wss:// -- RAT command channel)

Node.js RATs typically initiate WebSocket connections. Alert on any node.exe
establishing outbound TCP connections on port 443 from a non-standard path
(this is a lower-fidelity query; tune with asset-based whitelisting).

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "node.exe"
| where RemotePort == 443
| where not (InitiatingProcessFolderPath has "Program Files"
             or InitiatingProcessFolderPath has "nodejs" and
             not InitiatingProcessFolderPath has "AppData")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
