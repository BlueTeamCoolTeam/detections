# KQL Queries -- flomo-onedrive-sideload

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/flomo-onedrive-sideload/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. WindowsTerminal spawning PowerShell with download arguments (ClickFix Win+X variant)

The Win+X ClickFix lure uses Windows Terminal as the grandparent, bypassing
detections keyed on explorer.exe. Alert on this parent-child pattern with
download-indicative command line arguments.

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WindowsTerminal.exe", "wt.exe")
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr ", "DownloadFile",
        "WebClient", "GetRandomFileName")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2. Electron/flomo RAT -- process in ExFiles directory

The trojanized Electron app unpacks to %LOCALAPPDATA%\ExFiles\.
Any process executing from that path is anomalous.

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FolderPath contains @"\AppData\Local\ExFiles\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 3. OneDriveLauncher executing outside its real install path

The campaign drops Con_Adapter.exe (= signed OneDriveLauncher.exe) to %TEMP%
for DLL sideloading. Detect the binary running from any non-standard path.

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "OneDriveLauncher.exe"
| where not (FolderPath has "\\OneDrive\\" or FolderPath has "\\Microsoft OneDrive\\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4. LoggingPlatform.dll hash verification

The trojanized DLL has a specific hash that differs from any legitimate
OneDrive release. A single search for this hash is worth running.

```kql
// Microsoft Defender XDR -- DeviceFileEvents
DeviceFileEvents
| where SHA256 == "656fb0ce773fdfb745263deb1492170f9b332778a33ee3b15ee0adc33110cff7"
| project Timestamp, DeviceName, AccountName, ActionType, FolderPath, FileName,
          SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 5. Campaign domain indicators

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has_any ("clacndjsvulnarbi.beer", "devltd.top", "finework.top")
  or RemoteIP == "178.16.52.101"
| project Timestamp, DeviceName, AccountName, ActionType, RemoteUrl, RemoteIP,
          InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Microsoft Sentinel -- CommonSecurityLog
CommonSecurityLog
| where DestinationHostName has_any ("clacndjsvulnarbi.beer", "devltd.top", "finework.top")
  or DestinationIP == "178.16.52.101"
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName, RequestURL
| order by TimeGenerated desc
```

---

## 6. signal_config.meta co-located with an OneDrive binary

```kql
// Microsoft Defender XDR -- DeviceFileEvents
DeviceFileEvents
| where FileName in~ ("signal_config.meta", "volume1024.conf")
| project Timestamp, DeviceName, AccountName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName
| order by Timestamp desc
```
