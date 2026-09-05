# KQL Queries -- fake-webex-multi-rmm

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/fake-webex-multi-rmm/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

## 1. Rocky RMM C2 connection attempts (TCP 5222 to non-XMPP infra)

```kql
DeviceNetworkEvents
| where RemoteUrl has "casacam.net" or RemotePort == 5222
| where RemoteIP == "45.156.87.171" or RemoteUrl has "rockytomholland"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

## 2. ScreenConnect relay connections to the campaign's shared instance

```kql
DeviceNetworkEvents
| where RemoteIP == "167.94.158.48" and RemotePort in (8041, 443)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```

## 3. Agta Backup Agent C2 checkin

```kql
DeviceNetworkEvents
| where RemoteIP == "155.254.99.248" and RemotePort == 4080
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
```

## 4. Level.io enrollment key in process command lines

```kql
DeviceProcessEvents
| where ProcessCommandLine has "LEVEL_API_KEY=F528uEYAgf7LxEx9sVtRcmpc"
   or ProcessCommandLine has "downloads.level.io"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## 5. PowerShell-downloaded MSI silently installed (shared Leg 2a / Leg 3 pattern)

```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "/qn" and ProcessCommandLine has ".msi"
| where ProcessCommandLine has_any ("Temp", "AppData\\Local\\Temp")
| join kind=inner (
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("DownloadFile", "Invoke-WebRequest", "WebClient")
    | where ProcessCommandLine has ".msi"
) on DeviceId
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ProcessCommandLine1
```

## 6. Rocky RMM Startup-folder persistence (cscript writing a .lnk)

```kql
DeviceProcessEvents
| where FileName =~ "cscript.exe"
| where ProcessCommandLine has "//nologo" and ProcessCommandLine has ".vbs"
| where InitiatingProcessFileName !in~ ("explorer.exe", "wscript.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
DeviceFileEvents
| where FolderPath has @"\Microsoft\Windows\Start Menu\Programs\Startup\"
| where FileName == "RockyRMMClient.lnk"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
```

## 7. Agta hidden-service install and scheduled-task guardian

```kql
DeviceProcessEvents
| where ProcessCommandLine has "--install-service" and ProcessCommandLine has "--checkin-url"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("AgtaHideSC", "AgtaWifiKeeper")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## 8. Victim-lockout operator scripts (power/Wi-Fi captivity tooling)

```kql
DeviceProcessEvents
| where FileName =~ "secedit.exe"
| where ProcessCommandLine has "/configure" and ProcessCommandLine has "USER_RIGHTS"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

```kql
DeviceRegistryEvents
| where RegistryKey has @"Image File Execution Options\SlideToShutDown.exe"
| where RegistryValueName == "Debugger"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

```kql
DeviceRegistryEvents
| where RegistryKey has @"Policies\Explorer"
| where RegistryValueName in ("NoClose", "NoLogoff", "HidePowerOptions", "HideSCANetwork", "StartMenuLogOff")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## 9. Agta named-pipe artifacts (requires pipe-creation telemetry, e.g. Sysmon Event ID 17/18 forwarded to Defender/Sentinel)

```kql
DeviceEvents
| where ActionType in ("NamedPipeEvent", "PipeEvent")
| where AdditionalFields has_any ("agta-keylog-drain", "agta-ws-stream", "agta-bs-shell", "agta-file-tx")
| project Timestamp, DeviceName, ActionType, AdditionalFields
```
