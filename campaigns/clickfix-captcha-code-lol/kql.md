# KQL Queries -- clickfix-captcha-code-lol
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/clickfix-captcha-code-lol/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. RC4+GZip PowerShell Loader -- Script Block Logging

Matches the distinctive RC4 PRGA expression from the five-layer loader on Event ID 4104.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "-bxor $S[($S[$i] + $S[$j]) % 256]"
   or AdditionalFields has "captcha-code.lol"
   or AdditionalFields has "ABCD111"
   or AdditionalFields has "BCDA222"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessCommandLine, AdditionalFields
```

**Alternative (Sentinel -- SecurityEvent):**
```kql
SecurityEvent
| where EventID == 4104
| where EventData has "-bxor $S[($S[$i] + $S[$j]) % 256]"
   or EventData has "captcha-code.lol"
   or EventData has "ABCD111"
   or EventData has "BCDA222"
| project TimeGenerated, Computer, Account, EventData
```

---

## 2. ClickFix Delivery Chain -- cmd -> curl -> Hidden PowerShell

Matches the paste-and-run delivery pattern: cmd.exe with delayed expansion spawning curl
followed by a hidden PowerShell.

```kql
DeviceProcessEvents
| where FileName =~ "cmd.exe"
    and ProcessCommandLine has "/v:on"
    and ProcessCommandLine has_any ("where c*u*r*l", "captcha-code.lol")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| union (
    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
        and ProcessCommandLine has_any ("-WindowStyle Hidden", "-w h", "-wh")
        and InitiatingProcessFileName =~ "cmd.exe"
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
)
| sort by Timestamp desc
```

---

## 3. Rust Stealer C2 Network Traffic

Matches outbound connections to the known stealer C2 and the checkin API path.

```kql
DeviceNetworkEvents
| where RemoteIP in ("94.154.32.21", "87.232.123.174")
   or RemoteUrl has "captcha-code.lol"
   or RemoteUrl has "ziemaen.lol"
   or RemoteUrl has "/api/v1/checkin"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
```

---

## 4. ibrowser Run Key Persistence

Matches the Run key written by the Rust stealer for persistence.

```kql
DeviceRegistryEvents
| where RegistryKey has "CurrentVersion\\Run"
    and RegistryValueName =~ "ibrowser"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
```

---

## 5. Telegram Exfil from Non-Browser Process

Matches egress to the Telegram bot API from processes that aren't browsers.
The stealer provisions a Telegram token per victim at checkin.

```kql
DeviceNetworkEvents
| where RemoteUrl has "api.telegram.org/bot"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe",
                                         "brave.exe", "opera.exe", "vivaldi.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl
```

---

## 6. Hidden PowerShell Spawning AV Query (Stealer Recon)

The stealer spawns a fully hidden PowerShell subprocess to enumerate installed AV products.
This matches the specific flag combination used.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
    and ProcessCommandLine has "-NoProfile"
    and ProcessCommandLine has "-NonInteractive"
    and ProcessCommandLine has "-WindowStyle Hidden"
    and ProcessCommandLine has "AntiVirusProduct"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
```

---

## 7. Suspicious Process Accessing LSA (Workstation Context)

Hunt for non-system processes on workstations calling into secur32.dll LSA functions.
Requires process image load telemetry (Defender XDR MDE module load events).

```kql
DeviceImageLoadEvents
| where FileName =~ "secur32.dll"
| where InitiatingProcessFileName !in~ ("lsass.exe", "services.exe", "svchost.exe",
                                         "winlogon.exe", "csrss.exe", "wininit.exe")
| where DeviceName !has "DC"  // exclude domain controllers -- tune for your naming convention
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp desc
```

---

## 8. Bulk AD Enumeration from Workstation (NetAPI)

Hunt for workstations making an unusual number of connections to domain controllers
on NetBIOS/LDAP/SMB ports -- consistent with NetUserEnum/NetGroupEnum calls.

```kql
DeviceNetworkEvents
| where RemotePort in (389, 636, 445, 137, 138, 139)
| summarize ConnectionCount = count(), Ports = make_set(RemotePort)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where ConnectionCount > 20
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "dns.exe",
                                         "dfsrs.exe", "dfssvc.exe")
| sort by ConnectionCount desc
```
