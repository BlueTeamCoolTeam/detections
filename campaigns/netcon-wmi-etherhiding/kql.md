# KQL Queries -- netcon-wmi-etherhiding
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/netcon-wmi-etherhiding/
> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

## 1. New WMI permanent event subscription registrations

```kql
DeviceEvents
| where ActionType in ("WmiFilterBinding", "WmiConsumerEvent", "WmiFilterEvent")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName,
          AdditionalFields
| sort by Timestamp desc
```

## 2. scrcons.exe or WmiPrvSE.exe making outbound network connections

Legitimate WMI script-consumer execution almost never needs to reach the
internet. Flag any outbound connection from these processes:

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("scrcons.exe", "WmiPrvSE.exe")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP,
          RemoteUrl, RemotePort
| sort by Timestamp desc
```

## 3. Blockchain RPC calls from a non-browser process (EtherHiding indicator)

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("publicnode.com", "infura.io", "alchemy.com", "ankr.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| sort by Timestamp desc
```

## 4. Known campaign indicators (this rotation set)

```kql
let c2_domains = dynamic(["letsmefindyoudream.com", "throwfree.com",
    "mydreamcomesoon.com", "newmydreamcome.com", "nvpsuprotyudream.com",
    "666dream666toyou666.com", "666super666crazy666.com", "sjjthjthiter.com"]);
let c2_ips = dynamic(["45.32.162.181", "155.138.253.99", "91.228.152.92",
    "216.128.146.149", "155.138.224.155"]);
DeviceNetworkEvents
| where RemoteUrl has_any (c2_domains) or RemoteIP in (c2_ips)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| sort by Timestamp desc
```

Note: domains/IPs above are listed unescaped for direct use in the `dynamic()`
array -- see `iocs.csv` in this folder for the defanged reference copy.
