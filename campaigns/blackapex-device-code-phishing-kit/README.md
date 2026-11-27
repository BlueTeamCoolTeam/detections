# blackapex-device-code-phishing-kit

Blog post: https://blueteam.cool/posts/blackapex-device-code-phishing-kit/

## Summary

BlackApex is a phishing kit, deployed by many operators, targeting Microsoft 365 / Entra ID. A lure
link leads to a fake "Just a moment... | OneDrive" Cloudflare check with a real
Turnstile widget. Past the gate the victim completes a genuine Microsoft sign-in
(device code flow), and the kit's backend collects the tokens.

Within seconds the backend registers a device in the victim's tenant, obtains a
Primary Refresh Token for it and adds a Windows Hello for Business key. That key
is not affected by a password reset.

Each node answers several API routes without authentication, including one that
returns the real origin address behind Cloudflare. That is how the backend list
here was built.

```
lure email -> kit domain (?acct= / ?email=)
  -> fake Cloudflare gate + Turnstile  (GET /api/landing-paths/active, POST /verify-turnstile)
  -> lure page shows a device code  (POST /start, then GET /state?device_code=... every 5 s)
  -> genuine Microsoft sign-in, MFA completed by the victim
  -> backend collects tokens -> Register device -> PRT -> Windows Hello for Business key
  -> operator console: mailbox, contacts, directory, escalation
```

## What is included

| File | Description |
|---|---|
| `iocs.csv` | 93 backend IPs, 660 domains and hostnames, 94 Turnstile site keys, kit paths and titles. Network IOCs are defanged |
| `sigma-blackapex-gate-requests.yml` | Proxy rule for the gate and lure page URL paths and query string |
| `kql.md` | Sentinel / Defender XDR hunts for device code sign-ins and the device-then-key sequence |

No YARA rule: there is no file sample in this investigation.

## Coverage notes

**What these detections cover**

- A user's browser reaching a kit gate page (proxy rule, domain list)
- Device code sign-ins, and the device registration plus Windows Hello key that follow a capture
- Sign-ins from the backend addresses as of 2026-11-26

**What they do NOT cover**

- The lure email itself. No sample was captured
- The page shown after the gate. It was not captured in this investigation
- The kit's optional Cloudflare Worker "edge gateway". None was located
- New domains and backends. The lists are a snapshot from 2026-11-26

## False-positive notes

- `sigma-blackapex-gate-requests.yml`: unknown. `/verify-turnstile` on its own is a generic name; the pair with `/api/landing-paths/active` is the stronger signal.
- KQL 1: device code flow is legitimate for meeting room devices and some CLI tools. Baseline before alerting.
- KQL 2 and 3: a user setting up a new Windows laptop registers a device and a Windows Hello key in quick succession. Check the source IP and whether the device is one you issued.
- `iocs.csv` domains marked `low` came from Shodan results and were not probed. Domains marked `medium` served the gate title at some point in the Validin window. Some may since have lapsed, been parked or belong to a compromised legitimate site. Do not block them without checking.

## Confidence

High for the infrastructure indicators: backends and `high` domains identified
themselves by returning the kit's API schema on 2026-11-26. Medium for domains seen
only in passive data. The Entra hunts are derived from the kit's observed behaviour
and have not been validated in a production tenant.

## Related detections

- [iocs.csv](iocs.csv)
- [sigma-blackapex-gate-requests.yml](sigma-blackapex-gate-requests.yml)
- [kql.md](kql.md)
