#!/usr/bin/env python3
"""
Applies the redirect-attribution correction found by
13_redirect_attribution_check.py / 14_resolve_redirect_attribution.py.

Of 70 flagged apex-domain mismatches, 65 turned out to be false alarms
(the earlier check compared page.apexDomain against task.url's host, but
the eth_call's actual documentURL - the page that really executed the
injected script - matched page.apexDomain all along, just via a www./
subdomain path). 5 were genuine misattributions where page.apexDomain is
an unrelated redirect target that has nothing to do with the campaign:

  amazon.com        -> real site: hajighani-sons.com
  google.com         -> real sites: schneider-peklar.at, www.sicherheit-24.eu (TWO sites merged under one wrong label)
  youtube.com        -> real site: connectingtomorrowit.com (www. variant)
  aliexpress.com     -> real site: ssint.org
  unstives.com       -> real site: mardelupe.lachimenea.cl

This directly resolves the user-caught issue: amazon.com (and youtube.com,
google.com, aliexpress.com, unstives.com) should never have been in the
confirmed-sites list - they are redirect artifacts, not compromised sites.
"""
import json

WRONG_APEX_TO_REAL_SITES = {
    "amazon.com": ["hajighani-sons.com"],
    "google.com": ["schneider-peklar.at", "sicherheit-24.eu"],
    "youtube.com": ["connectingtomorrowit.com"],
    "aliexpress.com": ["ssint.org"],
    # lachimenea.cl looks like a shared Chilean hosting/blog platform (many
    # unrelated subdomains) rather than a single business's own domain -
    # recorded with the full subdomain rather than collapsed to the bare
    # apex, so this one entry doesn't over/under-represent a shared host
    "unstives.com": ["__FULL_HOST__mardelupe.lachimenea.cl"],
}


def apex_of_hostname(hostname):
    parts = hostname.lower().lstrip("www.").split(".")
    # handle the small set of multi-part TLDs seen in this dataset explicitly
    multi_part_tlds = {"co.uk", "com.au", "com.br", "cn.com", "in.net", "us.com",
                        "com.co", "co.nz", "org.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in multi_part_tlds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


with open("11_clean_confirmed_sites.txt", encoding="utf-8") as f:
    clean_sites = set(line.strip().lower() for line in f if line.strip())

print(f"Before correction: {len(clean_sites)} sites")

removed = []
added = []
for wrong_apex, real_sites in WRONG_APEX_TO_REAL_SITES.items():
    if wrong_apex in clean_sites:
        clean_sites.discard(wrong_apex)
        removed.append(wrong_apex)
    for real_host in real_sites:
        if real_host.startswith("__FULL_HOST__"):
            real_apex = real_host[len("__FULL_HOST__"):].lower()
        else:
            real_apex = apex_of_hostname(real_host)
        if real_apex not in clean_sites:
            clean_sites.add(real_apex)
            added.append(real_apex)
        else:
            print(f"  note: {real_apex} (true site for {wrong_apex}) was already present in the clean list separately")

print(f"Removed (redirect-artifact misattributions): {removed}")
print(f"Added (true compromised sites): {added}")
print(f"After correction: {len(clean_sites)} sites")

with open("15_final_corrected_confirmed_sites.txt", "w", encoding="utf-8") as f:
    for s in sorted(clean_sites):
        f.write(s + "\n")

print()
print("Final corrected list saved to 15_final_corrected_confirmed_sites.txt")
