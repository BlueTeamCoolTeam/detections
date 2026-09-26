# Validation data -- agta-strikes-again

Raw output and tooling behind every figure in the
[blog post](https://blueteam.cool/posts/agta-strikes-again/) (panel-network section), published so the
numbers can be recomputed rather than taken on faith.

| File | Description |
|------|-------------|
| `revalidate_agta.py` | The re-validation script. Read-only: GETs the panel root and the version endpoint, plus a TLS handshake for the certificate. No authentication attempts, no POSTs, no payload downloads. |
| `agta_revalidation_results.json` | Per-domain output for all 77 candidates, collected 2026-09-09 UTC. |
| `agta_certs.json` | Issuer, subject and validity window for the 67 hosts serving the panel. |
| `index-Bzqpb2VG.js` | The panel frontend bundle as served on 2026-09-09 (sha256 `e18c0a18...975f956`). Public static asset; retained so the API-surface claims in the post can be checked. |

## Reproducing

`revalidate_agta.py` takes a JSON array of candidate records:

```json
[
  {"domain": "example.top", "ip": "192.0.2.1", "asn": "AS 64496", "country": "US"}
]
```

Only `domain` and `ip` are required; `asn` and `country` are carried through
into the output so recorded attribution can be compared against what the host
actually presents.

```bash
python revalidate_agta.py candidates.json out.json
```

The candidate set used here is recoverable from
`agta_revalidation_results.json` itself -- every record retains its
`domain`, `recorded_ip`, `asn` and `country` fields.

## Why this exists

The first collection pass carried four systematic bugs, each of which produced
a plausible-looking finding:

| Bug | The false finding it produced |
|-----|-------------------------------|
| Server header captured on 1 of 77 records | "These panels expose no server header" -- in fact IIS on 66 of 67 |
| TLS certificate fields never populated | "No certificate data available" -- in fact retrievable from all 67 |
| Version endpoint recorded null on 10 hosts | "The operator removed the endpoint on newer builds" -- in fact all 67 answer, with a different version string that the parser discarded |
| Bundle hash null on 1 host | A fourth bundle hash the parser did not recognise |

Two of those point the same way: a field that is null across almost every
record looks like a finding when it is actually a collection bug. The
separate lesson, documented in the post, is that probing shared-hosting
infrastructure by bare IP produces false negatives because no TLS SNI is sent
-- `curl --resolve` (which sets both the `Host` header and SNI) is what this
script uses instead.

## Classification

| Status | Meaning |
|--------|---------|
| `LIVE` | Domain resolves publicly **and** the host serves the Agta panel. 66 records. |
| `VHOST_ONLY` | Host serves the panel when the `Host` header is forced, but the domain does not resolve publicly. Provisioned but not victim-reachable. 1 record (`avanade.cc`). |
| `DEAD` | Neither. 10 records. |

Only `LIVE` records appear in `iocs.csv`.

## Enumerating the API surface

The frontend bundle is served unauthenticated, so the client-side API paths can
be read directly:

```bash
curl -sk --resolve planetvocalfortheteas.cyou:443:153.52.175.88 \
  https://planetvocalfortheteas.cyou/assets/index-Bzqpb2VG.js -o bundle.js
grep -oE '/api/[a-zA-Z0-9/_-]+' bundle.js | sort -u
```

This is the panel UI's view of the API, not proof of the full backend surface.
Endpoints the SPA never calls would not show up.
