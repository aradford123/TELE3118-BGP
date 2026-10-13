# BGP AS Connectivity Lookup

Interrogates public, free, no-auth-required BGP/routing data sources to show how an
Autonomous System is connected: the prefixes it originates, its upstreams/peers/downstreams,
live AS-paths, RPKI status, and its declared routing policy.

Defaults to **AS23859 (UNSW)** but works for any ASN.

## Requirements

- [uv](https://docs.astral.sh/uv/) — that's it. Dependencies are declared inline in
  `bgp_lookup.py` (PEP 723) and `uv run` resolves/caches them automatically on first run;
  no venv or `pip install` step needed.

## Usage

```bash
# UNSW (AS23859), report printed to the console
uv run bgp_lookup.py

# Any other ASN
uv run bgp_lookup.py 15169

# Also write the full structured result to a JSON file
uv run bgp_lookup.py 23859 --json out.json

# Adjust per-request timeout (seconds, default 10)
uv run bgp_lookup.py 23859 --timeout 15
```

If a data source is unreachable or has no record for the ASN, the script prints a warning
for that section and continues — it won't abort the whole run.

## Data sources

| Source | What it provides |
|---|---|
| [RIPEstat](https://stat.ripe.net/) | AS holder/overview, announced IPv4/IPv6 prefixes, inferred neighbours (upstream/peer/downstream via RIS), live sample AS-paths from RIS route collectors, RPKI ROA validity |
| [CAIDA ASRank](https://asrank.caida.org/) | AS rank, organization, clique membership, inferred provider/peer/customer degree, customer cone size |
| [PeeringDB](https://www.peeringdb.com/) | IX/facility peering presence, peering policy, IRR AS-SET, if the network has a record |
| IRR/RPSL whois (`whois.radb.net`, falling back to `whois.apnic.net`) | Declared `route`/`route6` objects (origin AS per prefix) and the `aut-num` object's `import:`/`export:`/`mp-import:`/`mp-export:` lines — the actual declared BGP routing policy |

All lookups are read-only HTTP/whois queries against public infrastructure; no BGP session
or router access is required.

## Output sections

The console report (and equivalent JSON keys) covers:

1. AS Overview (`as_overview`)
2. Announced Prefixes (`announced_prefixes`)
3. Neighbours — upstreams/peers/downstreams (`asn_neighbours`)
4. Sample live AS-paths (`sample_paths`)
5. RPKI validation (`rpki_validation`)
6. CAIDA ASRank relationships (`caida_asrank`)
7. PeeringDB presence (`peeringdb`)
8. IRR declared routing policy (`irr_policy`)

## Notes / limitations

- `asn-neighbours`, `looking-glass`, and RPKI checks are sampled (a handful of prefixes),
  not exhaustive, to keep runtime and API load reasonable for large networks (e.g. AS15169
  has 1400+ prefixes).
- PeeringDB and CAIDA data reflect only what those third-party registries have on file —
  absence of a record isn't necessarily meaningful.
- The IRR whois lookup queries RADB (which mirrors many regional IRRs); if no `aut-num`
  policy is found there it falls back to APNIC's whois, appropriate for AU-registered ASNs
  like UNSW.

## Field Guide (teaching artifact)

`generate_field_guide.py` is a companion script, specific to the AS23859/AS7575/AS18062
case study, that renders the same kind of live data into an illustrated intro-to-BGP
teaching page (`field_guide_template.html` -> `as23859_field_guide.html`) rather than a
console report.

```bash
uv run generate_field_guide.py [--out as23859_field_guide.html] [--timeout 10]
```

In addition to RIPEstat/CAIDA/PeeringDB/whois, it cross-checks several facts against
[BGPKIT's `monocle`](https://bgpkit.com) CLI as a second, independent toolchain — AS
relationship inference (`as2rel`), ASPA/route-leak-protection adoption, and AS18062's own
ROA status — plus a MOAS (multi-origin) check via RIPEstat. `monocle` is optional
(`brew install bgpkit/tap/monocle`); every monocle-derived paragraph degrades gracefully
to an explanatory note if it isn't installed.

## BGP Explorer (generic, any ASN)

`bgp_explorer.py` is the generic sibling of the field guide: same illustrated HTML report
look (diagrams, chips, tables, terminal panels), but for **any** ASN you pass in, with every
paragraph generated from that ASN's own data rather than fixed prose about one case study.

```bash
uv run bgp_explorer.py 15169 [--out as15169_explorer.html] [--timeout 10] [--live-watch-seconds 10] [--json out.json]
```

The page leads with a **"Notable this run"** summary (RPKI gaps, IRR drift, MOAS hits, IPv6
absence) so the interesting findings are visible without reading all 10 sections. Covers: AS
overview and announced prefixes, neighbours and a topology diagram built from its actual top
neighbours, live sample AS-paths, RPKI validation, IRR declared policy (checked in **both**
directions -- a declared neighbour that's gone quiet, and a live neighbour that was never
declared at all), a MOAS check, CAIDA ASRank and PeeringDB presence (including actual IX
connections), and (with `monocle` installed) `as2rel` relationship inference -- targeted at
whichever neighbour the IRR check just flagged as undeclared, when there is one, rather than
just the highest-power link -- plus ASPA adoption, an **ASPA-vs-aut-num cross-check** (the
AS's own RFC 9582 provider list compared against its RPSL `import:` lines -- two of its own
declared sources checked against each other), and a bounded live RIS-Live capture.

RPKI severity is distinguished throughout: `invalid` (a real hijack signal) gets its own
red chip and wording, separate from the much more common, benign `unknown` (no ROA at all).

Each run is also compared against the last one recorded for that ASN (a small snapshot kept
in `--history-dir`, default `.explorer_history`, separate from `--cache-dir`): new/withdrawn
prefixes, new/gone neighbours, a topology change, or a newly-resolved IRR gap all show up as
**Trend** findings. Pass `--no-history` to skip this (no read or write of the snapshot).

Pass `--json out.json` to also write a structured summary (prefixes, neighbours with holder
names, RPKI/IRR/MOAS/ASPA results, CAIDA/PeeringDB/as2rel data, the current trend snapshot)
for programmatic use.

Run `uv run bgp_explorer.py --self-test` for its offline regression checks (no network calls).
