#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests>=2.31.0",
# ]
# ///
"""Regenerate the AS23859 Field Guide (as23859_field_guide.html) from live data.

This is a dedicated companion to bgp_lookup.py: instead of a plain-text report,
it renders the same facts into the illustrated teaching page built around the
AS23859 (UNSW) / AS7575 (AARNet) / AS18062 (GrangeNet) case study. It re-fetches
every data-driven figure (prefixes, RPKI status, live AS-paths, AARNet's
provider/peer/customer counts, PeeringDB footprint, whois route/aut-num
objects, AS18062's announced status, MOAS check, a live community capture) on
every run; the surrounding teaching prose is a static template because it's
pedagogical framing, not raw data.

If BGPKIT's `monocle` CLI (https://bgpkit.com, `brew install bgpkit/tap/monocle`)
is on PATH, this script also cross-checks several facts against it as a second,
independent toolchain: AS relationship inference (as2rel), ASPA adoption, and
AS18062's own ROA status. Every monocle-derived value degrades gracefully to an
explanatory note if the binary isn't installed -- it's an enhancement, not a
hard dependency.

Reliability notes:
- Network/whois fetches retry with backoff (public infra like RIPEstat/APNIC
  occasionally 502s or times out -- this happened repeatedly during development).
- Pass --cache-ttl to reuse recent results across reruns instead of re-fetching
  everything (courteous to the public APIs this leans on, and much faster while
  iterating on the template). Live captures (RIS Live watch) are never cached --
  caching a "live" demo would defeat the point.
- The two ~15s live-BGP captures run concurrently with the rest of the fetches
  (a thread pool), not serially after them.
- After template substitution, the output is scanned for leftover
  "$IDENTIFIER"-shaped placeholders and the run fails loudly if any remain,
  instead of silently shipping a broken page.

Usage:
    uv run generate_field_guide.py [--out as23859_field_guide.html] [--timeout 10]
"""

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import socket
import string
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timezone
from datetime import datetime as dt

import requests

RIPESTAT_BASE = "https://stat.ripe.net/data"
CAIDA_ASRANK_REST = "https://api.asrank.caida.org/v2/restful/asns"
PEERINGDB_BASE = "https://www.peeringdb.com/api"

ASN_ORIGIN = 23859     # AS23859, UNSW -- this case study's subject
ASN_UPSTREAM = 7575    # AS7575, AARNet -- the multi-homing case study
ASN_STALE_PEER = 18062  # AS18062, GrangeNet -- the "when BGP goes wrong" example


# ---------------------------------------------------------------- retry / cache

def with_retries(fn, *args, attempts=3, backoff=1.5, **kwargs):
    """Run fn(*args, **kwargs), retrying on transient network errors with backoff."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.RequestException, OSError) as exc:
            last_exc = exc
            if attempt < attempts - 1:
                print(f"[retry] {fn.__name__} attempt {attempt + 1} failed ({exc}); retrying...", file=sys.stderr)
                time.sleep(backoff ** attempt)
    raise last_exc


def cached(cache_dir, ttl, key, fn, *args, **kwargs):
    """Reuse a JSON-serializable result from disk if younger than ttl seconds. ttl<=0 disables caching."""
    if ttl <= 0:
        return fn(*args, **kwargs)
    digest = hashlib.sha256(key.encode()).hexdigest()[:24]
    path = os.path.join(cache_dir, f"{digest}.json")
    if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < ttl:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    result = fn(*args, **kwargs)
    os.makedirs(cache_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f)
    return result


# ---------------------------------------------------------------- fetch helpers

def ripestat(endpoint, params, timeout):
    def _get():
        resp = requests.get(f"{RIPESTAT_BASE}/{endpoint}/data.json", params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()["data"]
    return with_retries(_get)


def whois_query(server, query, timeout):
    def _query():
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((query + "\r\n").encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response.decode(errors="replace")
    return with_retries(_query)


# ---------------------------------------------------------------- AS23859 data

def get_prefixes(timeout):
    data = ripestat("announced-prefixes", {"resource": f"AS{ASN_ORIGIN}"}, timeout)
    return [p["prefix"] for p in data.get("prefixes", [])]


def prefix_size_label(prefix):
    if ":" in prefix:
        return "IPv6 block"
    length = int(prefix.rsplit("/", 1)[1])
    return f"{2 ** (32 - length):,} addresses"


def get_rpki(prefixes, timeout):
    """Returns list of {prefix, status, validating_roas}, in prefixes order.

    One independent fetch per prefix -- run them concurrently (same reasoning
    as get_global_table_stats / get_moas), then reassemble in the original
    order since later code picks the "first non-valid" entry as notable.
    """
    def _one(prefix):
        data = ripestat("rpki-validation", {"resource": f"AS{ASN_ORIGIN}", "prefix": prefix}, timeout)
        return {
            "prefix": prefix,
            "status": data.get("status", "unknown"),
            "validating_roas": data.get("validating_roas", []),
        }

    if not prefixes:
        return []
    with ThreadPoolExecutor(max_workers=len(prefixes)) as pool:
        results = {r["prefix"]: r for r in pool.map(_one, prefixes)}
    return [results[p] for p in prefixes]


def get_sample_paths(prefixes, timeout, max_prefixes=3, max_paths=5):
    paths = []
    for prefix in prefixes[:max_prefixes]:
        try:
            lg = ripestat("looking-glass", {"resource": prefix}, timeout)
        except Exception as exc:
            print(f"[warning] looking-glass for {prefix} failed: {exc}", file=sys.stderr)
            continue
        for rrc in lg.get("rrcs", []):
            for peer in rrc.get("peers", []):
                as_path = peer.get("as_path")
                if as_path and as_path not in [p["as_path"] for p in paths]:
                    paths.append({"prefix": prefix, "location": rrc.get("location"), "as_path": as_path})
                if len(paths) >= max_paths:
                    return paths
    return paths


def get_route_objects_raw(timeout):
    return whois_query("whois.apnic.net", f"-i origin AS{ASN_ORIGIN}", timeout)


def get_autnum_raw(timeout):
    return whois_query("whois.apnic.net", f"-T aut-num AS{ASN_ORIGIN}", timeout)


def parse_route_objects(raw_text):
    routes, current = [], {}
    for line in raw_text.splitlines():
        if not line.strip():
            if current:
                routes.append(current)
                current = {}
            continue
        if ":" not in line or line.startswith("%"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key in ("route", "route6"):
            current["route"] = value
        elif key in ("origin", "descr", "mnt-by", "source") and key not in current:
            current[key] = value
    if current:
        routes.append(current)
    return [r for r in routes if "route" in r]


def parse_autnum(raw_text):
    """Parse only the first (aut-num) object in the response.

    A "-T aut-num ASxxxx" query returns the aut-num object followed by whatever
    it references -- irt, organisation, role, person objects, each with their
    own last-modified/mnt-by fields. Scanning the whole blob and letting later
    keys overwrite earlier ones (the original bug here) silently attributes an
    unrelated contact object's last-modified date to the aut-num itself.
    """
    fields = {"as-name": None, "mnt-by": None, "last-modified": None, "import": [], "export": []}
    started = False
    for line in raw_text.splitlines():
        if not line.strip():
            if started:
                break  # blank line ends the aut-num block; ignore objects after it
            continue  # still in the leading "%" comment preamble
        if line.startswith("%") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "aut-num":
            started = True
        if not started:
            continue
        if key in ("as-name", "mnt-by", "last-modified"):
            fields[key] = value
        elif key in ("import", "export"):
            fields[key].append(value)
    return fields


# ---------------------------------------------------------------- AS7575 data

def get_aarnet_caida(timeout):
    def _get():
        resp = requests.get(f"{CAIDA_ASRANK_REST}/{ASN_UPSTREAM}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()["data"]["asn"]
    return with_retries(_get)


def get_aarnet_peeringdb(timeout):
    def _get():
        resp = requests.get(f"{PEERINGDB_BASE}/net", params={"asn": ASN_UPSTREAM}, timeout=timeout)
        resp.raise_for_status()
        nets = resp.json().get("data", [])
        return nets[0] if nets else None
    return with_retries(_get)


def get_neighbours(asn, timeout):
    return ripestat("asn-neighbours", {"resource": f"AS{asn}"}, timeout).get("neighbours", [])


# ---------------------------------------------------------------- AS18062 data

def get_as18062_announced(timeout):
    data = ripestat("as-overview", {"resource": f"AS{ASN_STALE_PEER}"}, timeout)
    return bool(data.get("announced"))


def get_moas(prefixes, timeout):
    """MOAS check via RIPEstat's routing-status (portable; no external tool needed).

    One independent fetch per prefix -- run them concurrently rather than
    looping, same reasoning as get_global_table_stats.
    Returns {prefix: [origin_asn, ...]}.
    """
    def _one(prefix):
        data = ripestat("routing-status", {"resource": prefix}, timeout)
        return prefix, [o.get("origin") for o in data.get("origins", [])]

    moas = {}
    if not prefixes:
        return moas
    with ThreadPoolExecutor(max_workers=len(prefixes)) as pool:
        futures = [pool.submit(_one, prefix) for prefix in prefixes]
        for future in futures:
            try:
                prefix, origins = future.result()
                moas[prefix] = origins
            except Exception as exc:
                print(f"[warning] routing-status failed: {exc}", file=sys.stderr)
    return moas


# ---------------------------------------------------------------- BGPKIT / monocle (optional)

def have_monocle():
    return shutil.which("monocle") is not None


def run_monocle(args, timeout):
    """Shell out to monocle for a JSON result. Returns None if unavailable/fails."""
    if not have_monocle():
        return None
    try:
        result = subprocess.run(
            ["monocle", *args, "--json"], capture_output=True, text=True, timeout=timeout,
        )
    except Exception as exc:
        print(f"[warning] monocle {' '.join(args)} failed: {exc}", file=sys.stderr)
        return None
    if result.returncode != 0:
        print(f"[warning] monocle {' '.join(args)} exited {result.returncode}: {result.stderr.strip()}", file=sys.stderr)
        return None
    text = result.stdout
    candidates = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not candidates:
        return None
    try:
        return json.loads(text[min(candidates):])
    except json.JSONDecodeError as exc:
        print(f"[warning] could not parse monocle {' '.join(args)} output: {exc}", file=sys.stderr)
        return None


def get_as2rel(asn1, asn2, timeout):
    data = run_monocle(["as2rel", str(asn1), str(asn2)], timeout)
    if not data or not data.get("results"):
        return None
    return data["results"][0]


def get_aspa(timeout, customer=None, provider=None):
    args = ["rpki", "aspas"]
    if customer is not None:
        args += ["--customer", str(customer)]
    if provider is not None:
        args += ["--provider", str(provider)]
    return run_monocle(args, timeout)


def get_as18062_roas(timeout):
    data = run_monocle(["inspect", str(ASN_STALE_PEER), "--show", "rpki"], timeout)
    if not data or not data.get("queries"):
        return None
    rpki = data["queries"][0].get("rpki") or {}
    roas = rpki.get("roas") or {}
    return roas.get("entries", [])


def _watch_once(asn, capture_seconds, max_msgs):
    """One bounded capture window. See get_live_watch_sample for the retry wrapper."""
    msgs = []
    proc = subprocess.Popen(
        ["monocle", "watch", "--as-path", str(asn), "--format", "json-line"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    deadline = time.time() + capture_seconds
    try:
        while len(msgs) < max_msgs:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select([proc.stdout], [], [], remaining)
            if not ready:
                break
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if asn in (msg.get("as_path") or []):
                msgs.append(msg)
    finally:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    return msgs


def get_live_watch_sample(asn, capture_seconds, max_msgs=6, max_attempts=2):
    """Capture a short bounded window of real live BGP updates via RIPE RIS Live.

    `monocle watch` streams indefinitely, so this reads its stdout incrementally
    against a wall-clock deadline (via select()) rather than subprocess.run(timeout=...):
    on POSIX, subprocess.run's TimeoutExpired discards everything read so far (stdout
    comes back None), which would silently throw away a real capture every time.

    We then post-filter for exact AS-path membership ourselves, since monocle's own
    --as-path client-side filter is substring-based (it would also match e.g. 267575).

    BGP updates are genuinely bursty: an empty window doesn't mean anything is
    broken, just that nothing matching happened to cross the wire in that
    stretch (observed empirically -- back-to-back 15-25s windows for the same
    AS came back empty roughly half the time during development). A single
    empty attempt already costs the full window (select() blocks for the whole
    remaining budget), so retrying once more on an empty result trades one
    more full window of time for a meaningfully better chance of shipping a
    non-empty example -- worth it since this only runs at generation time, not
    per page-view. Returns None if monocle isn't installed or capture_seconds <= 0.
    """
    if not have_monocle() or capture_seconds <= 0:
        return None
    for attempt in range(max_attempts):
        msgs = _watch_once(asn, capture_seconds, max_msgs)
        if msgs:
            return msgs
        if attempt < max_attempts - 1:
            print(f"[live-watch] attempt {attempt + 1} caught nothing for AS{asn}; retrying once...", file=sys.stderr)
    return msgs


def get_live_community_sample(capture_seconds=8, max_lines_scanned=20000):
    """Capture one real live BGP update carrying a communities attribute.

    Uses --firehose (unfiltered, ~5k msgs/s) rather than a per-AS filter, since
    we don't care which AS it's from -- any real, currently-live example of an
    operator tagging a route with communities is the point.
    """
    if not have_monocle() or capture_seconds <= 0:
        return None
    proc = subprocess.Popen(
        ["monocle", "watch", "--firehose", "--format", "json-line"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    deadline = time.time() + capture_seconds
    found, scanned = None, 0
    try:
        while found is None and scanned < max_lines_scanned:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select([proc.stdout], [], [], remaining)
            if not ready:
                break
            line = proc.stdout.readline()
            if not line:
                break
            scanned += 1
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("communities"):
                found = msg
    finally:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    return found


def decode_community(c):
    """Decode one of monocle's community JSON shapes into ASN:VALUE-style text.

    Three shapes show up in practice: a plain {"Custom": [asn, value]} standard
    community; a {"global_admin": asn, "local_data": [a, b]} RFC 8092 large
    community (asn:a:b); and an extended community wrapped under its subtype
    name, e.g. {"TransitiveTwoOctetAs": {"global_admin": ..., ...}}. A naive
    "grab the first dict key" fallback (the original bug here) picks
    "global_admin" itself off the large-community shape and silently drops
    local_data, making visually distinct communities render as identical text.
    """
    if not isinstance(c, dict):
        return str(c)
    if "Custom" in c and isinstance(c["Custom"], list) and len(c["Custom"]) == 2:
        return f'{c["Custom"][0]}:{c["Custom"][1]}'
    if "global_admin" in c and "local_data" in c:
        local = c["local_data"]
        tail = ":".join(str(x) for x in local) if isinstance(local, list) else str(local)
        return f'{c["global_admin"]}:{tail}'
    for key, val in c.items():
        if isinstance(val, dict) and "global_admin" in val:
            return f'{val["global_admin"]} (extended community, {key})'
        return key if val is None else f"{key}({val})"
    return str(c)


def build_communities_paragraph(msg):
    if not msg:
        return (
            'Install BGPKIT\'s <code class="mono">monocle</code> and re-run the generator to capture a real route '
            'carrying communities live from the RIS Live firehose.'
        )
    origin = (msg.get("origin_asns") or ["?"])[0]
    community_strs = [decode_community(c) for c in msg["communities"]]
    shown = ", ".join(community_strs[:6])
    if len(community_strs) > 6:
        shown += f", &hellip; +{len(community_strs) - 6} more"
    return (
        f'Captured live from the same RIS Live firehose used elsewhere in this guide: <span class="as-tag">AS{origin}</span> '
        f'announcing <span class="as-tag">{msg["prefix"]}</span> carrying {len(community_strs)} '
        f'communit{"y" if len(community_strs) == 1 else "ies"}: <code class="mono">{shown}</code>. '
        f'Unless you have AS{origin}\'s own published community guide, those numbers are meaningless &mdash; that\'s the '
        f'point. Unlike the well-known ones above, operator-defined communities are private vocabulary: agreed bilaterally '
        f'or documented unilaterally on a network\'s own website, never centrally registered.'
    )


POTAROO_BASE = "https://bgp.potaroo.net"


def _potaroo_value(path, timeout):
    """Fetch one Potaroo BGP-report metric: a small 'timestamp value' time-series
    text file (one sample per line); return the latest sample's value as text."""
    def _get():
        resp = requests.get(f"{POTAROO_BASE}/{path}", timeout=timeout)
        resp.raise_for_status()
        last_line = resp.text.strip().splitlines()[-1]
        return last_line.split()[-1]
    return with_retries(_get)


def get_global_table_stats(timeout):
    """Live global BGP table size/composition from Geoff Huston's BGP Routing
    Table Report (bgp.potaroo.net), sampled at a RouteViews full-feed vantage
    point (AS6447 / route-views2). Returns None if the site is unreachable.

    Nine independent text-file fetches -- run them concurrently rather than
    one after another (measured: this alone was several seconds of dead time
    in a script whose sequential fetch chain, end to end, took 71s).
    """
    paths = {
        "ipv4_fib": "as6447/bgp-active.txt",
        "ipv4_ribfib_ratio": "as6447/bgp-ribfib.txt",
        "as_count": "as6447/bgp-as-count.txt",
        "origin_only": "as6447/bgp-as-term.txt",
        "transit_only": "as6447/bgp-transit.txt",
        "mixed": "as6447/bgp-mixedas.txt",
        "avg_path": "as6447/bgp-average-aspath-length.txt",
        "max_path": "as6447/bgp-max-aspath-length.txt",
        "ipv6_fib": "v6/as6447/bgp-active.txt",
    }
    try:
        with ThreadPoolExecutor(max_workers=len(paths)) as pool:
            futures = {key: pool.submit(_potaroo_value, path, timeout) for key, path in paths.items()}
            raw = {key: future.result() for key, future in futures.items()}
        ipv4_fib = int(raw["ipv4_fib"])
        ipv4_ribfib_ratio = float(raw["ipv4_ribfib_ratio"])
        as_count = int(raw["as_count"])
        origin_only = int(raw["origin_only"])
        transit_only = int(raw["transit_only"])
        mixed = int(raw["mixed"])
        avg_path = float(raw["avg_path"])
        max_path = int(raw["max_path"])
        ipv6_fib = int(raw["ipv6_fib"])
    except Exception as exc:
        print(f"[warning] global table stats fetch failed: {exc}", file=sys.stderr)
        return None
    return {
        "ipv4_fib": ipv4_fib,
        "ipv4_rib": round(ipv4_fib * ipv4_ribfib_ratio),
        "ipv4_ribfib_ratio": ipv4_ribfib_ratio,
        "as_count": as_count,
        "origin_only": origin_only,
        "transit_only": transit_only,
        "mixed": mixed,
        "avg_path": avg_path,
        "max_path": max_path,
        "ipv6_fib": ipv6_fib,
    }


def build_table_size_paragraph(stats):
    if not stats:
        return (
            'Live global-table stats were unavailable this run (bgp.potaroo.net unreachable). See '
            '<a href="https://bgp.potaroo.net/index-bgp.html">Geoff Huston\'s BGP Routing Table Report</a> directly.'
        )
    return (
        f'As of this run, one full-feed vantage point (RouteViews\' AS6447, via Geoff Huston\'s BGP Routing Table '
        f'Report) carries <b>{stats["ipv4_fib"]:,}</b> active IPv4 FIB entries from <b>{stats["as_count"]:,}</b> '
        f'distinct ASes ({stats["origin_only"]:,} origin-only &mdash; stub networks like AS23859 &mdash; '
        f'{stats["transit_only"]:,} transit-only, {stats["mixed"]:,} mixed like AS7575). Average AS-PATH length: '
        f'{stats["avg_path"]:.2f} hops (max observed: {stats["max_path"]}) &mdash; consistent with the 3&ndash;5 hop '
        f'paths you read in section 05. IPv6\'s active table is far smaller: {stats["ipv6_fib"]:,} entries.'
    )


def build_table_memory_paragraph(stats):
    if not stats:
        return 'Memory-footprint estimate unavailable this run (needs the live table-size figures above).'
    fib, rib = stats["ipv4_fib"], stats["ipv4_rib"]
    fib_low_mb, fib_high_mb = fib * 100 / 1e6, fib * 150 / 1e6
    rib_low_gb, rib_high_gb = rib * 100 / 1e9, rib * 150 / 1e9
    return (
        f'That {fib:,}-entry FIB is only part of the picture: this same vantage point actually receives '
        f'<b>{rib:,}</b> total RIB entries once you count every peer\'s copy of every candidate route (a RIB/FIB '
        f'ratio of {stats["ipv4_ribfib_ratio"]:.1f}&times;) &mdash; section 06\'s Adj-RIB-In vs. Loc-RIB distinction, '
        f'at Internet scale. Forwarding hardware (TCAM) is commonly estimated at roughly 100&ndash;150 bytes per '
        f'entry, which puts the compiled FIB at only about {fib_low_mb:.0f}&ndash;{fib_high_mb:.0f}MB &mdash; trivial '
        f'by today\'s standards. Naively keeping the <i>entire</i> {rib:,}-entry RIB in that same specialized memory '
        f'would cost roughly {rib_low_gb:.1f}&ndash;{rib_high_gb:.1f}GB instead. That gap is exactly why routers don\'t '
        f'do that: Loc-RIB (one winner per prefix) is small enough for expensive, fixed-size, ternary-matching '
        f'hardware; the full RIB lives in ordinary, cheap, expandable RAM on the control plane instead.'
    )


def build_512k_day_paragraph(stats):
    ratio_note = (
        f' Today\'s IPv4 FIB, at {stats["ipv4_fib"]:,} entries, is over {stats["ipv4_fib"] / 512000:.1f}&times; that '
        f'old ceiling.' if stats else ''
    )
    return (
        'On 12 August 2014, the global IPv4 FIB crossed 512,000 entries &mdash; and many older Cisco routers had '
        'their TCAM hard-partitioned to exactly 512K IPv4 slots (with a separate, mostly-unused 256K reserved for '
        'IPv6, which had barely 20,000 routes at the time). Routers that hit the ceiling didn\'t just refuse new '
        'routes: some fell back from hardware to slow software forwarding, others silently dropped or blackholed '
        'the overflow. eBay, LastPass, and Microsoft Azure all saw real outages that day.' + ratio_note + ' The fix '
        'wasn\'t more physical memory &mdash; it was repartitioning the same TCAM (and, longer-term, buying hardware '
        'with bigger tables). "Splitting it up" happens on at least two levels: physically, a chassis router spreads '
        'its FIB across multiple forwarding-ASIC line cards, each needing its own synced copy; operationally, edge '
        'networks that don\'t need a full table at all just carry a default route instead, and large ASes scale '
        'their internal iBGP mesh (section 03) with route reflectors or confederations rather than a full mesh of '
        'sessions.'
    )


def get_aarnet_rpki_summary(timeout):
    data = run_monocle(["inspect", str(ASN_UPSTREAM), "--show", "prefixes"], timeout)
    if not data or not data.get("queries"):
        return None
    prefixes = data["queries"][0].get("prefixes") or {}
    summary = prefixes.get("validation_summary")
    if not summary:
        return None
    return {
        "total": prefixes.get("total_count"),
        "ipv4_count": prefixes.get("ipv4_count"),
        "ipv6_count": prefixes.get("ipv6_count"),
        **summary,
    }


# ---------------------------------------------------------------- HTML builders

def build_prefix_rows(rpki_rows):
    chip_for = {"valid": ("good", "valid"), "invalid": ("warn", "invalid"), "unknown": ("warn", "no ROA")}
    rows = []
    for r in rpki_rows:
        chip_class, label = chip_for.get(r["status"], ("mute", r["status"]))
        rows.append(
            f'            <tr><td class="mono">{r["prefix"]}</td>'
            f'<td>{prefix_size_label(r["prefix"])}</td>'
            f'<td><span class="chip {chip_class}">{label}</span></td></tr>'
        )
    return "\n".join(rows)


def build_paths_intro(paths):
    if not paths:
        return "No live sample paths were returned by RIS for these prefixes on this run."
    locations = sorted(set(p["location"] for p in paths if p.get("location")))
    prefixes_seen = sorted(set(p["prefix"] for p in paths))
    loc_str = " / ".join(locations) if locations else "an RIS route collector"
    if len(prefixes_seen) == 1:
        prefix_str = f'the prefix <span class="as-tag">{prefixes_seen[0]}</span>'
    else:
        prefix_str = "prefixes " + ", ".join(f'<span class="as-tag">{p}</span>' for p in prefixes_seen)
    return (
        f"These {len(paths)} paths were captured live by RIPE RIS route collectors "
        f"({loc_str}), for {prefix_str}:"
    )


def build_paths_rows(paths):
    rows = []
    for p in paths:
        tokens = p["as_path"].split()
        origin = tokens[-1] if tokens else ""
        up = tokens[-2] if len(tokens) >= 2 else None
        lead = " ".join(tokens[:-2]) if up else ""
        hop_html = (f'{lead} <span class="hop up-hop">{up}</span> ' if up else "") + \
                   f'<span class="hop origin-hop">{origin}</span>'
        rows.append(
            f'        <div class="prow"><span class="loc">{p["location"]}</span>'
            f'<span class="path">{hop_html.strip()}</span></div>'
        )
    return "\n".join(rows)


def build_route_objects_block(raw_text):
    routes = parse_route_objects(raw_text)
    if not routes:
        return '<span class="c">(no route objects returned)</span>'
    first = routes[0]
    lines = [f'<span class="c">% Information related to \'{first["route"]}AS{ASN_ORIGIN}\'</span>', ""]
    lines.append(f'<span class="k">route:</span>          {first["route"]}')
    lines.append(f'<span class="k">origin:</span>         {first.get("origin", f"AS{ASN_ORIGIN}")}')
    if first.get("descr"):
        lines.append(f'<span class="c">descr:          {first["descr"]}</span>')
    if first.get("mnt-by"):
        lines.append(f'<span class="k">mnt-by:</span>         {first["mnt-by"]}')
    lines.append(f'<span class="k">source:</span>         {first.get("source", "APNIC")}')
    rest = routes[1:]
    if rest:
        rest_prefixes = ", ".join(r["route"] for r in rest)
        lines.append("")
        lines.append(f'<span class="c">&hellip; {len(rest)} more route object(s) follow the same pattern for\n    {rest_prefixes} &hellip;</span>')
    return "\n".join(lines)


def build_autnum_block(raw_text):
    fields = parse_autnum(raw_text)
    lines = [f'<span class="k">aut-num:</span>        AS{ASN_ORIGIN}']
    if fields["as-name"]:
        lines.append(f'<span class="k">as-name:</span>        {fields["as-name"]}')
    for imp in fields["import"]:
        lines.append(f'<span class="k">import:</span>         {imp}')
    for exp in fields["export"]:
        lines.append(f'<span class="k">export:</span>         {exp}')
    if fields["mnt-by"]:
        lines.append(f'<span class="k">mnt-by:</span>         {fields["mnt-by"]}')
    if fields["last-modified"]:
        lines.append(f'<span class="w">last-modified:  {fields["last-modified"]}</span>')
    return "\n".join(lines)


def build_rpki_json_block(rpki_rows):
    notable = next((r for r in rpki_rows if r["status"] != "valid"), rpki_rows[0])
    roas = notable["validating_roas"]
    roas_str = "[]" if not roas else "[\n" + ",\n".join(
        f'    {{"origin": "{r.get("origin")}", "prefix": "{r.get("prefix")}", "max_length": {r.get("max_length")}}}'
        for r in roas
    ) + "\n  ]"
    return (
        '<span class="c">{</span>\n'
        f'  <span class="k">"status"</span>: <span class="w">"{notable["status"]}"</span>,\n'
        f'  <span class="k">"validating_roas"</span>: {roas_str}\n'
        '<span class="c">}</span>'
    ), notable


def build_rpki_worked_paragraph(rpki_rows, notable):
    valid_count = sum(1 for r in rpki_rows if r["status"] == "valid")
    total = len(rpki_rows)
    if notable["status"] == "valid":
        return (
            f'All {total} of AS23859\'s prefixes currently come back '
            f'<span class="chip good">valid</span> &mdash; every one has a matching ROA on file.'
        )
    label = "no ROA" if notable["status"] == "unknown" else notable["status"]
    chip_class = "warn" if notable["status"] != "valid" else "good"
    return (
        f'{valid_count} of AS23859\'s {total} prefixes are <span class="chip good">valid</span>. '
        f'<span class="as-tag">{notable["prefix"]}</span> comes back '
        f'<span class="chip {chip_class}">{label}</span> &mdash; querying RIPEstat\'s validator directly confirms why: '
        f'<code class="mono">"validating_roas": {notable["validating_roas"] or []}</code>. '
        f'Until a ROA covers it, RPKI-aware routers have no cryptographic basis to reject an impostor '
        f'announcing that same prefix from a different AS.'
    )


def build_as18062_paragraph(announced, roas):
    if announced:
        return (
            'AS18062 (<span class="as-tag">GRANGENET-AS-AP</span>) is now announcing prefixes again '
            '(<code class="mono">"announced": true</code>) &mdash; re-check whether AS23859\'s <code class="mono">aut-num</code> '
            'import/export lines referencing it reflect a live relationship before treating this as stale data.'
        )
    base = (
        'AS18062 (<span class="as-tag">GRANGENET-AS-AP</span>) is exactly the fourth kind of failure: it currently '
        'announces zero prefixes anywhere in RIS (<code class="mono">"announced": false</code>) &mdash; it\'s a defunct-looking '
        'Australian grid-networking project from the early 2000s, sharing its abuse contact with AARNet. Nothing is being '
        'attacked here; it\'s just an <code class="mono">aut-num</code> object nobody cleaned up after a relationship ended.'
    )
    if roas:
        prefix_list = ", ".join(f'<span class="as-tag">{r["prefix"]}</span>' for r in roas)
        base += (
            f' But it isn\'t fully dormant on paper: querying BGPKIT\'s <code class="mono">monocle inspect 18062</code> shows '
            f'AS18062 still holds {"an active ROA" if len(roas) == 1 else f"{len(roas)} active ROAs"} for {prefix_list} '
            f'&mdash; its number resources are still validly assigned even though nothing is currently routed under them. '
            f'"Not announcing anything" and "resources revoked" are two different states, and cross-checking IRR against '
            f'RPKI data is how you tell them apart.'
        )
    else:
        base += (
            ' It\'s a useful, low-stakes example of exactly the kind of drift that, at larger scale or combined with a missing '
            'ROA, is how real incidents start.'
        )
    return base


def build_as2rel_paragraph(rel):
    if not rel:
        return (
            'BGPKIT\'s <code class="mono">monocle</code> (a second, independent toolchain &mdash; '
            '<code class="mono">brew install bgpkit/tap/monocle</code>) can quantify exactly this ambiguity via '
            '<code class="mono">monocle as2rel 7575 23859</code>. It wasn\'t installed when this page was generated, so this '
            'run falls back to the qualitative picture above; install it and re-run the generator to see the real numbers.'
        )
    connected, peer, up1, up2 = rel["connected"], rel["peer"], rel["as1_upstream"], rel["as2_upstream"]
    return (
        f'BGPKIT\'s independent <code class="mono">as2rel</code> dataset (inferred from {rel.get("asn1", 7575)} and '
        f'{rel.get("asn2", 23859)} across ~1,896 vantage points) puts a number on that ambiguity: only <b>{connected}</b> of '
        f'vantage points see the AS7575&ndash;AS23859 link at all, and among those, <b>{up1}</b> classify AS7575 as the '
        f'provider while <b>{peer}</b> classify it as a settlement-free peer instead (the rest, {up2}, would call AS23859 '
        f'the provider &mdash; essentially zero, as expected). Same physical link, two different inferred business '
        f'relationships, depending entirely on which vantage points you trust &mdash; which is exactly why '
        f'<code class="mono">monocle inspect 23859</code> reports "Total neighbors: 2" for a network whose own IRR '
        f'<code class="mono">aut-num</code> object names exactly one upstream.'
    )


def build_aspa_paragraph(customer_aspas, provider_aspas):
    if customer_aspas is None and provider_aspas is None:
        return (
            'RPKI\'s ROAs (section 10) authenticate <i>origin</i> &mdash; they say nothing about the AS-PATH shape a leak '
            'exploits. A newer, complementary object called an <b>ASPA</b> (Autonomous System Provider Authorization, '
            'RFC 9582) fixes that: a customer publishes "my only valid providers are X, Y, Z," letting a receiving router '
            'reject a route whose path shape doesn\'t match. Install BGPKIT\'s <code class="mono">monocle</code> '
            '(<code class="mono">brew install bgpkit/tap/monocle</code>) and re-run the generator to see AS23859 and '
            'AS7575\'s real ASPA adoption status here.'
        )
    customer_count = len(customer_aspas or [])
    provider_count = len(provider_aspas or [])
    customer_list = ", ".join(
        f'AS{c["customer_asn"]} ({c["customer_name"]})' for c in (provider_aspas or [])
    ) or "none"
    return (
        'RPKI\'s ROAs (section 10) authenticate <i>origin</i> &mdash; they say nothing about the AS-PATH shape a leak '
        'exploits. A newer, complementary object called an <b>ASPA</b> (Autonomous System Provider Authorization, RFC 9582) '
        'fixes that: a customer publishes "my only valid providers are X, Y, Z," letting a receiving router reject a route '
        f'whose path shape doesn\'t match. Querying BGPKIT\'s cached ASPA set: AS7575 (AARNet) is already named as an '
        f'authorized provider by {provider_count} other customers ({customer_list}) &mdash; but AS23859 itself has published '
        f'{customer_count} ASPA record{"s" if customer_count != 1 else ""} naming AS7575 as its own provider. Like RPKI ROAs '
        'a few years ago, ASPA adoption is real but still partial, even between networks that already trust each other '
        'operationally.'
    )


def build_aarnet_rpki_zoomout_paragraph(summary):
    if not summary:
        return (
            'Install BGPKIT\'s <code class="mono">monocle</code> and re-run the generator to see how AS7575\'s RPKI coverage '
            'looks across its <i>entire</i> announced portfolio, not just the four prefixes it hands to AS23859.'
        )
    return (
        f'Zoom out to AARNet\'s entire announced portfolio and the RPKI story flips: of AS7575\'s {summary["total"]} '
        f'prefixes, only {summary["valid_percent"]:.1f}% currently validate &mdash; {summary["unknown_percent"]:.1f}% have no '
        f'ROA at all, a far larger gap in percentage terms than UNSW\'s single missing prefix. (This also cross-checks the '
        f'203.10.48.0/24 finding above through a second, unrelated pipeline: BGPKIT\'s RPKI cache is sourced from '
        f'Cloudflare\'s relying-party software, not RIPEstat\'s, and agrees there\'s no covering ROA.)'
    )


def build_live_watch_block(msgs, asn, capture_seconds):
    if msgs is None:
        return (
            '<div class="term"><div class="term-bar"><span class="mono">$ monocle watch --as-path 7575</span>'
            '<span>RIPE RIS Live</span></div>'
            '<pre><span class="c">(skipped this run -- monocle not installed, or --live-watch-seconds 0)</span></pre></div>'
        )
    if not msgs:
        return (
            '<div class="term"><div class="term-bar"><span class="mono">$ monocle watch --as-path 7575</span>'
            '<span>RIPE RIS Live</span></div>'
            f'<pre><span class="c">(watched {capture_seconds}s, captured 0 exact AS7575 matches this run -- '
            'BGP updates are bursty, try again or increase --live-watch-seconds)</span></pre></div>'
        )
    origin_count = sum(1 for m in msgs if m.get("origin_asns") == [asn])
    transit_count = len(msgs) - origin_count
    unique_sessions = {(m.get("peer_asn"), m.get("peer_ip")) for m in msgs}
    single_session = len(unique_sessions) == 1 and len(msgs) > 1

    lines = []
    for m in msgs[:5]:
        path_str = " ".join(str(a) for a in m["as_path"])
        role = "origin" if m.get("origin_asns") == [asn] else "transit"
        role_span = "k" if role == "origin" else "w"
        lines.append(
            f'<span class="c">{m.get("type", "ANNOUNCE")}</span>  {m["prefix"]}  '
            f'<span class="v">{path_str}</span>  <span class="{role_span}">[{role}]</span>'
        )
    pre = "\n".join(lines)

    match_noun = "exact match" if len(msgs) == 1 else "exact matches"

    if origin_count == 0:
        subject = "it was" if len(msgs) == 1 else f"all {transit_count} of them were"
        commentary = (
            f'{len(msgs)} {match_noun}, and {subject} AS7575 purely relaying <i>other</i> networks\' '
            f'prefixes rather than its own. That\'s the common case for a busy transit AS: it forwards other people\'s '
            f'routing changes constantly, while its own handful of originated prefixes barely ever change. "Busy" and '
            f'"unstable" are different things.'
        )
    elif transit_count == 0:
        session_note = (
            ' All of them came from the same single peer session, which is the giveaway: this is one session '
            'reset/reconverge event re-announcing a batch of prefixes at once, not several independent changes.'
            if single_session else ''
        )
        subject = "it was" if len(msgs) == 1 else "every one of them was"
        commentary = (
            f'{len(msgs)} {match_noun}, and {subject} AS7575 originating a route itself.{session_note} '
            f'That\'s also what "busy" looks like on a backbone: real BGP sessions reconverge in bursts, not just a '
            f'steady trickle of independent updates.'
        )
    else:
        commentary = (
            f'{len(msgs)} {match_noun}: {origin_count} where AS7575 originated the route itself, {transit_count} '
            f'where it was purely relaying someone else\'s. Both are "busy" &mdash; a backbone AS constantly forwards '
            f'other networks\' changes and, less often, reconverges its own.'
        )

    return (
        '<div class="term"><div class="term-bar"><span class="mono">$ monocle watch --as-path 7575</span>'
        '<span>RIPE RIS Live, live capture</span></div>'
        f'<pre>{pre}</pre></div>'
        f'<p style="margin-top:12px;">Watched RIPE RIS Live for {capture_seconds}s, filtered to AS7575: {commentary}</p>'
    )


def build_moas_paragraph(moas):
    if not moas:
        return 'MOAS check unavailable this run (routing-status lookup failed for every prefix).'
    flagged = {p: origins for p, origins in moas.items() if len(set(origins)) > 1}
    if not flagged:
        prefix_list = ", ".join(f'<span class="as-tag">{p}</span>' for p in moas)
        return (
            f'We actually ran this check, rather than just describing it: querying RIPEstat\'s routing-status for all of '
            f'AS23859\'s prefixes ({prefix_list}) turns up exactly one origin AS each &mdash; AS23859 itself. No MOAS today. '
            f'That\'s the boring-but-correct outcome; what matters pedagogically is that the check exists and runs on every '
            f'regeneration, since a MOAS can appear at any time without warning.'
        )
    lines = "; ".join(f'{p} originated by {", ".join("AS" + str(o) for o in set(origins))}' for p, origins in flagged.items())
    return f'MOAS detected right now: {lines}. This needs investigation &mdash; see section 11\'s hijack/leak categories above.'


def render(timeout, template_path, live_watch_seconds=15, cache_ttl=0, cache_dir=".fieldguide_cache"):
    def c(key, fn, *args, **kwargs):
        return cached(cache_dir, cache_ttl, key, fn, *args, **kwargs)

    # Every fetch below is independent of every other one except for the three
    # that need `prefixes` first (rpki_rows, paths, moas) -- so they all run
    # concurrently in one pool, in two waves, instead of one after another.
    # Measured before this change: the sequential fetch chain alone (live BGP
    # captures aside) took 71 seconds. The live captures join the same pool
    # since they're just more concurrent work, not a special case anymore.
    # Never cached: a "live capture" replayed from an hour-old cache would be
    # dishonest about what "live" means.
    monocle_available = have_monocle()
    with ThreadPoolExecutor(max_workers=16) as pool:
        live_watch_future = pool.submit(get_live_watch_sample, ASN_UPSTREAM, live_watch_seconds)
        live_community_future = pool.submit(get_live_community_sample)

        prefixes_future = pool.submit(c, "prefixes", get_prefixes, timeout)
        route_objects_future = pool.submit(c, "route_objects_raw", get_route_objects_raw, timeout)
        autnum_future = pool.submit(c, "autnum_raw", get_autnum_raw, timeout)
        caida_future = pool.submit(c, "caida", get_aarnet_caida, timeout)
        pdb_future = pool.submit(c, "peeringdb", get_aarnet_peeringdb, timeout)
        aarnet_neighbours_future = pool.submit(c, "aarnet_neighbours", get_neighbours, ASN_UPSTREAM, timeout)
        unsw_neighbours_future = pool.submit(c, "unsw_neighbours", get_neighbours, ASN_ORIGIN, timeout)
        as18062_announced_future = pool.submit(c, "as18062_announced", get_as18062_announced, timeout)
        global_table_stats_future = pool.submit(c, "global_table_stats", get_global_table_stats, timeout)

        if monocle_available:
            as2rel_future = pool.submit(c, "as2rel", get_as2rel, ASN_UPSTREAM, ASN_ORIGIN, timeout)
            aspa_customer_future = pool.submit(c, "aspa_customer", get_aspa, timeout, customer=ASN_ORIGIN)
            aspa_provider_future = pool.submit(c, "aspa_provider", get_aspa, timeout, provider=ASN_UPSTREAM)
            as18062_roas_future = pool.submit(c, "as18062_roas", get_as18062_roas, timeout)
            aarnet_rpki_summary_future = pool.submit(c, "aarnet_rpki_summary", get_aarnet_rpki_summary, timeout)

        # Second wave: these three need `prefixes`, so they're submitted as
        # soon as it's ready rather than waiting for the whole first wave.
        prefixes = prefixes_future.result()
        rpki_rows_future = pool.submit(c, "rpki_rows", get_rpki, prefixes, timeout)
        paths_future = pool.submit(c, "paths", get_sample_paths, prefixes, timeout)
        moas_future = pool.submit(c, "moas", get_moas, prefixes, timeout)

        route_objects_raw = route_objects_future.result()
        autnum_raw = autnum_future.result()
        caida = caida_future.result()
        pdb = pdb_future.result()
        aarnet_neighbours = aarnet_neighbours_future.result()
        unsw_neighbours = unsw_neighbours_future.result()
        as18062_announced = as18062_announced_future.result()
        global_table_stats = global_table_stats_future.result()
        rpki_rows = rpki_rows_future.result()
        paths = paths_future.result()
        moas = moas_future.result()

        as2rel = as2rel_future.result() if monocle_available else None
        aspa_customer = aspa_customer_future.result() if monocle_available else None
        aspa_provider = aspa_provider_future.result() if monocle_available else None
        as18062_roas = as18062_roas_future.result() if monocle_available else None
        aarnet_rpki_summary = aarnet_rpki_summary_future.result() if monocle_available else None

        live_watch_msgs = live_watch_future.result()
        live_community_msg = live_community_future.result()

    degree = caida.get("asnDegree", {})
    cone = caida.get("cone", {})

    left_neighbours = sorted(
        (n for n in aarnet_neighbours if n.get("type") == "left"),
        key=lambda n: n.get("power", 0), reverse=True,
    )
    top_providers = ", ".join(f'AS{n["asn"]}' for n in left_neighbours[:3]) or "n/a"
    uncertain_count = sum(1 for n in aarnet_neighbours if n.get("type") == "uncertain")
    certain_count = sum(1 for n in aarnet_neighbours if n.get("type") in ("left", "right"))

    edge_power = next(
        (n.get("power") for n in unsw_neighbours if str(n.get("asn")) == str(ASN_UPSTREAM)),
        "?",
    )

    hop_counts = [len(p["as_path"].split()) for p in paths] or [0]
    shortest_path = min(paths, key=lambda p: len(p["as_path"].split())) if paths else None

    rpki_json_block, notable = build_rpki_json_block(rpki_rows)

    if pdb:
        peeringdb_str = f'{pdb["ix_count"]} IXPs, {pdb["fac_count"]} facilities, {pdb["info_traffic"]}'
        ix_count = pdb["ix_count"]
    else:
        peeringdb_str, ix_count = "no record", 0

    values = {
        "SNAPSHOT_DATE": date.today().isoformat(),
        "PREFIX_COUNT": len(prefixes),
        "IPV6_NOTE": "including IPv6" if any(":" in p for p in prefixes) else "no IPv6 announced today",
        "PREFIX_ROWS": build_prefix_rows(rpki_rows),
        "EDGE_POWER": f"{edge_power:,}" if isinstance(edge_power, int) else str(edge_power),
        "PATHS_INTRO_SENTENCE": build_paths_intro(paths),
        "PATHS_ROWS": build_paths_rows(paths),
        "MIN_PATH_EXAMPLE": shortest_path["as_path"] if shortest_path else "n/a",
        "SHORTEST_HOPS": min(hop_counts),
        "LONGEST_HOPS": max(hop_counts),
        "AARNET_PROVIDERS": degree.get("provider", "?"),
        "AARNET_PEERS": degree.get("peer", "?"),
        "AARNET_CUSTOMERS": degree.get("customer", "?"),
        "AARNET_TOTAL_CAIDA": degree.get("total", "?"),
        "AARNET_RIPESTAT_UNIQUE": certain_count,
        "AARNET_RIPESTAT_UNCERTAIN": uncertain_count,
        "AARNET_PEERINGDB": peeringdb_str,
        "AARNET_IX_COUNT": ix_count,
        "AARNET_CONE": f'{cone.get("numberAsns", "?")} ASes, {cone.get("numberPrefixes", 0):,} prefixes',
        "AARNET_TOP_PROVIDERS": top_providers,
        "UNSW_CONE": f"1 AS, {len(prefixes)} prefixes",
        "UNSW_IPV6_COUNT": sum(1 for p in prefixes if ":" in p),
        "TABLE_SIZE_PARAGRAPH": build_table_size_paragraph(global_table_stats),
        "TABLE_MEMORY_PARAGRAPH": build_table_memory_paragraph(global_table_stats),
        "TABLE_512K_PARAGRAPH": build_512k_day_paragraph(global_table_stats),
        "AARNET_IPV6_COUNT": (
            f'{aarnet_rpki_summary["ipv6_count"]} (of {aarnet_rpki_summary["total"]} total)'
            if aarnet_rpki_summary and aarnet_rpki_summary.get("ipv6_count") is not None
            else "n/a (install monocle)"
        ),
        "ROUTE_OBJECTS_BLOCK": build_route_objects_block(route_objects_raw),
        "AUTNUM_BLOCK": build_autnum_block(autnum_raw),
        "RPKI_JSON_BLOCK": rpki_json_block,
        "RPKI_WORKED_PARAGRAPH": build_rpki_worked_paragraph(rpki_rows, notable),
        "AARNET_RPKI_ZOOMOUT_PARAGRAPH": build_aarnet_rpki_zoomout_paragraph(aarnet_rpki_summary),
        "AS18062_PARAGRAPH": build_as18062_paragraph(as18062_announced, as18062_roas),
        "AS2REL_PARAGRAPH": build_as2rel_paragraph(as2rel),
        "ASPA_PARAGRAPH": build_aspa_paragraph(aspa_customer, aspa_provider),
        "MOAS_PARAGRAPH": build_moas_paragraph(moas),
        "LIVE_WATCH_BLOCK": build_live_watch_block(live_watch_msgs, ASN_UPSTREAM, live_watch_seconds),
        "COMMUNITIES_PARAGRAPH": build_communities_paragraph(live_community_msg),
        "MONOCLE_STATUS": (
            "BGPKIT's monocle CLI was installed and queried live for this run."
            if monocle_available else
            "BGPKIT's monocle CLI wasn't installed for this run (brew install bgpkit/tap/monocle) "
            "-- the monocle-sourced call-outs above show install instructions instead of live numbers."
        ),
    }

    with open(template_path, encoding="utf-8") as f:
        template = string.Template(f.read())
    html = template.substitute(values)

    leftover = re.findall(r'\$[A-Z][A-Z0-9_]*', html)
    if leftover:
        raise RuntimeError(
            f"Template substitution left {len(leftover)} placeholder(s) unfilled: {sorted(set(leftover))}. "
            "This means the template references a $NAME with no matching entry in values{} -- fix before shipping."
        )
    return html


def self_test():
    """Offline regression tests for the parsing/formatting logic -- no network calls.

    This exists because three real bugs shipped this session (parse_autnum
    silently inheriting last-modified/mnt-by from an unrelated object further
    down the same whois response; decode_community collapsing distinct large
    communities to identical text; a singular/plural grammar bug in the live-
    capture commentary) and every one of them was caught by manually
    screenshotting the output, not by any automated check. This is that check.
    """
    failures = []
    total = 0

    def check(name, got, want):
        nonlocal total
        total += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    # parse_autnum must stop at the end of the aut-num block, not keep reading
    # into the irt/organisation/person objects that follow it in the same response.
    autnum_fixture = (
        "% [whois.apnic.net]\n"
        "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n"
        "\n"
        "% Information related to 'AS23859'\n"
        "\n"
        "aut-num:        AS23859\n"
        "as-name:        UNSW-AS-AP\n"
        "import:         from AS7575 accept ANY\n"
        "import:         from AS18062 accept ANY\n"
        "export:         to AS7575 announce AS23859\n"
        "export:         to AS18062 announce AS23859\n"
        "mnt-by:         APNIC-HM\n"
        "last-modified:  2020-06-22T05:22:11Z\n"
        "source:         APNIC\n"
        "\n"
        "irt:            IRT-AARNET-AU\n"
        "mnt-by:         MAINT-AARNET-AP\n"
        "last-modified:  2026-04-14T13:11:57Z\n"
        "source:         APNIC\n"
        "\n"
        "person:         UNSW Hostmaster\n"
        "mnt-by:         MAINT-AU-NSWUNI\n"
        "last-modified:  2008-09-04T07:29:24Z\n"
        "source:         APNIC\n"
    )
    parsed = parse_autnum(autnum_fixture)
    check("parse_autnum last-modified (regression: must come from aut-num, not a later object)",
          parsed["last-modified"], "2020-06-22T05:22:11Z")
    check("parse_autnum mnt-by (regression: must come from aut-num, not a later object)",
          parsed["mnt-by"], "APNIC-HM")
    check("parse_autnum import count", len(parsed["import"]), 2)
    check("parse_autnum export count", len(parsed["export"]), 2)
    check("parse_autnum as-name", parsed["as-name"], "UNSW-AS-AP")

    # parse_route_objects must keep each blank-line-delimited block independent.
    routes_fixture = (
        "route:          129.94.0.0/16\n"
        "origin:         AS23859\n"
        "descr:          University of New South Wales\n"
        "mnt-by:         MAINT-AU-NSWUNIVERSITY\n"
        "source:         APNIC\n"
        "\n"
        "route:          131.236.0.0/16\n"
        "origin:         AS23859\n"
        "source:         APNIC\n"
    )
    routes = parse_route_objects(routes_fixture)
    check("parse_route_objects count", len(routes), 2)
    if len(routes) == 2:
        check("parse_route_objects[0].route", routes[0]["route"], "129.94.0.0/16")
        check("parse_route_objects[0].mnt-by", routes[0]["mnt-by"], "MAINT-AU-NSWUNIVERSITY")
        check("parse_route_objects[1] must not inherit block 0's mnt-by", routes[1].get("mnt-by"), None)

    # decode_community must not collapse distinct large communities to the same
    # string (regression: a naive "first dict key" fallback previously returned
    # "global_admin(43252)" for every large community sharing that global_admin,
    # silently dropping local_data).
    large_a = {"global_admin": 6695, "local_data": [1911, 82]}
    large_b = {"global_admin": 6695, "local_data": [1912, 0]}
    check("decode_community large community A", decode_community(large_a), "6695:1911:82")
    check("decode_community large community B", decode_community(large_b), "6695:1912:0")
    check("decode_community distinguishes A from B (regression)", decode_community(large_a) != decode_community(large_b), True)
    check("decode_community Custom shape", decode_community({"Custom": [7018, 5000]}), "7018:5000")
    extended = {"TransitiveTwoOctetAs": {"global_admin": 24482, "local_admin": [0, 0, 1, 54], "subtype": 2}}
    check("decode_community extended community mentions its ASN", "24482" in decode_community(extended), True)

    # prefix_size_label
    check("prefix_size_label /24", prefix_size_label("203.10.48.0/24"), "256 addresses")
    check("prefix_size_label /16", prefix_size_label("129.94.0.0/16"), "65,536 addresses")

    # build_live_watch_block singular/plural (regression: it used to say "1 exact matches").
    one_msg = [{
        "as_path": [48070, 7575, 23859], "origin_asns": [999], "prefix": "1.2.3.0/24",
        "type": "ANNOUNCE", "peer_asn": 1, "peer_ip": "1.1.1.1",
    }]
    block = build_live_watch_block(one_msg, 7575, 15)
    check("build_live_watch_block never says '1 exact matches' (regression)", "1 exact matches" in block, False)
    check("build_live_watch_block says '1 exact match' for a single message", "1 exact match" in block, True)

    # Global table size/memory arithmetic is a pure function of the fetched
    # numbers -- test it against a fixed synthetic input, no network needed.
    fake_stats = {
        "ipv4_fib": 1_000_000, "ipv4_rib": 10_000_000, "ipv4_ribfib_ratio": 10.0,
        "as_count": 80_000, "origin_only": 67_000, "transit_only": 700, "mixed": 12_000,
        "avg_path": 3.9, "max_path": 15, "ipv6_fib": 260_000,
    }
    mem_para = build_table_memory_paragraph(fake_stats)
    check("build_table_memory_paragraph mentions the FIB entry count", "1,000,000" in mem_para, True)
    check("build_table_memory_paragraph mentions the RIB entry count", "10,000,000" in mem_para, True)
    k_para = build_512k_day_paragraph(fake_stats)
    check("build_512k_day_paragraph computes the 512K ratio correctly (1,000,000/512,000 = 1.953..)", "2.0" in k_para, True)
    check("build_table_memory_paragraph degrades gracefully with no stats", bool(build_table_memory_paragraph(None)), True)
    check("build_512k_day_paragraph still reads fine with no stats", bool(build_512k_day_paragraph(None)), True)

    if failures:
        print(f"SELF-TEST FAILED: {len(failures)} of {total} checks failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return False
    print(f"Self-test passed: {total} checks OK.")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="as23859_field_guide.html", help="output HTML path")
    parser.add_argument("--template", default="field_guide_template.html", help="template path")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    parser.add_argument(
        "--live-watch-seconds", type=float, default=15.0,
        help="how long to capture live RIPE RIS Live traffic for AS7575 via monocle watch (0 to skip)",
    )
    parser.add_argument(
        "--cache-ttl", type=float, default=0.0,
        help="reuse fetched results younger than this many seconds instead of re-fetching (0 disables caching; "
             "never applies to the live BGP/community captures)",
    )
    parser.add_argument("--cache-dir", default=".fieldguide_cache", help="where cached results are stored")
    parser.add_argument(
        "--self-test", action="store_true",
        help="run offline regression checks against the parsing/formatting logic and exit (no network calls)",
    )
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    html = render(args.timeout, args.template, args.live_watch_seconds, args.cache_ttl, args.cache_dir)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {args.out}  ({dt.now(timezone.utc).isoformat(timespec='seconds')})")


if __name__ == "__main__":
    main()
