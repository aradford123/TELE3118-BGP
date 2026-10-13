#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests>=2.31.0",
# ]
# ///
"""Generate an illustrated, data-driven BGP explorer page for any ASN.

Generic sibling of generate_field_guide.py: instead of a fixed teaching
narrative about one specific case study (AS23859/AS7575/AS18062), this
renders whatever facts come back for an arbitrary --asn into the same
illustrated report look (diagrams, chips, tables, terminal panels) with
commentary paragraphs generated from the data itself.

If BGPKIT's `monocle` CLI (https://bgpkit.com, `brew install bgpkit/tap/monocle`)
is on PATH, this also cross-checks relationship inference (as2rel) against
the AS's top neighbour and reports ASPA adoption. Every monocle-derived value
degrades gracefully to an explanatory note if the binary isn't installed.

Usage:
    uv run bgp_explorer.py 15169 [--out as15169_explorer.html] [--timeout 10]
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


def load_history(asn, history_dir):
    """Distinct from cached()/--cache-dir: that's for avoiding re-fetches within
    a single dev session (short TTL, disabled by default). This is a small,
    always-on per-ASN snapshot kept *across* runs so the report can say what
    changed since last time -- new/withdrawn prefixes, new/gone neighbours, a
    resolved or newly-discovered IRR gap. Returns None on a first run (or a
    corrupt file, treated the same as "no history yet")."""
    path = os.path.join(history_dir, f"as{asn}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def save_history(asn, history_dir, snapshot):
    os.makedirs(history_dir, exist_ok=True)
    path = os.path.join(history_dir, f"as{asn}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f)


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


# ---------------------------------------------------------------- per-ASN data

def get_overview(asn, timeout):
    return ripestat("as-overview", {"resource": f"AS{asn}"}, timeout)


def get_prefixes(asn, timeout):
    data = ripestat("announced-prefixes", {"resource": f"AS{asn}"}, timeout)
    return [p["prefix"] for p in data.get("prefixes", [])]


def prefix_size_label(prefix):
    if ":" in prefix:
        return "IPv6 block"
    length = int(prefix.rsplit("/", 1)[1])
    return f"{2 ** (32 - length):,} addresses"


def get_neighbours(asn, timeout):
    return ripestat("asn-neighbours", {"resource": f"AS{asn}"}, timeout).get("neighbours", [])


def get_neighbour_holders(neighbour_asns, timeout):
    """Resolve each neighbour ASN to its registered holder name, so the report can say
    *who* an upstream actually is (e.g. AS1221 -> Telstra) instead of just its number.

    Keyed by str(asn) rather than the raw int: this dict is round-tripped through
    JSON when --cache-ttl is set, which silently coerces int keys to strings, so
    keying by string from the start keeps cached and uncached lookups consistent.
    """
    def _one(n_asn):
        try:
            data = ripestat("as-overview", {"resource": f"AS{n_asn}"}, timeout)
            return str(n_asn), data.get("holder") or f"AS{n_asn}"
        except Exception as exc:
            print(f"[warning] as-overview for AS{n_asn} failed: {exc}", file=sys.stderr)
            return str(n_asn), f"AS{n_asn}"

    if not neighbour_asns:
        return {}
    with ThreadPoolExecutor(max_workers=len(neighbour_asns)) as pool:
        return dict(pool.map(_one, neighbour_asns))


def get_rpki(asn, prefixes, timeout, max_prefixes=12):
    """Returns list of {prefix, status, validating_roas}, in prefixes order (capped for large ASes)."""
    sample = prefixes[:max_prefixes]

    def _one(prefix):
        data = ripestat("rpki-validation", {"resource": f"AS{asn}", "prefix": prefix}, timeout)
        return {
            "prefix": prefix,
            "status": data.get("status", "unknown"),
            "validating_roas": data.get("validating_roas", []),
        }

    if not sample:
        return []
    with ThreadPoolExecutor(max_workers=len(sample)) as pool:
        results = {r["prefix"]: r for r in pool.map(_one, sample)}
    return [results[p] for p in sample]


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


def get_moas(prefixes, timeout, max_prefixes=8):
    """MOAS check via RIPEstat's routing-status. Returns {prefix: [origin_asn, ...]}."""
    sample = prefixes[:max_prefixes]

    def _one(prefix):
        data = ripestat("routing-status", {"resource": prefix}, timeout)
        return prefix, [o.get("origin") for o in data.get("origins", [])]

    moas = {}
    if not sample:
        return moas
    with ThreadPoolExecutor(max_workers=len(sample)) as pool:
        futures = [pool.submit(_one, prefix) for prefix in sample]
        for future in futures:
            try:
                prefix, origins = future.result()
                moas[prefix] = origins
            except Exception as exc:
                print(f"[warning] routing-status failed: {exc}", file=sys.stderr)
    return moas


def get_caida(asn, timeout):
    def _get():
        resp = requests.get(f"{CAIDA_ASRANK_REST}/{asn}", timeout=timeout)
        resp.raise_for_status()
        return resp.json()["data"]["asn"]
    try:
        return with_retries(_get)
    except Exception as exc:
        print(f"[warning] CAIDA ASRank lookup failed: {exc}", file=sys.stderr)
        return None


def get_peeringdb(asn, timeout):
    """A 404 here just means "no PeeringDB record for this ASN" -- extremely
    common for arbitrary ASNs, and not transient, so it's returned immediately
    rather than burning retries on a permanent result.

    Also fetches netixlan (actual IX presence: facility, speed, v4/v6 addresses)
    -- bgp_lookup.py's console report already includes this; the explorer had
    fallen behind it, reporting only network type/policy and dropping the part
    that answers "who it connects to" (this tool's own stated purpose) at IXPs.
    """
    def _get():
        resp = requests.get(f"{PEERINGDB_BASE}/net", params={"asn": asn}, timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        nets = resp.json().get("data", [])
        return nets[0] if nets else None
    try:
        net = with_retries(_get)
    except Exception as exc:
        print(f"[warning] PeeringDB lookup failed: {exc}", file=sys.stderr)
        return None
    if not net:
        return None

    def _get_ixlan():
        resp = requests.get(f"{PEERINGDB_BASE}/netixlan", params={"net_id": net["id"]}, timeout=timeout)
        resp.raise_for_status()
        return resp.json().get("data", [])
    try:
        ixlans = with_retries(_get_ixlan)
    except Exception as exc:
        print(f"[warning] PeeringDB netixlan lookup failed: {exc}", file=sys.stderr)
        ixlans = []
    net["exchanges"] = [
        {"ix_name": ix.get("name"), "ipv4": ix.get("ipaddr4"), "ipv6": ix.get("ipaddr6"), "speed_mbps": ix.get("speed")}
        for ix in ixlans
    ]
    return net


def get_route_objects_raw(asn, timeout):
    try:
        return whois_query("whois.radb.net", f"-i origin AS{asn}", timeout)
    except Exception as exc:
        print(f"[warning] RADB route-object whois failed: {exc}", file=sys.stderr)
        return ""


def get_autnum_raw(asn, timeout):
    """RADB first; APNIC/ARIN/RIPE-style RIRs mirror into RADB, but if it comes
    back empty we fall back to APNIC directly (same reasoning as bgp_lookup.py:
    APNIC-registered ASNs sometimes aren't fully mirrored)."""
    try:
        raw = whois_query("whois.radb.net", f"-T aut-num AS{asn}", timeout)
    except Exception as exc:
        print(f"[warning] RADB aut-num whois failed: {exc}", file=sys.stderr)
        raw = ""
    if "aut-num:" not in raw:
        try:
            raw = whois_query("whois.apnic.net", f"-T aut-num AS{asn}", timeout)
        except Exception as exc:
            print(f"[warning] APNIC aut-num whois fallback failed: {exc}", file=sys.stderr)
    return raw


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
    """Parse only the first (aut-num) object in the response -- a "-T aut-num"
    query returns that object followed by whatever it references (irt,
    organisation, person, ...), each with their own last-modified/mnt-by
    fields that must not be attributed to the aut-num itself."""
    fields = {"as-name": None, "mnt-by": None, "last-modified": None, "import": [], "export": []}
    started = False
    for line in raw_text.splitlines():
        if not line.strip():
            if started:
                break
            continue
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


# ---------------------------------------------------------------- BGPKIT / monocle (optional)

def have_monocle():
    return shutil.which("monocle") is not None


def run_monocle(args, timeout):
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


def _watch_once(asn, capture_seconds, max_msgs):
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
    """Bounded live capture from RIPE RIS Live via monocle. See generate_field_guide.py
    for why this reads stdout incrementally against select() rather than subprocess.run(timeout=...)."""
    if not have_monocle() or capture_seconds <= 0:
        return None
    msgs = []
    for attempt in range(max_attempts):
        msgs = _watch_once(asn, capture_seconds, max_msgs)
        if msgs:
            return msgs
        if attempt < max_attempts - 1:
            print(f"[live-watch] attempt {attempt + 1} caught nothing for AS{asn}; retrying once...", file=sys.stderr)
    return msgs


# ---------------------------------------------------------------- commentary builders
#
# Every paragraph below is generated purely from the fetched data for whatever
# ASN was requested -- no hand-written facts about a specific network. Each
# one degrades to an explanatory placeholder if its inputs are missing.

def build_prefix_rows(rpki_rows):
    # "invalid" (a ROA exists but names a different AS/max-length) is a real
    # hijack signal; "unknown" (no ROA at all) is the default state for most of
    # the Internet and means nothing on its own. Rendering both as the same
    # "warn" chip understated the one that actually matters.
    chip_for = {"valid": ("good", "valid"), "invalid": ("bad", "invalid"), "unknown": ("warn", "no ROA")}
    rows = []
    for r in rpki_rows:
        chip_class, label = chip_for.get(r["status"], ("mute", r["status"]))
        rows.append(
            f'            <tr><td class="mono">{r["prefix"]}</td>'
            f'<td>{prefix_size_label(r["prefix"])}</td>'
            f'<td><span class="chip {chip_class}">{label}</span></td></tr>'
        )
    return "\n".join(rows) if rows else '            <tr><td colspan="3"><span class="c">(no announced prefixes found)</span></td></tr>'


def build_prefix_sample_note(shown_count, total_count):
    """The prefix table only ever shows the RPKI-checked sample (get_rpki caps at
    12): for a large AS (AS15169 has 1400+) that silently looked like the complete
    list with no indication it wasn't, unlike the RPKI paragraph's own explicit
    "(sampled X of Y)" caveat."""
    if total_count <= shown_count:
        return ""
    return (
        f'<p style="font-size:0.85rem;color:var(--text-muted);margin-top:-6px;">Showing {shown_count} of '
        f'{total_count} announced prefixes (the same sample checked against RPKI above).</p>'
    )


def build_overview_paragraph(asn, overview, prefixes, holder_name):
    announced = overview.get("announced")
    if not announced:
        return (
            f'AS{asn} ({holder_name}) is not currently announcing any prefixes in RIPEstat\'s view of the routing '
            f'table &mdash; it may be dormant, recently deregistered, or simply not visible from RIS\'s vantage points.'
        )
    v6 = sum(1 for p in prefixes if ":" in p)
    v4 = len(prefixes) - v6
    return (
        f'AS{asn} ({holder_name}) is currently announcing <b>{len(prefixes)}</b> prefix{"es" if len(prefixes) != 1 else ""} '
        f'({v4} IPv4, {v6} IPv6) as seen by RIPE RIS route collectors.'
    )


def build_homing_label(neighbours):
    """Short, unambiguous multihoming verdict for a masthead/summary chip."""
    left = sum(1 for n in neighbours if n.get("type") == "left")
    if left == 0:
        return "No visible upstream"
    if left == 1:
        return "Single-homed &middot; 1 upstream"
    return f"Multi-homed &middot; {left} upstreams"


NEIGHBOUR_NAME_LIMIT = 5  # how many upstreams to name in prose before falling back to "+N more"


def build_neighbours_paragraph(asn, neighbours, holders):
    if not neighbours:
        return f'RIPEstat\'s asn-neighbours dataset returned no neighbours for AS{asn} -- either it has none visible from RIS, or the lookup failed this run.'
    left = [n for n in neighbours if n.get("type") == "left"]
    right = [n for n in neighbours if n.get("type") == "right"]
    uncertain = [n for n in neighbours if n.get("type") == "uncertain"]
    homing = "single-homed" if len(left) == 1 else ("multi-homed" if len(left) > 1 else "has no clear upstream")
    parts = [
        f'AS{asn} has <b>{len(neighbours)}</b> total neighbour{"s" if len(neighbours) != 1 else ""} inferred from live AS-path '
        f'data: <b>{len(left)}</b> upstream-like ("left") and <b>{len(right)}</b> downstream-like ("right")'
    ]
    if uncertain:
        parts.append(f', plus {len(uncertain)} whose direction RIS couldn\'t classify')
    parts.append(f'. With {len(left)} upstream link{"s" if len(left) != 1 else ""}, this AS looks {homing}')
    if left:
        ranked_left = sorted(left, key=lambda n: n.get("power", 0), reverse=True)
        shown = ranked_left[:NEIGHBOUR_NAME_LIMIT]
        owner_list = ", ".join(
            f'<span class="as-tag">AS{n.get("asn")}</span> ({holders.get(str(n.get("asn")), "?")})' for n in shown
        )
        remainder = len(ranked_left) - len(shown)
        if remainder > 0:
            owner_list += f', and {remainder} more'
        verb = "belongs to" if len(ranked_left) == 1 else "connects upstream through"
        parts.append(f': it {verb} {owner_list}')
    parts.append(".")
    return "".join(parts)


def build_topology_role(neighbours):
    """Returns (role_label, node_class) describing this AS's rough topological role."""
    left = sum(1 for n in neighbours if n.get("type") == "left")
    right = sum(1 for n in neighbours if n.get("type") == "right")
    if left == 0 and right == 0:
        return "Isolated / no visible neighbours", "rest"
    if left <= 1 and right == 0:
        return "Stub &middot; single-homed", "origin"
    if right > 0 and left > 0:
        return "Transit &middot; multi-homed", "transit"
    if left > 1:
        return "Multi-homed, no customers seen", "transit"
    return "Downstream-only (no visible upstream)", "rest"


def build_diagram_block(asn, holder_name, role_label, role_class, neighbours, holders, limit=3):
    """Subject node on the left, its top neighbours fanned out as parallel branches
    to the right -- each neighbour connects independently to the subject. Earlier
    version chained node -> connector -> node -> connector -> node in a single row,
    which visually implied a serial path (AS7474 -> AS32787 -> AS1221) between
    neighbours that in reality have no relationship to each other at all."""
    subject = (
        f'          <div class="node {role_class}" style="justify-content:center; flex:0 0 190px;">'
        f'<span class="role">{role_label}</span>'
        f'<span class="node-as">AS{asn}</span><span class="node-name">{holder_name}</span></div>'
    )
    ranked = sorted(neighbours, key=lambda n: n.get("power", 0), reverse=True)[:limit]
    if not ranked:
        return f'<div class="diagram">\n        <div class="diagram-row" style="align-items:stretch;">\n{subject}\n        </div>\n      </div>'

    hues = ["hue1", "hue2", "hue3", "hue4"]
    type_role = {"left": "Upstream-like", "right": "Downstream-like", "uncertain": "Uncertain direction"}
    branches = []
    for i, n in enumerate(ranked):
        hue = f"var(--{hues[i % len(hues)]})"
        n_asn = n.get("asn")
        branches.append(
            f'            <div style="display:flex; align-items:center; gap:10px;">'
            f'<svg width="34" height="16" viewBox="0 0 34 16" style="flex:none; color:{hue};">'
            f'<line x1="0" y1="8" x2="26" y2="8" stroke="currentColor" stroke-width="2"/>'
            f'<polygon points="26,3 34,8 26,13" fill="currentColor"/></svg>'
            f'<div class="node" style="border:2px solid {hue}; flex:1;">'
            f'<span class="role" style="color:{hue};">{type_role.get(n.get("type"), "Neighbour")} &middot; power {n.get("power", "?")}</span>'
            f'<span class="node-as">AS{n_asn}</span>'
            f'<span class="node-name">{holders.get(str(n_asn), f"AS{n_asn}")}</span></div></div>'
        )
    branches_html = "\n".join(branches)
    return (
        f'<div class="diagram">\n        <div class="diagram-row" style="align-items:stretch;">\n{subject}\n'
        f'          <div style="display:flex; flex-direction:column; gap:10px; flex:1;">\n{branches_html}\n          </div>\n'
        f'        </div>\n'
        f'        <p class="diagram-cap">Top {len(ranked)} neighbour{"s" if len(ranked) != 1 else ""} of AS{asn} by RIS path '
        f'weight ("power") &mdash; each an independent link to AS{asn}, not to each other. "Power" measures how many '
        f'route-collector peers observe that edge, not link capacity.</p>\n      </div>'
    )


def build_top_neighbours_rows(neighbours, holders, limit=8):
    ranked = sorted(neighbours, key=lambda n: n.get("power", 0), reverse=True)[:limit]
    if not ranked:
        return '            <tr><td colspan="4"><span class="c">(no neighbours found)</span></td></tr>'
    type_label = {"left": "upstream-like", "right": "downstream-like", "uncertain": "uncertain"}
    rows = []
    for n in ranked:
        n_asn = n.get("asn")
        rows.append(
            f'            <tr><td class="mono">AS{n_asn}</td>'
            f'<td>{holders.get(str(n_asn), "?")}</td>'
            f'<td>{type_label.get(n.get("type"), n.get("type"))}</td>'
            f'<td class="mono">{n.get("power", "?")}</td></tr>'
        )
    return "\n".join(rows)


def build_neighbour_sample_note(neighbours, limit=8):
    """Mirrors build_prefix_sample_note: a heavily-connected AS (e.g. AS15169 has
    300+ neighbours) would otherwise show exactly `limit` table rows with no hint
    that most neighbours are cut off, unlike the RPKI paragraph's own caveat."""
    if len(neighbours) <= limit:
        return ""
    return (
        f'<p style="font-size:0.85rem;color:var(--text-muted);margin-top:-6px;">Showing top {limit} of '
        f'{len(neighbours)} neighbours by RIS path weight ("power").</p>'
    )


def build_paths_intro(asn, paths):
    if not paths:
        return f"No live sample paths were returned by RIS for AS{asn}'s prefixes on this run."
    locations = sorted(set(p["location"] for p in paths if p.get("location")))
    prefixes_seen = sorted(set(p["prefix"] for p in paths))
    loc_str = " / ".join(locations) if locations else "an RIS route collector"
    if len(prefixes_seen) == 1:
        prefix_str = f'the prefix <span class="as-tag">{prefixes_seen[0]}</span>'
    else:
        prefix_str = "prefixes " + ", ".join(f'<span class="as-tag">{p}</span>' for p in prefixes_seen)
    intro = (
        f"These {len(paths)} paths were captured live by RIPE RIS route collectors "
        f"({loc_str}), for {prefix_str}:"
    )
    # get_sample_paths only checks the AS's first 3 prefixes, so when every path
    # captured also happens to transit the same single upstream, that's an
    # artifact of the narrow sample (one prefix, one collector), not evidence the
    # AS lacks other active upstream links -- a real run surfaced exactly this
    # (5/5 paths via one upstream for a bank multi-homed to three).
    up_hops = {tokens[-2] for p in paths if len(tokens := p["as_path"].split()) >= 2}
    if len(prefixes_seen) == 1 and len(up_hops) <= 1:
        intro += (
            '<br><span style="font-size:0.85rem;font-weight:400;color:var(--text-muted);">A single-prefix sample '
            '&mdash; every path transiting the same neighbour here reflects that narrow sample, not necessarily the '
            'AS\'s only active upstream link (see section 02\'s full neighbour list).</span>'
        )
    return intro


def path_lead_tokens(as_path):
    """The hops in an AS-path that are NOT the origin or the up-hop -- i.e. the
    ones build_paths_rows leaves plain rather than highlighting. Factored out so
    build_paths_rows and build_paths_key_block can't silently drift apart on
    what counts as "already highlighted, no lookup needed"."""
    tokens = as_path.split()
    return tokens[:-2] if len(tokens) >= 2 else []


def build_paths_rows(paths):
    if not paths:
        return '        <div class="prow"><span class="path"><span class="c">(no live paths captured this run)</span></span></div>'
    rows = []
    for p in paths:
        tokens = p["as_path"].split()
        origin = tokens[-1] if tokens else ""
        up = tokens[-2] if len(tokens) >= 2 else None
        lead = " ".join(path_lead_tokens(p["as_path"]))
        hop_html = (f'{lead} <span class="hop up-hop">{up}</span> ' if up else "") + \
                   f'<span class="hop origin-hop">{origin}</span>'
        rows.append(
            f'        <div class="prow"><span class="loc">{p["location"]}</span>'
            f'<span class="path">{hop_html.strip()}</span></div>'
        )
    return "\n".join(rows)


def build_paths_key_block(paths, holders):
    """A small ASN -> holder legend for the *lead* hops in each captured path --
    i.e. whichever unrelated transit networks (other ISPs, carriers) RIS's route
    collector happened to reach through before the subject's own up-hop/origin.
    Deliberately excludes the origin and up-hop: those are already highlighted
    in the path list and named elsewhere in the report (masthead, section 02),
    so repeating them here would just be noise."""
    if not paths:
        return ""
    seen, seen_set = [], set()
    for p in paths:
        for tok in path_lead_tokens(p["as_path"]):
            if tok not in seen_set:
                seen_set.add(tok)
                seen.append(tok)
    if not seen:
        return ""
    rows = "\n".join(
        f'            <tr><td class="mono">AS{a}</td><td>{holders.get(a, "?")}</td></tr>' for a in seen
    )
    return (
        '<div class="tbl-wrap" style="margin-top:4px;">\n'
        '        <table>\n'
        '          <thead><tr><th class="mono">ASN</th><th>Holder</th></tr></thead>\n'
        '          <tbody>\n'
        f'{rows}\n'
        '          </tbody>\n'
        '        </table>\n'
        '      </div>'
    )


def build_rpki_json_block(rpki_rows):
    if not rpki_rows:
        return '<span class="c">(no prefixes to validate)</span>', None
    # Prefer surfacing an "invalid" prefix (a real hijack signal) over a merely
    # "unknown" one (no ROA at all, common and benign) if both are present --
    # picking whichever came first in API order could bury the worse finding.
    notable = (
        next((r for r in rpki_rows if r["status"] == "invalid"), None)
        or next((r for r in rpki_rows if r["status"] != "valid"), None)
        or rpki_rows[0]
    )
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


def build_rpki_paragraph(asn, rpki_rows, notable, prefix_count):
    if not rpki_rows:
        return f'No prefixes were available to RPKI-validate for AS{asn} this run.'
    valid_count = sum(1 for r in rpki_rows if r["status"] == "valid")
    total = len(rpki_rows)
    sample_note = f' (sampled {total} of {prefix_count})' if prefix_count > total else ''
    if notable["status"] == "valid":
        return (
            f'All {total} checked prefix{"es" if total != 1 else ""}{sample_note} for AS{asn} currently come back '
            f'<span class="chip good">valid</span> &mdash; every one has a matching ROA on file.'
        )
    if notable["status"] == "invalid":
        return (
            f'{valid_count} of {total} checked prefixes{sample_note} are <span class="chip good">valid</span>. '
            f'<span class="as-tag">{notable["prefix"]}</span> comes back <span class="chip bad">invalid</span> '
            f'&mdash; a real hijack signal: a ROA exists but names a different origin AS, or a stricter max-length, '
            f'than this announcement. Querying RIPEstat\'s validator directly confirms it: '
            f'<code class="mono">"validating_roas": {notable["validating_roas"] or []}</code>.'
        )
    return (
        f'{valid_count} of {total} checked prefixes{sample_note} are <span class="chip good">valid</span>. '
        f'<span class="as-tag">{notable["prefix"]}</span> comes back <span class="chip warn">no ROA</span> &mdash; '
        f'not itself alarming (most of the Internet still has no ROA), just zero cryptographic protection for that '
        f'one prefix. <code class="mono">"validating_roas": {notable["validating_roas"] or []}</code>.'
    )


def build_route_objects_block(asn, raw_text):
    routes = parse_route_objects(raw_text)
    if not routes:
        return '<span class="c">(no route objects returned)</span>'
    first = routes[0]
    lines = [f'<span class="c">% Information related to \'{first["route"]}AS{asn}\'</span>', ""]
    lines.append(f'<span class="k">route:</span>          {first["route"]}')
    lines.append(f'<span class="k">origin:</span>         {first.get("origin", f"AS{asn}")}')
    if first.get("descr"):
        lines.append(f'<span class="c">descr:          {first["descr"]}</span>')
    if first.get("mnt-by"):
        lines.append(f'<span class="k">mnt-by:</span>         {first["mnt-by"]}')
    lines.append(f'<span class="k">source:</span>         {first.get("source", "?")}')
    rest = routes[1:]
    if rest:
        shown_prefixes = ", ".join(r["route"] for r in rest[:9])
        if len(rest) > 9:
            shown_prefixes += f", and {len(rest) - 9} more"
        lines.append("")
        lines.append(f'<span class="c">&hellip; {len(rest)} more route object(s) follow the same pattern for\n    {shown_prefixes} &hellip;</span>')
    return "\n".join(lines)


def build_autnum_block(asn, raw_text):
    fields = parse_autnum(raw_text)
    if not fields["as-name"] and not fields["import"] and not fields["export"]:
        return '<span class="c">(no aut-num policy object found)</span>'
    lines = [f'<span class="k">aut-num:</span>        AS{asn}']
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


def build_irr_paragraph(asn, raw_text, neighbours, holders):
    """Checks IRR-declared policy against live AS-path data in BOTH directions.

    The original version only checked one direction (a declared neighbour that
    never shows up live -- "stale registry data"). It never checked the reverse:
    a real, live neighbour that isn't named in policy at all -- arguably the more
    interesting finding (an undocumented BGP relationship), and one real-world
    run turned up exactly this (a bank's DDoS-scrubbing upstream present in live
    AS-paths but absent from its aut-num object).

    Returns (paragraph_html, stale, undeclared, has_policy): the drift lists are
    exposed alongside the prose so a run-level findings summary, and the as2rel
    cross-check (which prefers to target an undeclared neighbour over just the
    highest-power one), don't have to re-derive the same comparison.
    """
    fields = parse_autnum(raw_text)
    imports = fields["import"] + fields["export"]
    # "uncertain"-typed neighbours are excluded from this check: RIS couldn't even
    # classify their direction, so flagging them as "undeclared policy" would be
    # noise, not a finding (this matters at scale -- a busy AS can have hundreds).
    directional = [n for n in neighbours if n.get("type") in ("left", "right")]

    if not imports:
        base = f'No <code class="mono">import:</code>/<code class="mono">export:</code> policy lines were found for AS{asn} in this registry.'
        if directional:
            base += (
                f' Live AS-path data shows {len(directional)} real neighbour{"s" if len(directional) != 1 else ""} for '
                f'this AS, so the gap is in registered policy, not in the network\'s actual connectivity.'
            )
        return base, [], [], False

    referenced = set(re.findall(r'AS(\d+)', " ".join(imports))) - {str(asn)}
    live_neighbour_asns = {str(n.get("asn")) for n in directional}
    stale = sorted(referenced - live_neighbour_asns, key=int)
    undeclared = sorted(live_neighbour_asns - referenced, key=int)

    ref_phrase = (
        f'AS{asn}\'s <code class="mono">aut-num</code> object references {len(referenced)} neighbour AS'
        f'{"es" if len(referenced) != 1 else ""}'
    )

    if not stale and not undeclared:
        return (
            f'{ref_phrase}, every one of them shows up in live AS-path data too, and there is no live neighbour missing '
            f'from policy either &mdash; declared policy and observed reality fully agree.',
            stale, undeclared, True,
        )

    parts = [ref_phrase]
    if stale:
        stale_str = ", ".join(f"AS{a}" for a in stale[:10])
        if len(stale) > 10:
            stale_str += f", and {len(stale) - 10} more"
        verb = "doesn" + "'" + "t" if len(stale) == 1 else "don" + "'" + "t"
        parts.append(
            f', but {stale_str} {verb} show up in any live AS-path RIS observed this run &mdash; a sign of registry '
            f'drift: declared policy that no longer matches current topology'
        )
    else:
        parts.append(', and every one of them shows up in live AS-path data too')

    if undeclared:
        shown = undeclared[:NEIGHBOUR_NAME_LIMIT]
        names = ", ".join(f'AS{a} ({holders.get(a, "?")})' for a in shown)
        remainder = len(undeclared) - len(shown)
        if remainder > 0:
            names += f', and {remainder} more'
        last_mod = fields["last-modified"] or "an unknown date"
        subj_verb = "isn" + "'" + "t" if len(undeclared) == 1 else "aren" + "'" + "t"
        parts.append(
            f'. The other direction tells a different story: {len(undeclared)} live neighbour'
            f'{"s" if len(undeclared) != 1 else ""} RIS actually observes for AS{asn} {subj_verb} named in this policy '
            f'object at all: {names} &mdash; either an undocumented relationship, or policy that predates it '
            f'(last modified {last_mod})'
        )

    return "".join(parts) + ".", stale, undeclared, True


def build_moas_paragraph(moas, prefix_count):
    """Returns (paragraph_html, flagged) -- flagged exposed for the findings summary.
    Takes the AS's total prefix count so it can disclose sampling the same way
    the prefix table and RPKI paragraph already do (this used to just say
    "checked N prefixes" with no sense of how much of the AS that covered)."""
    if not moas:
        return 'MOAS check unavailable this run (routing-status lookup failed for every prefix, or there were no prefixes to check).', {}
    # One combined phrase ("8 of 44 prefixes") rather than a separate leading
    # "(sampled X of Y)" parenthetical stacked right before the prefix-list
    # parenthetical -- that read as an awkward double-parenthetical.
    count_phrase = f'{len(moas)} of {prefix_count} prefixes' if prefix_count > len(moas) else f'{len(moas)} prefix{"es" if len(moas) != 1 else ""}'
    flagged = {p: origins for p, origins in moas.items() if len(set(origins)) > 1}
    if not flagged:
        prefix_list = ", ".join(f'<span class="as-tag">{p}</span>' for p in moas)
        return (
            f'Checked {count_phrase} ({prefix_list}) against RIPEstat\'s routing-status: each one has exactly one '
            f'origin AS. No MOAS today.'
        ), flagged
    lines = "; ".join(f'{p} originated by {", ".join("AS" + str(o) for o in set(origins))}' for p, origins in flagged.items())
    return (
        f'MOAS detected right now (checked {count_phrase}): {lines}. Multiple ASes are originating the same prefix '
        f'simultaneously &mdash; sometimes legitimate (anycast), sometimes a hijack signal.'
    ), flagged


def build_caida_paragraph(asn, caida, prefix_count):
    if not caida:
        return f'No CAIDA ASRank record found for AS{asn} (or the lookup failed this run).'
    org = (caida.get("organization") or {}).get("orgName") or "unknown organization"
    degree = caida.get("asnDegree", {})
    cone = caida.get("cone", {})
    rank = caida.get("rank")
    cone_prefixes = cone.get("numberPrefixes", 0)
    base = (
        f'CAIDA ASRank lists AS{asn} as <b>{caida.get("asnName", "?")}</b> ({org}), globally ranked <b>#{rank}</b> by '
        f'customer cone size. Inferred degree: {degree.get("provider", 0)} providers, {degree.get("peer", 0)} peers, '
        f'{degree.get("customer", 0)} customers. Customer cone: {cone.get("numberAsns", 0)} ASes, '
        f'{cone_prefixes:,} prefixes.'
    )
    # These two prefix counts come from different sources (CAIDA's own crawl vs.
    # RIPEstat/RIS) on different measurement schedules, so they routinely won't
    # match exactly -- left unreconciled, a careful reader cross-referencing
    # section 01's count against this one would be left wondering why they differ.
    if prefix_count and cone_prefixes and abs(cone_prefixes - prefix_count) > max(1, round(0.05 * prefix_count)):
        base += (
            f' That figure differs from RIPEstat\'s live count above ({prefix_count:,}) &mdash; different sources, '
            f'different measurement windows, not a discrepancy to read anything into on its own.'
        )
    return base


def build_peeringdb_paragraph(asn, pdb):
    if not pdb:
        return f'No PeeringDB record found for AS{asn} &mdash; absence isn\'t necessarily meaningful, since PeeringDB is opt-in.'
    base = (
        f'PeeringDB has a record for <b>{pdb.get("name")}</b> ({pdb.get("aka") or "no alias"}): network type '
        f'"{pdb.get("info_type") or "unspecified"}", peering policy "{pdb.get("policy_general") or "unspecified"}"'
        + (f', IRR AS-SET <code class="mono">{pdb["irr_as_set"]}</code>' if pdb.get("irr_as_set") else '') + '.'
    )
    exchanges = [ix for ix in (pdb.get("exchanges") or []) if ix.get("ix_name")]
    if not exchanges:
        return base + ' No public IX presence is listed.'
    shown = exchanges[:5]
    ix_list = ", ".join(ix["ix_name"] for ix in shown)
    remainder = len(exchanges) - len(shown)
    if remainder > 0:
        ix_list += f', and {remainder} more'
    return (
        f'{base} Present at <b>{len(exchanges)}</b> IX connection{"s" if len(exchanges) != 1 else ""}: {ix_list}.'
    )


def parse_percent(value):
    """monocle's as2rel returns percentages as strings like "44.7%". Returns None
    (rather than raising) for anything else, so callers can treat "couldn't
    parse it" the same as "no data" instead of crashing on unexpected input."""
    try:
        return float(str(value).rstrip("%"))
    except (TypeError, ValueError):
        return None


def build_as2rel_paragraph(asn, target_asn, rel, is_undeclared_check=False):
    """target_asn is normally the highest-power neighbour, but render() prefers a
    neighbour section 05 flagged as live-but-undeclared-in-policy when one exists
    -- a second, independent toolchain is a much stronger way to corroborate (or
    cast doubt on) that specific finding than just picking whichever link is
    biggest, which usually isn't the interesting one."""
    if not target_asn:
        return 'No neighbour was available to cross-check a relationship against.'
    context = (
        ' &mdash; chosen because section 05 flagged it as live but missing from declared policy'
        if is_undeclared_check else ''
    )
    if not rel:
        return (
            f'BGPKIT\'s <code class="mono">monocle</code> (<code class="mono">brew install bgpkit/tap/monocle</code>) can '
            f'independently infer the AS{asn}&ndash;AS{target_asn} relationship{context} via '
            f'<code class="mono">monocle as2rel {asn} {target_asn}</code>. It wasn\'t installed for this run, so this '
            f'falls back to RIPEstat/CAIDA\'s picture above; install it and re-run to see the independent numbers.'
        )
    connected, peer, up1, up2 = rel["connected"], rel["peer"], rel["as1_upstream"], rel["as2_upstream"]
    return (
        f'BGPKIT\'s independent <code class="mono">as2rel</code> dataset puts a number on the AS{asn}&ndash;AS{target_asn} '
        f'link{context}: <b>{connected}</b> of vantage points see it at all, and among those, <b>{up1}</b> classify AS{asn} as the '
        f'provider, <b>{peer}</b> as settlement-free peers, and <b>{up2}</b> the reverse.'
    )


def build_aspa_paragraph(asn, customer_aspas, provider_aspas):
    if customer_aspas is None and provider_aspas is None:
        return (
            'Install BGPKIT\'s <code class="mono">monocle</code> (<code class="mono">brew install bgpkit/tap/monocle</code>) '
            f'and re-run to see AS{asn}\'s real ASPA (RFC 9582) adoption status here &mdash; a newer, complementary object to '
            'RPKI ROAs that authenticates AS-PATH shape, not just origin.'
        )
    customer_count = len(customer_aspas or [])
    provider_count = len(provider_aspas or [])
    return (
        f'Querying BGPKIT\'s cached ASPA (RFC 9582) set: AS{asn} has published {customer_count} ASPA record'
        f'{"s" if customer_count != 1 else ""} naming its own valid providers, and is itself named as an authorized '
        f'provider by {provider_count} other AS{"es" if provider_count != 1 else ""}.'
    )


def build_aspa_irr_paragraph(asn, customer_aspas, autnum_raw):
    """Cross-checks the AS's own ASPA-declared providers (RFC 9582, cryptographically
    signed) against its RPSL aut-num import: lines (unsigned, decades older) -- the
    same "check two of the AS's own declared sources against each other" pattern as
    the IRR-vs-live-AS-path check, but here both sides are things the AS itself
    published, so any mismatch is drift between the AS's own records, not just
    registry staleness.

    Schema verified against a real ASPA record (AS7575/AARNet, which has live
    adoption): each entry is {"customer_asn": ..., "providers": [{"asn": ..., "name": ...}, ...]}.

    Returns (paragraph_html, only_in_aspa, only_in_irr) -- the mismatch lists
    are exposed the same way build_irr_paragraph exposes stale/undeclared, so
    render() can add a findings-summary entry without recomputing the sets.
    """
    if customer_aspas is None:
        return (
            'Install BGPKIT\'s <code class="mono">monocle</code> (<code class="mono">brew install bgpkit/tap/monocle</code>) '
            f'and re-run to cross-check AS{asn}\'s ASPA-declared providers against its aut-num <code class="mono">import:</code> lines.'
        ), [], []
    aspa_provider_asns = {
        str(p["asn"]) for record in customer_aspas for p in record.get("providers", []) if p.get("asn") is not None
    }
    if not aspa_provider_asns:
        return (
            f'AS{asn} hasn\'t published any ASPA records naming its own valid providers, so there\'s nothing yet to '
            f'cross-check against its aut-num <code class="mono">import:</code> lines.'
        ), [], []
    fields = parse_autnum(autnum_raw)
    irr_provider_asns = set(re.findall(r'AS(\d+)', " ".join(fields["import"]))) - {str(asn)}
    only_in_aspa = sorted(aspa_provider_asns - irr_provider_asns, key=int)
    only_in_irr = sorted(irr_provider_asns - aspa_provider_asns, key=int)

    if not only_in_aspa and not only_in_irr:
        return (
            f'AS{asn}\'s ASPA-declared providers match its aut-num <code class="mono">import:</code> lines exactly '
            f'&mdash; {len(aspa_provider_asns)} provider{"s" if len(aspa_provider_asns) != 1 else ""} named in both.'
        ), only_in_aspa, only_in_irr
    parts = [
        f'AS{asn} has published ASPA records naming {len(aspa_provider_asns)} valid provider'
        f'{"s" if len(aspa_provider_asns) != 1 else ""}'
    ]
    if only_in_irr:
        verb = "isn" + "'" + "t" if len(only_in_irr) == 1 else "aren" + "'" + "t"
        parts.append(
            f', but its aut-num <code class="mono">import:</code> lines also reference '
            f'{", ".join("AS" + a for a in only_in_irr)}, which {verb} in the ASPA set'
        )
    if only_in_aspa:
        lead = "; " if only_in_irr else ", but "
        parts.append(
            f'{lead}ASPA additionally names {", ".join("AS" + a for a in only_in_aspa)} not mentioned in the '
            f'aut-num <code class="mono">import:</code> lines'
        )
    parts.append(
        ' &mdash; the two are meant to describe the same relationships, so a mismatch between them is worth reconciling.'
    )
    return "".join(parts), only_in_aspa, only_in_irr


def build_live_watch_block(msgs, asn, capture_seconds):
    if msgs is None:
        return (
            f'<div class="term"><div class="term-bar"><span class="mono">$ monocle watch --as-path {asn}</span>'
            '<span>RIPE RIS Live</span></div>'
            '<pre><span class="c">(skipped this run -- monocle not installed, or --live-watch-seconds 0)</span></pre></div>'
        )
    if not msgs:
        return (
            f'<div class="term"><div class="term-bar"><span class="mono">$ monocle watch --as-path {asn}</span>'
            '<span>RIPE RIS Live</span></div>'
            f'<pre><span class="c">(watched {capture_seconds}s, captured 0 exact AS{asn} matches this run -- '
            'BGP updates are bursty, try again or increase --live-watch-seconds)</span></pre></div>'
        )
    origin_count = sum(1 for m in msgs if m.get("origin_asns") == [asn])
    transit_count = len(msgs) - origin_count
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
    commentary = (
        f'{len(msgs)} {match_noun} in {capture_seconds}s: {origin_count} where AS{asn} originated the route itself, '
        f'{transit_count} where it was purely relaying someone else\'s.'
    )
    return (
        f'<div class="term"><div class="term-bar"><span class="mono">$ monocle watch --as-path {asn}</span>'
        '<span>RIPE RIS Live, live capture</span></div>'
        f'<pre>{pre}</pre></div>'
        f'<p style="margin-top:12px;">{commentary}</p>'
    )


def build_trend_findings(previous, current):
    """Compares this run's snapshot against the last one recorded for this ASN.
    Returns (chip_class, label, text) tuples in the same shape build_findings_block
    expects, so trend items slot into the existing "Notable this run" summary
    instead of a whole separate section."""
    if previous is None:
        return [("mute", "Trend", "First recorded run for this ASN &mdash; future runs will show what's changed since today.")]
    if previous.get("snapshot_date") == current["snapshot_date"]:
        return []  # already ran today; nothing meaningful to compare yet

    since = previous.get("snapshot_date", "the last run")
    findings = []

    prev_prefixes = set(previous.get("prefixes", []))
    cur_prefixes = set(current["prefixes"])
    added_p, removed_p = cur_prefixes - prev_prefixes, prev_prefixes - cur_prefixes
    if added_p or removed_p:
        parts = []
        if added_p:
            parts.append(f'+{len(added_p)}')
        if removed_p:
            parts.append(f'-{len(removed_p)}')
        findings.append(("info", "Trend", f'Prefixes changed since {since}: {" / ".join(parts)} (now {len(cur_prefixes)} total)'))

    prev_neighbours = set(previous.get("neighbour_asns", []))
    cur_neighbours = set(current["neighbour_asns"])
    added_n, removed_n = cur_neighbours - prev_neighbours, prev_neighbours - cur_neighbours
    if added_n or removed_n:
        parts = []
        if added_n:
            names = sorted(added_n, key=int)
            parts.append(f'+{"".join(f"AS{a} " for a in names[:5]).strip()}' + (f' and {len(names) - 5} more' if len(names) > 5 else ''))
        if removed_n:
            names = sorted(removed_n, key=int)
            parts.append(f'-{"".join(f"AS{a} " for a in names[:5]).strip()}' + (f' and {len(names) - 5} more' if len(names) > 5 else ''))
        findings.append(("info", "Trend", f'Neighbours changed since {since}: {" / ".join(parts)}'))

    if previous.get("homing_label") and previous["homing_label"] != current["homing_label"]:
        findings.append(("warn", "Trend", f'Topology changed since {since}: {previous["homing_label"]} &rarr; {current["homing_label"]}'))

    prev_undeclared = set(previous.get("irr_undeclared", []))
    cur_undeclared = set(current["irr_undeclared"])
    newly_undeclared = cur_undeclared - prev_undeclared
    resolved_undeclared = prev_undeclared - cur_undeclared
    if newly_undeclared:
        names = ", ".join(f"AS{a}" for a in sorted(newly_undeclared, key=int))
        findings.append(("warn", "Trend", f'Newly undeclared since {since}: {names} now live but missing from policy'))
    if resolved_undeclared:
        names = ", ".join(f"AS{a}" for a in sorted(resolved_undeclared, key=int))
        verb = "is" if len(resolved_undeclared) == 1 else "are"
        findings.append(("good", "Trend", f'Resolved since {since}: {names} {verb} no longer flagged as undeclared'))

    new_invalid = set(current["rpki_invalid_prefixes"]) - set(previous.get("rpki_invalid_prefixes", []))
    if new_invalid:
        findings.append(("bad", "Trend", f'New RPKI-invalid prefix{"es" if len(new_invalid) != 1 else ""} since {since}: {", ".join(sorted(new_invalid))}'))

    if not findings:
        findings.append(("good", "Trend", f'No material change since {since}.'))
    return findings


def build_findings_block(findings):
    """findings: list of (chip_class, label, html_text) tuples, most important
    first. Every check below already computes a pass/fail signal internally --
    this just collects them so a reader gets an at-a-glance verdict instead of
    having to read all 10 sections to notice, e.g., a missing ROA."""
    if not findings:
        return ""
    rows = "\n".join(
        f'      <div class="finding"><span class="chip {chip_class}">{label}</span><span>{text}</span></div>'
        for chip_class, label, text in findings
    )
    return f'<div class="highlights">\n      <h2>Notable this run</h2>\n{rows}\n    </div>'


# ---------------------------------------------------------------- render / main

def render(asn, timeout, template_path, live_watch_seconds=10, cache_ttl=0, cache_dir=".explorer_cache",
           history_dir=".explorer_history", track_history=True):
    def c(key, fn, *args, **kwargs):
        return cached(cache_dir, cache_ttl, f"{asn}:{key}", fn, *args, **kwargs)

    monocle_available = have_monocle()
    with ThreadPoolExecutor(max_workers=16) as pool:
        overview_future = pool.submit(c, "overview", get_overview, asn, timeout)
        prefixes_future = pool.submit(c, "prefixes", get_prefixes, asn, timeout)
        neighbours_future = pool.submit(c, "neighbours", get_neighbours, asn, timeout)
        route_objects_future = pool.submit(c, "route_objects_raw", get_route_objects_raw, asn, timeout)
        autnum_future = pool.submit(c, "autnum_raw", get_autnum_raw, asn, timeout)
        caida_future = pool.submit(c, "caida", get_caida, asn, timeout)
        pdb_future = pool.submit(c, "peeringdb", get_peeringdb, asn, timeout)

        overview = overview_future.result()
        prefixes = prefixes_future.result()
        neighbours = neighbours_future.result()
        # Resolved here (rather than down with the rest of the second-wave results)
        # so the undeclared-neighbour check below can inform which ASNs need a
        # holder-name lookup, before holders_future is submitted.
        autnum_raw = autnum_future.result()

        rpki_rows_future = pool.submit(c, "rpki_rows", get_rpki, asn, prefixes, timeout)
        paths_future = pool.submit(c, "paths", get_sample_paths, prefixes, timeout)
        moas_future = pool.submit(c, "moas", get_moas, prefixes, timeout)

        # Holders must be resolved for every ASN any builder might actually name:
        # the top-8-overall (table/diagram), the top-N "left" neighbours the prose
        # paragraph names (these two rankings can differ -- a network with many
        # high-power downstream customers can crowd its own upstreams out of the
        # top-8-overall), and any live neighbour the IRR check flags as undeclared
        # in policy (build_irr_paragraph names those too). Missing any of these
        # left the report showing literal "(?)" instead of a name.
        directional_neighbours = [n for n in neighbours if n.get("type") in ("left", "right")]
        autnum_fields_early = parse_autnum(autnum_raw)
        referenced_early = set(
            re.findall(r'AS(\d+)', " ".join(autnum_fields_early["import"] + autnum_fields_early["export"]))
        ) - {str(asn)}
        undeclared_early = {str(n.get("asn")) for n in directional_neighbours} - referenced_early

        left_neighbours = [n for n in neighbours if n.get("type") == "left"]
        top_overall = sorted(neighbours, key=lambda n: n.get("power", 0), reverse=True)[:8]
        top_left = sorted(left_neighbours, key=lambda n: n.get("power", 0), reverse=True)[:NEIGHBOUR_NAME_LIMIT]
        holder_asns = sorted(
            {str(n.get("asn")) for n in top_overall} | {str(n.get("asn")) for n in top_left} | undeclared_early,
            key=int,
        )
        holders_future = pool.submit(c, "neighbour_holders", get_neighbour_holders, holder_asns, timeout)

        top_neighbour = max(neighbours, key=lambda n: n.get("power", 0), default=None) if neighbours else None
        # Prefer cross-checking whichever neighbour the IRR check just flagged as
        # live-but-undeclared: a second, independent toolchain corroborating (or
        # casting doubt on) that specific finding is far more useful than as2rel
        # against just the biggest link, which usually isn't the interesting one.
        undeclared_candidates = [n for n in neighbours if str(n.get("asn")) in undeclared_early]
        if undeclared_candidates:
            as2rel_target = max(undeclared_candidates, key=lambda n: n.get("power", 0))
            as2rel_is_undeclared_check = True
        else:
            as2rel_target = top_neighbour
            as2rel_is_undeclared_check = False
        as2rel_target_asn = as2rel_target.get("asn") if as2rel_target else None

        live_watch_future = pool.submit(get_live_watch_sample, asn, live_watch_seconds)
        if monocle_available and as2rel_target_asn:
            as2rel_future = pool.submit(c, "as2rel", get_as2rel, asn, as2rel_target_asn, timeout)
        else:
            as2rel_future = None
        if monocle_available:
            aspa_customer_future = pool.submit(c, "aspa_customer", get_aspa, timeout, customer=asn)
            aspa_provider_future = pool.submit(c, "aspa_provider", get_aspa, timeout, provider=asn)
        else:
            aspa_customer_future = aspa_provider_future = None

        route_objects_raw = route_objects_future.result()
        caida = caida_future.result()
        pdb = pdb_future.result()
        rpki_rows = rpki_rows_future.result()
        paths = paths_future.result()
        # Distinct from `holders` (the subject's declared/live neighbours): this
        # resolves every ASN appearing anywhere in the captured paths, including
        # unrelated transit networks a route collector happened to reach through.
        path_asns = sorted({tok for p in paths for tok in path_lead_tokens(p["as_path"])}, key=int)
        path_holders_future = pool.submit(c, "path_holders", get_neighbour_holders, path_asns, timeout)
        moas = moas_future.result()
        holders = holders_future.result()
        path_holders = path_holders_future.result()
        live_watch_msgs = live_watch_future.result()
        as2rel = as2rel_future.result() if as2rel_future else None
        aspa_customer = aspa_customer_future.result() if aspa_customer_future else None
        aspa_provider = aspa_provider_future.result() if aspa_provider_future else None

    holder_name = overview.get("holder", f"AS{asn}")
    role_label, role_class = build_topology_role(neighbours)
    homing_label = build_homing_label(neighbours)
    rpki_json_block, notable = build_rpki_json_block(rpki_rows)
    irr_paragraph, irr_stale, irr_undeclared, irr_has_policy = build_irr_paragraph(asn, autnum_raw, neighbours, holders)
    moas_paragraph, moas_flagged = build_moas_paragraph(moas, len(prefixes))

    # Every check above already computes a pass/fail signal -- collect them here
    # so the page can lead with an at-a-glance verdict instead of requiring a
    # full read-through of all 10 sections to notice, e.g., a missing ROA.
    findings = []
    invalid_rpki = [r for r in rpki_rows if r["status"] == "invalid"]
    non_valid_rpki = [r for r in rpki_rows if r["status"] != "valid"]
    if rpki_rows:
        if invalid_rpki:
            # "invalid" is a real hijack signal and reads very differently from
            # "unknown" (no ROA at all, true for most of the Internet) -- lumping
            # them into one "no valid ROA" finding buried the one that matters.
            findings.append(("bad", "RPKI", f'{len(invalid_rpki)} of {len(rpki_rows)} checked prefixes are RPKI-invalid -- a real hijack signal (section 04)'))
        elif non_valid_rpki:
            findings.append(("warn", "RPKI", f'{len(non_valid_rpki)} of {len(rpki_rows)} checked prefixes have no ROA on file (section 04)'))
        else:
            findings.append(("good", "RPKI", f'All {len(rpki_rows)} checked prefixes have a valid ROA'))
    if not irr_has_policy:
        findings.append(("mute", "IRR", f'No import/export policy published for AS{asn} (section 05)'))
    else:
        if irr_stale:
            verb = "doesn" + "'" + "t" if len(irr_stale) == 1 else "don" + "'" + "t"
            findings.append(("warn", "IRR", f'{len(irr_stale)} declared neighbour{"s" if len(irr_stale) != 1 else ""} {verb} show up live (section 05)'))
        if irr_undeclared:
            verb = "isn" + "'" + "t" if len(irr_undeclared) == 1 else "aren" + "'" + "t"
            findings.append(("warn", "IRR", f'{len(irr_undeclared)} live neighbour{"s" if len(irr_undeclared) != 1 else ""} {verb} named in declared policy (section 05)'))
            # Close the loop opened above: when as2rel specifically targeted this
            # undeclared neighbour, say whether the second, independent toolchain
            # actually corroborates it -- otherwise the two checks never speak to
            # each other and a reader has to go compare section 05 against 08 by hand.
            if as2rel_is_undeclared_check and as2rel:
                connected_pct = parse_percent(as2rel.get("connected"))
                if connected_pct is not None and connected_pct >= 5:
                    findings.append(("info", "as2rel", f'Independent data corroborates it: {as2rel["connected"]} of vantage points see the AS{asn}&ndash;AS{as2rel_target_asn} link (section 08)'))
                elif connected_pct is not None:
                    findings.append(("mute", "as2rel", f'Independent data sees that link from only {as2rel["connected"]} of vantage points &mdash; inconclusive (section 08)'))
        if not irr_stale and not irr_undeclared:
            findings.append(("good", "IRR", "Declared policy matches observed reality"))
    if moas:
        if moas_flagged:
            findings.append(("warn", "MOAS", f'{len(moas_flagged)} prefix{"es" if len(moas_flagged) != 1 else ""} show multiple origins right now (section 06)'))
        else:
            findings.append(("good", "MOAS", "No multi-origin announcements detected"))
    v6_count = sum(1 for p in prefixes if ":" in p)
    if prefixes and v6_count == 0:
        findings.append(("mute", "IPv6", "No IPv6 prefixes announced"))

    aspa_irr_paragraph, aspa_only_in_aspa, aspa_only_in_irr = build_aspa_irr_paragraph(asn, aspa_customer, autnum_raw)
    if aspa_only_in_aspa or aspa_only_in_irr:
        findings.append(("warn", "ASPA", "ASPA-declared providers don't match aut-num import: lines (section 08)"))
    elif aspa_customer:  # non-empty and no mismatch -- a genuine, checked agreement worth noting
        findings.append(("good", "ASPA", "ASPA-declared providers match aut-num policy exactly"))

    # Trend: compare against the last recorded run for this ASN (a small,
    # always-on snapshot kept across runs -- separate from --cache-dir, which is
    # only for avoiding re-fetches within one session and is off by default).
    current_snapshot = {
        "snapshot_date": date.today().isoformat(),
        "prefixes": sorted(prefixes),
        "neighbour_asns": sorted({str(n.get("asn")) for n in neighbours}, key=int),
        "homing_label": homing_label,
        "irr_undeclared": sorted(irr_undeclared, key=int),
        "rpki_invalid_prefixes": sorted(r["prefix"] for r in invalid_rpki),
    }
    if track_history:
        previous_snapshot = load_history(asn, history_dir)
        findings.extend(build_trend_findings(previous_snapshot, current_snapshot))
        save_history(asn, history_dir, current_snapshot)

    values = {
        "ASN": asn,
        "HOLDER_NAME": holder_name,
        "SNAPSHOT_DATE": date.today().isoformat(),
        "HOMING_LABEL": homing_label,
        "FINDINGS_BLOCK": build_findings_block(findings),
        "OVERVIEW_PARAGRAPH": build_overview_paragraph(asn, overview, prefixes, holder_name),
        "PREFIX_COUNT": len(prefixes),
        "PREFIX_ROWS": build_prefix_rows(rpki_rows),
        "PREFIX_SAMPLE_NOTE": build_prefix_sample_note(len(rpki_rows), len(prefixes)),
        "NEIGHBOURS_PARAGRAPH": build_neighbours_paragraph(asn, neighbours, holders),
        "NEIGHBOUR_ROWS": build_top_neighbours_rows(neighbours, holders),
        "NEIGHBOUR_SAMPLE_NOTE": build_neighbour_sample_note(neighbours),
        "DIAGRAM_BLOCK": build_diagram_block(asn, holder_name, role_label, role_class, neighbours, holders),
        "PATHS_INTRO_SENTENCE": build_paths_intro(asn, paths),
        "PATHS_ROWS": build_paths_rows(paths),
        "PATHS_KEY_BLOCK": build_paths_key_block(paths, path_holders),
        "RPKI_JSON_BLOCK": rpki_json_block,
        "RPKI_PARAGRAPH": build_rpki_paragraph(asn, rpki_rows, notable, len(prefixes)),
        "ROUTE_OBJECTS_BLOCK": build_route_objects_block(asn, route_objects_raw),
        "AUTNUM_BLOCK": build_autnum_block(asn, autnum_raw),
        "IRR_PARAGRAPH": irr_paragraph,
        "MOAS_PARAGRAPH": moas_paragraph,
        "CAIDA_PARAGRAPH": build_caida_paragraph(asn, caida, len(prefixes)),
        "PEERINGDB_PARAGRAPH": build_peeringdb_paragraph(asn, pdb),
        "AS2REL_PARAGRAPH": build_as2rel_paragraph(asn, as2rel_target_asn, as2rel, as2rel_is_undeclared_check),
        "ASPA_PARAGRAPH": build_aspa_paragraph(asn, aspa_customer, aspa_provider),
        "ASPA_IRR_PARAGRAPH": aspa_irr_paragraph,
        "LIVE_WATCH_BLOCK": build_live_watch_block(live_watch_msgs, asn, live_watch_seconds),
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

    json_summary = {
        "asn": asn,
        "holder": holder_name,
        "snapshot_date": values["SNAPSHOT_DATE"],
        "prefix_count": len(prefixes),
        "ipv6_prefix_count": v6_count,
        "homing": homing_label.replace("&middot;", "·"),
        "neighbours": [
            {"asn": n.get("asn"), "holder": holders.get(str(n.get("asn"))), "type": n.get("type"), "power": n.get("power")}
            for n in neighbours
        ],
        "rpki": {
            "checked": len(rpki_rows),
            "valid": len(rpki_rows) - len(non_valid_rpki),
            "invalid_prefixes": [r["prefix"] for r in invalid_rpki],
            "unknown_prefixes": [r["prefix"] for r in rpki_rows if r["status"] == "unknown"],
        },
        "irr": {
            "has_policy": irr_has_policy,
            "stale_referenced_asns": irr_stale,
            "undeclared_live_asns": irr_undeclared,
        },
        "moas_flagged_prefixes": list(moas_flagged.keys()),
        "caida": caida,
        "peeringdb": pdb,
        "as2rel": {"target_asn": as2rel_target_asn, "is_undeclared_check": as2rel_is_undeclared_check, "result": as2rel},
        "aspa": {
            "customer": aspa_customer, "provider": aspa_provider,
            "only_in_aspa": aspa_only_in_aspa, "only_in_irr": aspa_only_in_irr,
        },
        "trend": {"tracked": track_history, "current_snapshot": current_snapshot},
    }
    return html, json_summary


def self_test():
    """Offline regression tests for the parsing/formatting logic -- no network calls."""
    failures = []
    total = 0

    def check(name, got, want):
        nonlocal total
        total += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    autnum_fixture = (
        "% [whois.apnic.net]\n"
        "\n"
        "aut-num:        AS64500\n"
        "as-name:        EXAMPLE-AS\n"
        "import:         from AS64501 accept ANY\n"
        "export:         to AS64501 announce AS64500\n"
        "mnt-by:         MAINT-EXAMPLE\n"
        "last-modified:  2020-01-01T00:00:00Z\n"
        "source:         APNIC\n"
        "\n"
        "irt:            IRT-EXAMPLE\n"
        "mnt-by:         MAINT-OTHER\n"
        "last-modified:  2026-01-01T00:00:00Z\n"
        "source:         APNIC\n"
    )
    parsed = parse_autnum(autnum_fixture)
    check("parse_autnum stops at end of aut-num block", parsed["last-modified"], "2020-01-01T00:00:00Z")
    check("parse_autnum mnt-by from aut-num, not later object", parsed["mnt-by"], "MAINT-EXAMPLE")
    check("parse_autnum import count", len(parsed["import"]), 1)

    routes_fixture = (
        "route:          198.51.100.0/24\n"
        "origin:         AS64500\n"
        "mnt-by:         MAINT-EXAMPLE\n"
        "source:         APNIC\n"
        "\n"
        "route:          203.0.113.0/24\n"
        "origin:         AS64500\n"
        "source:         APNIC\n"
    )
    routes = parse_route_objects(routes_fixture)
    check("parse_route_objects count", len(routes), 2)
    if len(routes) == 2:
        check("parse_route_objects[1] doesn't inherit block 0's mnt-by", routes[1].get("mnt-by"), None)

    check("prefix_size_label /24", prefix_size_label("203.0.113.0/24"), "256 addresses")
    check("prefix_size_label /16", prefix_size_label("198.51.0.0/16"), "65,536 addresses")

    check("build_topology_role stub", build_topology_role([{"type": "left", "asn": 1, "power": 5}]), ("Stub &middot; single-homed", "origin"))
    check(
        "build_topology_role transit",
        build_topology_role([{"type": "left", "asn": 1, "power": 5}, {"type": "right", "asn": 2, "power": 3}]),
        ("Transit &middot; multi-homed", "transit"),
    )
    check("build_topology_role isolated", build_topology_role([]), ("Isolated / no visible neighbours", "rest"))

    one_msg = [{
        "as_path": [64500, 64501], "origin_asns": [999], "prefix": "198.51.100.0/24",
        "type": "ANNOUNCE", "peer_asn": 1, "peer_ip": "1.1.1.1",
    }]
    block = build_live_watch_block(one_msg, 64501, 10)
    check("build_live_watch_block never says '1 exact matches' (regression)", "1 exact matches" in block, False)
    check("build_live_watch_block says '1 exact match' for a single message", "1 exact match" in block, True)

    irr_para_drift, irr_stale_t, irr_undeclared_t, irr_has_policy_t = build_irr_paragraph(
        64500, autnum_fixture, [{"asn": 999, "type": "left", "power": 1}], {})
    check("build_irr_paragraph flags stale reference", "AS64501" in irr_para_drift and "drift" in irr_para_drift, True)
    check("build_irr_paragraph exposes the stale list", irr_stale_t, ["64501"])
    check("build_irr_paragraph has_policy is True when import/export exist", irr_has_policy_t, True)
    irr_para_fresh, _, _, _ = build_irr_paragraph(64500, autnum_fixture, [{"asn": 64501, "type": "left", "power": 1}], {})
    check("build_irr_paragraph agrees when neighbour is live", "agree" in irr_para_fresh, True)

    # Regression: the original IRR check only caught declared-but-dead neighbours,
    # never a live neighbour missing from policy entirely (found for real: a
    # bank's DDoS-scrubbing upstream was live in AS-paths but absent from its
    # aut-num object).
    irr_para_undeclared, _, irr_undeclared_list, _ = build_irr_paragraph(
        64500, autnum_fixture,
        [{"asn": 64501, "type": "left", "power": 1}, {"asn": 64777, "type": "left", "power": 1}],
        {"64501": "EXAMPLE-NEIGHBOUR", "64777": "UNDOCUMENTED-NEIGHBOUR"},
    )
    check(
        "build_irr_paragraph flags a live-but-undeclared neighbour (regression)",
        "AS64777" in irr_para_undeclared and "UNDOCUMENTED-NEIGHBOUR" in irr_para_undeclared, True,
    )
    check("build_irr_paragraph doesn't mislabel an undeclared-only finding as drift", "drift" in irr_para_undeclared, False)
    check("build_irr_paragraph exposes the undeclared list too", irr_undeclared_list, ["64777"])

    # Regression: a single-prefix, single-upstream path sample used to be presented
    # with no caveat, which read as "this AS only has one active upstream" even for
    # a multi-homed AS -- misleading given get_sample_paths only checks 3 prefixes.
    narrow_paths = [
        {"prefix": "198.51.100.0/24", "location": "X", "as_path": "111 222 64500"},
        {"prefix": "198.51.100.0/24", "location": "Y", "as_path": "333 222 64500"},
    ]
    check("build_paths_intro adds a caveat for a single-prefix, single-upstream sample",
          "single-prefix sample" in build_paths_intro(64500, narrow_paths), True)
    broad_paths = [
        {"prefix": "198.51.100.0/24", "location": "X", "as_path": "111 222 64500"},
        {"prefix": "203.0.113.0/24", "location": "Y", "as_path": "333 444 64500"},
    ]
    check("build_paths_intro omits the caveat once the sample covers >1 prefix",
          "single-prefix sample" in build_paths_intro(64500, broad_paths), False)

    # build_moas_paragraph now returns (text, flagged) so render() can report a
    # MOAS hit in the findings summary without re-deriving it from the raw dict.
    moas_text_hit, moas_flagged_hit = build_moas_paragraph({"198.51.100.0/24": [64500, 64777]}, 1)
    check("build_moas_paragraph flags a real MOAS", "MOAS detected" in moas_text_hit, True)
    check("build_moas_paragraph exposes the flagged dict", moas_flagged_hit, {"198.51.100.0/24": [64500, 64777]})
    moas_text_clean, moas_flagged_clean = build_moas_paragraph({"198.51.100.0/24": [64500]}, 1)
    check("build_moas_paragraph reports no MOAS when origins agree", "No MOAS today" in moas_text_clean, True)
    check("build_moas_paragraph's flagged dict is empty when nothing is flagged", moas_flagged_clean, {})
    check("build_moas_paragraph discloses sampling like the RPKI/prefix sections do",
          "1 of 5 prefixes" in build_moas_paragraph({"198.51.100.0/24": [64500]}, 5)[0], True)
    check("build_moas_paragraph omits the sampling note when it checked everything",
          "of 1 prefixes" in build_moas_paragraph({"198.51.100.0/24": [64500]}, 1)[0], False)
    check("build_moas_paragraph never produces a double-parenthetical (regression)",
          ") (" in build_moas_paragraph({"198.51.100.0/24": [64500]}, 5)[0], False)

    # path_lead_tokens / build_paths_key_block: the key only covers "lead" hops
    # (everything before the up-hop) -- the origin and up-hop are already
    # highlighted in the path list and named elsewhere in the report (masthead,
    # section 02), so repeating them in the key would just be noise. Regression:
    # an earlier version keyed every hop including the already-known ones.
    check("path_lead_tokens excludes the up-hop and origin", path_lead_tokens("111 222 64500"), ["111"])
    check("path_lead_tokens is empty for a 2-hop path (just up-hop + origin)", path_lead_tokens("222 64500"), [])
    check("path_lead_tokens is empty for a single-hop (origin-only) path", path_lead_tokens("64500"), [])

    key_paths = [
        {"prefix": "198.51.100.0/24", "location": "X", "as_path": "111 222 64500"},
        {"prefix": "198.51.100.0/24", "location": "Y", "as_path": "333 222 64500"},
    ]
    key_holders = {"111": "FIRST-NET", "222": "MIDDLE-NET", "333": "OTHER-NET", "64500": "SUBJECT-AS"}
    key_block = build_paths_key_block(key_paths, key_holders)
    check("build_paths_key_block lists lead hops from every path", all(f"AS{a}" in key_block for a in ("111", "333")), True)
    check("build_paths_key_block omits the up-hop (already highlighted)", "AS222" in key_block, False)
    check("build_paths_key_block omits the origin (already named elsewhere)", "AS64500" in key_block, False)
    check("build_paths_key_block resolves holder names", "FIRST-NET" in key_block, True)
    check("build_paths_key_block returns nothing when there are no paths", build_paths_key_block([], {}), "")
    check("build_paths_key_block returns nothing when no path has a lead hop",
          build_paths_key_block([{"prefix": "x", "location": "X", "as_path": "222 64500"}], {}), "")

    # RPKI severity: "invalid" (a real hijack signal) must read differently from
    # "unknown" (no ROA at all -- true for most of the Internet, not alarming).
    invalid_row = {"prefix": "198.51.100.0/24", "status": "invalid", "validating_roas": []}
    unknown_row = {"prefix": "203.0.113.0/24", "status": "unknown", "validating_roas": []}
    valid_row = {"prefix": "192.0.2.0/24", "status": "valid", "validating_roas": []}
    rpki_block_json, rpki_notable = build_rpki_json_block([unknown_row, invalid_row, valid_row])
    check("build_rpki_json_block prioritizes an invalid ROA over a merely-unknown one",
          rpki_notable["status"], "invalid")
    invalid_para = build_rpki_paragraph(64500, [invalid_row, valid_row], invalid_row, 2)
    check("build_rpki_paragraph gives an invalid ROA the 'bad' chip, not 'warn'", 'chip bad">invalid' in invalid_para, True)
    check("build_rpki_paragraph calls an invalid ROA a hijack signal", "hijack signal" in invalid_para, True)
    unknown_para = build_rpki_paragraph(64500, [unknown_row, valid_row], unknown_row, 2)
    check("build_rpki_paragraph keeps 'unknown' at the milder 'warn' chip", 'chip warn">no ROA' in unknown_para, True)
    check("build_rpki_paragraph doesn't call a mere no-ROA prefix a hijack signal", "hijack signal" in unknown_para, False)
    check("build_prefix_rows gives invalid its own 'bad' chip class", 'chip bad">invalid' in build_prefix_rows([invalid_row]), True)

    # CAIDA/RIPEstat prefix-count reconciliation: two different sources with
    # different measurement schedules routinely disagree slightly -- that should
    # be acknowledged, not left for a reader to notice and wonder about.
    caida_fixture = {
        "asnName": "EXAMPLE-AS", "rank": 12345, "organization": {"orgName": "Example Org"},
        "asnDegree": {"provider": 1, "peer": 0, "customer": 0}, "cone": {"numberAsns": 1, "numberPrefixes": 100},
    }
    check("build_caida_paragraph flags a large prefix-count mismatch vs RIPEstat",
          "differs from RIPEstat" in build_caida_paragraph(64500, caida_fixture, 10), True)
    check("build_caida_paragraph stays quiet when the counts roughly agree",
          "differs from RIPEstat" in build_caida_paragraph(64500, caida_fixture, 98), False)

    # as2rel corroboration text (fed into the findings summary in render())
    check("parse_percent reads monocle's percentage strings", parse_percent("44.7%"), 44.7)
    check("parse_percent degrades to None instead of raising on bad input", parse_percent(None), None)

    # build_aspa_irr_paragraph: cross-checks the AS's own ASPA-declared providers
    # against its aut-num import: lines. Schema matches a real record (verified
    # against AS7575/AARNet's actual published ASPA data).
    aspa_customer_fixture = [
        {"customer_asn": 64500, "providers": [{"asn": 64501, "name": "EXAMPLE-PROVIDER"}, {"asn": 64777, "name": "OTHER-PROVIDER"}]},
    ]
    autnum_matching = "aut-num:        AS64500\nimport:         from AS64501 accept ANY\nimport:         from AS64777 accept ANY\n"
    match_text, match_only_aspa, match_only_irr = build_aspa_irr_paragraph(64500, aspa_customer_fixture, autnum_matching)
    check("build_aspa_irr_paragraph reports agreement when ASPA and aut-num match", "match" in match_text, True)
    check("build_aspa_irr_paragraph has no mismatch lists when everything agrees", (match_only_aspa, match_only_irr), ([], []))

    autnum_mismatch = "aut-num:        AS64500\nimport:         from AS64501 accept ANY\nimport:         from AS64999 accept ANY\n"
    mismatch_text, mismatch_only_aspa, mismatch_only_irr = build_aspa_irr_paragraph(64500, aspa_customer_fixture, autnum_mismatch)
    check("build_aspa_irr_paragraph flags a provider only in aut-num, not ASPA", "AS64999" in mismatch_text, True)
    check("build_aspa_irr_paragraph flags a provider only in ASPA, not aut-num", "AS64777" in mismatch_text, True)
    check("build_aspa_irr_paragraph exposes the only-in-IRR list", mismatch_only_irr, ["64999"])
    check("build_aspa_irr_paragraph exposes the only-in-ASPA list", mismatch_only_aspa, ["64777"])

    check("build_aspa_irr_paragraph handles monocle-not-installed gracefully",
          "Install BGPKIT" in build_aspa_irr_paragraph(64500, None, autnum_matching)[0], True)
    check("build_aspa_irr_paragraph handles no-ASPA-published gracefully",
          "hasn't published" in build_aspa_irr_paragraph(64500, [], autnum_matching)[0], True)

    # build_trend_findings: compares this run's snapshot against the last one.
    check("build_trend_findings announces a first-ever run", "First recorded run" in build_trend_findings(None, {"snapshot_date": "2026-01-01"})[0][2], True)

    same_snapshot = {"snapshot_date": "2026-01-01", "prefixes": ["1.2.3.0/24"], "neighbour_asns": ["64501"], "homing_label": "x", "irr_undeclared": [], "rpki_invalid_prefixes": []}
    check("build_trend_findings has nothing to say when re-run same-day", build_trend_findings(same_snapshot, same_snapshot), [])

    prev_snapshot = {
        "snapshot_date": "2026-01-01", "prefixes": ["1.2.3.0/24"], "neighbour_asns": ["64501"],
        "homing_label": "Single-homed", "irr_undeclared": [], "rpki_invalid_prefixes": [],
    }
    cur_snapshot = {
        "snapshot_date": "2026-01-08", "prefixes": ["1.2.3.0/24", "1.2.4.0/24"], "neighbour_asns": ["64501", "64777"],
        "homing_label": "Multi-homed &middot; 2 upstreams", "irr_undeclared": ["64777"], "rpki_invalid_prefixes": ["1.2.4.0/24"],
    }
    trend = build_trend_findings(prev_snapshot, cur_snapshot)
    trend_text = " | ".join(t[2] for t in trend)
    check("build_trend_findings notices a new prefix", "+1" in trend_text, True)
    check("build_trend_findings notices a new neighbour", "AS64777" in trend_text, True)
    check("build_trend_findings notices a topology change", "Topology changed" in trend_text, True)
    check("build_trend_findings notices a newly-undeclared neighbour", "Newly undeclared" in trend_text, True)
    check("build_trend_findings notices a new RPKI-invalid prefix (regression: severity-aware trend)", "New RPKI-invalid" in trend_text, True)

    no_change_cur = dict(prev_snapshot, snapshot_date="2026-01-08")
    no_change_trend = build_trend_findings(prev_snapshot, no_change_cur)
    check("build_trend_findings reports 'no material change' when nothing differs",
          any("No material change" in t[2] for t in no_change_trend), True)

    # build_as2rel_paragraph should explain *why* a neighbour was chosen when
    # it's the one section 05 flagged as undeclared, not just report the numbers.
    fake_rel = {"connected": "10%", "peer": "5%", "as1_upstream": "3%", "as2_upstream": "2%"}
    as2rel_flagged = build_as2rel_paragraph(64500, 64777, fake_rel, is_undeclared_check=True)
    check("build_as2rel_paragraph explains an undeclared-neighbour cross-check", "flagged it as live but missing" in as2rel_flagged, True)
    as2rel_plain = build_as2rel_paragraph(64500, 64777, fake_rel, is_undeclared_check=False)
    check("build_as2rel_paragraph stays plain for an ordinary top-neighbour check", "flagged it as live but missing" in as2rel_plain, False)

    # build_peeringdb_paragraph should surface IX presence (netixlan), not just
    # network type/policy -- this was fetched by bgp_lookup.py but dropped here.
    pdb_with_ix = {
        "name": "EXAMPLE-NET", "aka": None, "info_type": "Content", "policy_general": "Open", "irr_as_set": None,
        "exchanges": [{"ix_name": "Example-IX", "ipv4": "192.0.2.1", "ipv6": None, "speed_mbps": 10000}],
    }
    check("build_peeringdb_paragraph lists IX presence when netixlan has entries",
          "Example-IX" in build_peeringdb_paragraph(64500, pdb_with_ix), True)
    pdb_no_ix = {**pdb_with_ix, "exchanges": []}
    check("build_peeringdb_paragraph says so when there's no IX presence",
          "No public IX presence" in build_peeringdb_paragraph(64500, pdb_no_ix), True)

    # build_findings_block
    check("build_findings_block returns empty string for no findings", build_findings_block([]), "")
    findings_html = build_findings_block([("warn", "RPKI", "1 prefix has no valid ROA")])
    check("build_findings_block renders a finding's chip class and text",
          'chip warn' in findings_html and "1 prefix has no valid ROA" in findings_html, True)

    if failures:
        print(f"SELF-TEST FAILED: {len(failures)} of {total} checks failed:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return False
    print(f"Self-test passed: {total} checks OK.")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asn", nargs="?", type=int, default=None, help="ASN to look up (required unless --self-test)")
    parser.add_argument("--out", default=None, help="output HTML path (default: as<ASN>_explorer.html)")
    parser.add_argument("--template", default="explorer_template.html", help="template path")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    parser.add_argument(
        "--live-watch-seconds", type=float, default=10.0,
        help="how long to capture live RIPE RIS Live traffic for this ASN via monocle watch (0 to skip)",
    )
    parser.add_argument(
        "--cache-ttl", type=float, default=0.0,
        help="reuse fetched results younger than this many seconds instead of re-fetching (0 disables caching; "
             "never applies to the live BGP capture)",
    )
    parser.add_argument("--cache-dir", default=".explorer_cache", help="where cached results are stored")
    parser.add_argument(
        "--history-dir", default=".explorer_history",
        help="where per-ASN snapshots are kept across runs, to report what's changed since last time",
    )
    parser.add_argument(
        "--no-history", action="store_true",
        help="don't read or write the trend snapshot (skip the 'since last run' comparison entirely)",
    )
    parser.add_argument(
        "--json", metavar="PATH", default=None,
        help="also write a structured JSON summary of findings (prefixes, neighbours, RPKI/IRR/MOAS results) to PATH",
    )
    parser.add_argument(
        "--self-test", action="store_true",
        help="run offline regression checks against the parsing/formatting logic and exit (no network calls)",
    )
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    if args.asn is None:
        parser.error("an ASN is required (unless --self-test)")

    out_path = args.out or f"as{args.asn}_explorer.html"
    html, json_summary = render(
        args.asn, args.timeout, args.template, args.live_watch_seconds, args.cache_ttl, args.cache_dir,
        args.history_dir, not args.no_history,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {out_path}  ({dt.now(timezone.utc).isoformat(timespec='seconds')})")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(json_summary, f, indent=2, default=str)
        print(f"Full structured summary written to {args.json}")


if __name__ == "__main__":
    main()
