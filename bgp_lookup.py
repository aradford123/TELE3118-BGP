#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests>=2.31.0",
# ]
# ///
"""Interrogate public BGP/routing data sources for a given ASN.

Usage:
    uv run bgp_lookup.py [ASN] [--json out.json] [--timeout 10]

Default ASN is 23859 (UNSW).
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

RIPESTAT_BASE = "https://stat.ripe.net/data"
CAIDA_ASRANK_URL = "https://api.asrank.caida.org/v2/graphql"
PEERINGDB_BASE = "https://www.peeringdb.com/api"


def safe_call(name, func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        print(f"[warning] {name} failed: {exc}", file=sys.stderr)
        return {"error": str(exc)}


def ripestat(endpoint, params, timeout):
    resp = requests.get(f"{RIPESTAT_BASE}/{endpoint}/data.json", params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["data"]


def get_as_overview(asn, timeout):
    return ripestat("as-overview", {"resource": f"AS{asn}"}, timeout)


def get_announced_prefixes(asn, timeout):
    data = ripestat("announced-prefixes", {"resource": f"AS{asn}"}, timeout)
    return [p["prefix"] for p in data.get("prefixes", [])]


def get_asn_neighbours(asn, timeout):
    return ripestat("asn-neighbours", {"resource": f"AS{asn}"}, timeout)


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
                    paths.append({"prefix": prefix, "rrc": rrc.get("location"), "as_path": as_path})
                if len(paths) >= max_paths:
                    return paths
    return paths


def get_rpki_validation(asn, prefixes, timeout, max_prefixes=5):
    results = []
    for prefix in prefixes[:max_prefixes]:
        try:
            data = ripestat("rpki-validation", {"resource": f"AS{asn}", "prefix": prefix}, timeout)
            results.append({"prefix": prefix, "status": data.get("status")})
        except Exception as exc:
            print(f"[warning] rpki-validation for {prefix} failed: {exc}", file=sys.stderr)
    return results


def get_caida_asrank(asn, timeout):
    query = """
    query ($asn: String!) {
      asn(asn: $asn) {
        asn
        asnName
        rank
        organization { orgName }
        cliqueMember
        cone { numberAsns numberPrefixes numberAddresses }
        asnDegree { provider peer customer total }
      }
    }
    """
    resp = requests.post(
        CAIDA_ASRANK_URL,
        json={"query": query, "variables": {"asn": str(asn)}},
        timeout=timeout,
    )
    resp.raise_for_status()
    payload = resp.json()
    if "errors" in payload:
        raise RuntimeError(payload["errors"])
    return payload["data"]["asn"]


def get_peeringdb(asn, timeout):
    resp = requests.get(f"{PEERINGDB_BASE}/net", params={"asn": asn}, timeout=timeout)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    nets = resp.json().get("data", [])
    if not nets:
        return None
    net = nets[0]
    ixlan_resp = requests.get(f"{PEERINGDB_BASE}/netixlan", params={"net_id": net["id"]}, timeout=timeout)
    ixlan_resp.raise_for_status()
    exchanges = [
        {"ix_name": ix.get("name"), "ipv4": ix.get("ipaddr4"), "ipv6": ix.get("ipaddr6"), "speed_mbps": ix.get("speed")}
        for ix in ixlan_resp.json().get("data", [])
    ]
    return {
        "name": net.get("name"),
        "aka": net.get("aka"),
        "info_type": net.get("info_type"),
        "policy_general": net.get("policy_general"),
        "policy_url": net.get("policy_url"),
        "irr_as_set": net.get("irr_as_set"),
        "website": net.get("website"),
        "exchanges": exchanges,
    }


def whois_query(server, query, timeout):
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    return response.decode(errors="replace")


def parse_route_objects(raw_text):
    routes = []
    current = {}
    for line in raw_text.splitlines():
        if not line.strip():
            if current:
                routes.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in ("route", "route6"):
            current["route"] = value
        elif key == "origin":
            current["origin"] = value
        elif key == "descr" and "descr" not in current:
            current["descr"] = value
    if current:
        routes.append(current)
    return [r for r in routes if "route" in r]


def parse_autnum(raw_text):
    policy = {"as-name": None, "descr": [], "import": [], "export": [], "mp-import": [], "mp-export": []}
    for line in raw_text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "as-name":
            policy["as-name"] = value
        elif key == "descr":
            policy["descr"].append(value)
        elif key in ("import", "export", "mp-import", "mp-export"):
            policy[key].append(value)
    return policy


def get_irr_policy(asn, timeout):
    routes_raw = whois_query("whois.radb.net", f"-i origin AS{asn}", timeout)
    routes = parse_route_objects(routes_raw)

    autnum_raw = whois_query("whois.radb.net", f"AS{asn}", timeout)
    if "import:" not in autnum_raw and "export:" not in autnum_raw:
        try:
            autnum_raw = whois_query("whois.apnic.net", f"AS{asn}", timeout)
        except Exception as exc:
            print(f"[warning] APNIC whois fallback failed: {exc}", file=sys.stderr)

    policy = parse_autnum(autnum_raw)
    return {"declared_routes": routes, "policy": policy}


def collect(asn, timeout):
    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            "as_overview": pool.submit(safe_call, "as_overview", get_as_overview, asn, timeout),
            "announced_prefixes": pool.submit(safe_call, "announced_prefixes", get_announced_prefixes, asn, timeout),
            "asn_neighbours": pool.submit(safe_call, "asn_neighbours", get_asn_neighbours, asn, timeout),
            "caida_asrank": pool.submit(safe_call, "caida_asrank", get_caida_asrank, asn, timeout),
            "peeringdb": pool.submit(safe_call, "peeringdb", get_peeringdb, asn, timeout),
            "irr_policy": pool.submit(safe_call, "irr_policy", get_irr_policy, asn, timeout),
        }
        for key, future in futures.items():
            results[key] = future.result()

    prefixes = results["announced_prefixes"] if isinstance(results["announced_prefixes"], list) else []
    results["sample_paths"] = safe_call("sample_paths", get_sample_paths, prefixes, timeout)
    results["rpki_validation"] = safe_call("rpki_validation", get_rpki_validation, asn, prefixes, timeout)
    return results


def section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_report(asn, results):
    print(f"BGP connectivity report for AS{asn}")

    section("AS Overview")
    overview = results["as_overview"]
    if "error" in overview:
        print(f"  (unavailable: {overview['error']})")
    else:
        print(f"  Holder: {overview.get('holder')}")
        print(f"  Announced: {overview.get('announced')}")

    section("Announced Prefixes")
    prefixes = results["announced_prefixes"]
    if isinstance(prefixes, dict) and "error" in prefixes:
        print(f"  (unavailable: {prefixes['error']})")
    else:
        print(f"  Total: {len(prefixes)}")
        for p in prefixes[:20]:
            print(f"    {p}")
        if len(prefixes) > 20:
            print(f"    ... and {len(prefixes) - 20} more")

    section("Neighbours (Upstreams / Peers / Downstreams)")
    neighbours = results["asn_neighbours"]
    if isinstance(neighbours, dict) and "error" in neighbours:
        print(f"  (unavailable: {neighbours['error']})")
    else:
        for n in neighbours.get("neighbours", []):
            print(f"  AS{n.get('asn')}  type={n.get('type')}  power={n.get('power')}")

    section("Sample AS Paths (live, from RIS)")
    paths = results["sample_paths"]
    if isinstance(paths, dict) and "error" in paths:
        print(f"  (unavailable: {paths['error']})")
    elif not paths:
        print("  (none found)")
    else:
        for p in paths:
            print(f"  [{p['rrc']}] {p['prefix']}: {p['as_path']}")

    section("RPKI Validation (sample of announced prefixes)")
    rpki = results["rpki_validation"]
    if isinstance(rpki, dict) and "error" in rpki:
        print(f"  (unavailable: {rpki['error']})")
    else:
        for r in rpki:
            print(f"  {r['prefix']}: {r['status']}")

    section("CAIDA ASRank")
    caida = results["caida_asrank"]
    if isinstance(caida, dict) and "error" in caida:
        print(f"  (unavailable: {caida['error']})")
    elif not caida:
        print("  (no CAIDA record found)")
    else:
        org = (caida.get("organization") or {}).get("orgName")
        degree = caida.get("asnDegree") or {}
        cone = caida.get("cone") or {}
        print(f"  Name: {caida.get('asnName')}  Org: {org}")
        print(f"  Rank: {caida.get('rank')}  Clique member: {caida.get('cliqueMember')}")
        print(f"  Degree: providers={degree.get('provider')} peers={degree.get('peer')} customers={degree.get('customer')}")
        print(f"  Customer cone: {cone.get('numberAsns')} ASNs, {cone.get('numberPrefixes')} prefixes")

    section("PeeringDB")
    pdb = results["peeringdb"]
    if isinstance(pdb, dict) and "error" in pdb:
        print(f"  (unavailable: {pdb['error']})")
    elif not pdb:
        print("  (no PeeringDB record found)")
    else:
        print(f"  Name: {pdb.get('name')} ({pdb.get('aka')})")
        print(f"  Type: {pdb.get('info_type')}  Policy: {pdb.get('policy_general')}")
        print(f"  IRR AS-SET: {pdb.get('irr_as_set')}")
        for ix in pdb.get("exchanges", []):
            print(f"    IX: {ix['ix_name']}  v4={ix['ipv4']}  v6={ix['ipv6']}  speed={ix['speed_mbps']}Mbps")

    section("IRR Declared Policy")
    irr = results["irr_policy"]
    if isinstance(irr, dict) and "error" in irr:
        print(f"  (unavailable: {irr['error']})")
    else:
        routes = irr.get("declared_routes", [])
        print(f"  Declared route objects: {len(routes)}")
        for r in routes[:10]:
            print(f"    {r.get('route')} origin={r.get('origin')}")
        if len(routes) > 10:
            print(f"    ... and {len(routes) - 10} more")
        policy = irr.get("policy", {})
        print(f"  as-name: {policy.get('as-name')}")
        for label in ("import", "export", "mp-import", "mp-export"):
            lines = policy.get(label, [])
            if lines:
                print(f"  {label}:")
                for line in lines:
                    print(f"    {line}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asn", nargs="?", type=int, default=23859, help="ASN to look up (default: 23859, UNSW)")
    parser.add_argument("--json", metavar="PATH", help="also write full results as JSON to PATH")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    args = parser.parse_args()

    results = collect(args.asn, args.timeout)
    print_report(args.asn, results)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nFull results written to {args.json}")


if __name__ == "__main__":
    main()
