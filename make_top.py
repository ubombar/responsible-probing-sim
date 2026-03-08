#!/usr/bin/python3
"""
Topology Generator
==================
Generates a forwarding table for a simulated network and writes it to a JSON
file.

The forwarding table structure:

    {
        "<router_ip>": {
            "<destination_ip>": ["<next_hop_ip>", ...],
            "*":                ["<next_hop_ip>", ...],   <- default gateway
            ...
        },
        ...
    }

The "*" key is a default gateway entry. When the prober looks up a destination
on a router and finds no specific entry, it falls back to "*". This mirrors how
real routers work: edge and distribution routers only know their local subnets
explicitly; everything else is sent upstream via the default gateway.

Specific routes are only installed where the router has direct knowledge:
  - Edge routers know their one directly attached destination.
  - All other upstream traffic uses "*" toward the core.
  - Distribution routers know their downstream edges specifically.
  - Core routers know which distribution router serves each destination.
  - Source knows the two cores; uses "*" toward core_a as default.

Network layout:

    [source: 10.0.0.1]
         /          \\
  [core_a: 10.0.1.1]  [core_b: 10.0.1.2]
       /     \\              /      \\
  [dist_a] [dist_b]    [dist_b]  [dist_c]
  10.0.2.1 10.0.2.2   10.0.2.2  10.0.2.3
    / \\       / \\        / \\       / \\
   e1  e2   e3  e4     e3  e4   e5  e6
   |   |    |   |      |   |    |   |
   d1  d2   d3  d4     d3  d4   d5  d6

Usage:
    python generate_topology.py --output topology.json
"""

from __future__ import annotations

import argparse
import json


NODES: dict[str, str] = {
    "source": "10.0.0.1",
    "core_a": "10.0.1.1",
    "core_b": "10.0.1.2",
    "dist_a": "10.0.2.1",
    "dist_b": "10.0.2.2",
    "dist_c": "10.0.2.3",
    "edge_1": "10.0.3.1",
    "edge_2": "10.0.3.2",
    "edge_3": "10.0.3.3",
    "edge_4": "10.0.3.4",
    "edge_5": "10.0.3.5",
    "edge_6": "10.0.3.6",
    "dest_1": "10.0.4.1",
    "dest_2": "10.0.4.2",
    "dest_3": "10.0.4.3",
    "dest_4": "10.0.4.4",
    "dest_5": "10.0.4.5",
    "dest_6": "10.0.4.6",
}

ip = NODES.__getitem__


def build_forwarding_table() -> dict[str, dict[str, list[str]]]:
    """
    Build the forwarding table with default gateway ("*") entries.

    Design rules:
      - Edge routers: specific route for their one destination; "*" toward
        their distribution router (upstream default).
      - Distribution routers: specific routes for their downstream
        destinations; "*" toward core_a (upstream default).
      - Core routers: specific routes for all destinations they serve;
        "*" toward the other core (upstream default for unknown dests).
      - Source: specific routes to both cores; "*" toward core_a as default.
    """
    table: dict[str, dict[str, list[str]]] = {}

    # ── Edge routers ──────────────────────────────────────────────────────────
    # edge_1 -> dest_1 specifically; everything else upstream via dist_a
    edge_dist_map = {
        "edge_1": ("dest_1", "dist_a"),
        "edge_2": ("dest_2", "dist_a"),
        "edge_3": ("dest_3", "dist_b"),
        "edge_4": ("dest_4", "dist_b"),
        "edge_5": ("dest_5", "dist_c"),
        "edge_6": ("dest_6", "dist_c"),
    }
    for edge, (dest, dist) in edge_dist_map.items():
        table[ip(edge)] = {
            ip(dest): [ip(dest)],  # directly attached destination
            "*": [ip(dist)],  # default: send upstream
        }

    # ── Distribution routers ──────────────────────────────────────────────────
    # dist_a serves dest_1 and dest_2 via edge_1 and edge_2
    table[ip("dist_a")] = {
        ip("dest_1"): [ip("edge_1")],
        ip("dest_2"): [ip("edge_2")],
        "*": [ip("core_a")],  # default gateway upstream
    }
    # dist_b serves dest_3 and dest_4 via edge_3 and edge_4
    table[ip("dist_b")] = {
        ip("dest_3"): [ip("edge_3")],
        ip("dest_4"): [ip("edge_4")],
        "*": [ip("core_a"), ip("core_b")],  # ECMP toward both cores
    }
    # dist_c serves dest_5 and dest_6 via edge_5 and edge_6
    table[ip("dist_c")] = {
        ip("dest_5"): [ip("edge_5")],
        ip("dest_6"): [ip("edge_6")],
        "*": [ip("core_b")],  # default gateway upstream
    }

    # ── Core routers ──────────────────────────────────────────────────────────
    # core_a serves dist_a (dest_1, dest_2) and dist_b (dest_3, dest_4)
    table[ip("core_a")] = {
        ip("dest_1"): [ip("dist_a")],
        ip("dest_2"): [ip("dist_a")],
        ip("dest_3"): [ip("dist_b")],
        ip("dest_4"): [ip("dist_b")],
        "*": [ip("core_b")],  # unknown destinations: try peer core
    }
    # core_b serves dist_b (dest_3, dest_4) and dist_c (dest_5, dest_6)
    table[ip("core_b")] = {
        ip("dest_3"): [ip("dist_b")],
        ip("dest_4"): [ip("dist_b")],
        ip("dest_5"): [ip("dist_c")],
        ip("dest_6"): [ip("dist_c")],
        "*": [ip("core_a")],  # unknown destinations: try peer core
    }

    # ── Source ────────────────────────────────────────────────────────────────
    # Source knows both cores; ECMP for dest_3/dest_4 (reachable via either).
    table[ip("source")] = {
        ip("dest_1"): [ip("core_a")],
        ip("dest_2"): [ip("core_a")],
        ip("dest_3"): [ip("core_a"), ip("core_b")],  # ECMP
        ip("dest_4"): [ip("core_a"), ip("core_b")],  # ECMP
        ip("dest_5"): [ip("core_b")],
        ip("dest_6"): [ip("core_b")],
        "*": [ip("core_a")],  # default gateway
    }

    return table


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a network forwarding table with default gateways.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./sim/topology/topology.json",
        help="Output JSON file path",
    )
    args = parser.parse_args()

    table = build_forwarding_table()

    with open(args.output, "w") as f:
        json.dump(table, f, indent=2)

    print(f"Forwarding table written to: {args.output}")
    print(f"  Routers            : {len(table)}")
    dest_ips = {d for routes in table.values() for d in routes if d != "*"}
    print(f"  Specific dst entries: {len(dest_ips)}")
    print(f"  Routers with '*'   : {sum(1 for r in table.values() if '*' in r)}")
    print()
    print("Source routes (10.0.0.1):")
    for dest, hops in sorted(table[ip("source")].items()):
        print(f"  -> {dest:<14} : {hops}")
