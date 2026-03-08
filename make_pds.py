#!/usr/bin/python3
"""
Probing Directive Generator
============================
Generates a list of ProbingDirectives and writes them to a JSON file.

PDs are derived from a forwarding table: destination IPs are any address that
appears as a routing target but is never itself a router (i.e. leaf nodes).
The near_ttl for each PD is assigned randomly within a configurable range.

Output format:
    [
        {"probing_directive_id": 1, "destination_addr": "10.0.4.1", "near_ttl": 2},
        ...
    ]

Usage:
    python generate_pds.py --topology topology.json --output pds.json
    python generate_pds.py --topology topology.json --output pds.json --min-ttl 1 --max-ttl 4 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random


def load_forwarding_table(path: str) -> dict[str, dict[str, list[str]]]:
    with open(path) as f:
        return json.load(f)


def derive_destinations(table: dict[str, dict[str, list[str]]]) -> list[str]:
    """
    Return all IPs that appear as destinations in the forwarding table but
    are never themselves a router (i.e. leaf / host nodes).
    """
    all_routers = set(table.keys())
    all_destinations: set[str] = set()
    for routes in table.values():
        all_destinations.update(routes.keys())
    return sorted(all_destinations - all_routers)


def generate_pds(
    destinations: list[str],
    min_ttl: int,
    max_ttl: int,
    rng: random.Random,
) -> list[dict]:
    return [
        {
            "probing_directive_id": i,
            "destination_addr": dest,
            "near_ttl": rng.randint(min_ttl, max_ttl),
        }
        for i, dest in enumerate(destinations, start=1)
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate probing directives from a forwarding table.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--topology",
        type=str,
        default="./sim/topology/topology.json",
        help="Path to the forwarding table JSON",
    )
    parser.add_argument(
        "--output", type=str, default="./sim/pds/pds.json", help="Output JSON file path"
    )
    parser.add_argument("--min-ttl", type=int, default=2, help="Minimum near_ttl value")
    parser.add_argument("--max-ttl", type=int, default=2, help="Maximum near_ttl value")
    parser.add_argument(
        "--seed", type=int, default=42, help="RNG seed for TTL assignment"
    )
    args = parser.parse_args()

    if args.min_ttl > args.max_ttl:
        raise ValueError(
            f"--min-ttl ({args.min_ttl}) cannot exceed --max-ttl ({args.max_ttl})"
        )

    rng = random.Random(args.seed)
    table = load_forwarding_table(args.topology)
    destinations = derive_destinations(table)

    if not destinations:
        raise ValueError("No leaf destinations found in the forwarding table.")

    pds = generate_pds(destinations, args.min_ttl, args.max_ttl, rng)

    with open(args.output, "w") as f:
        json.dump(pds, f, indent=2)

    print(f"Probing directives written to: {args.output}")
    print(f"  Count       : {len(pds)}")
    print(f"  TTL range   : {args.min_ttl} - {args.max_ttl}")
    print()
    for pd in pds:
        print(
            f"  PD {pd['probing_directive_id']:>3} | dest={pd['destination_addr']:<12} near_ttl={pd['near_ttl']}"
        )
