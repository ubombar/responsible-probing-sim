#!/usr/bin/python3
"""
Retina Responsible Prober Simulation
=====================================
Python port of the Go scheduler + randomizer, with a network topology
simulator and event logging.

Usage:
    python retina_simulation.py
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ProbingDirective:
    probing_directive_id: int
    destination_addr: str
    near_ttl: int


@dataclass
class ForwardingInfoElement:
    probing_directive_id: int
    near_addr: Optional[str]
    near_ttl: int
    far_addr: Optional[str]
    far_ttl: int


@dataclass
class SimulationEvent:
    """One complete probe cycle recorded during the simulation."""

    event_id: int
    wall_time: float  # seconds since simulation start
    probing_directive_id: int
    destination_addr: str
    near_ttl: int
    far_ttl: int
    probe_success: bool  # False when Bernoulli experiment fails
    near_addr: Optional[str]
    far_addr: Optional[str]
    # Scheduler state snapshot after update
    # { directive_id: issuance_prob } for all directives
    issuance_probs: dict[int, float]
    # { address: { directive_id: issuance_prob } } — full impact table
    impact_table: dict[str, dict[int, float]]
    # Cumulative probe hits per IP address since simulation start
    cumulative_impact_counts: dict[str, int]


# ---------------------------------------------------------------------------
# Randomizer  (Fisher-Yates, mirrors the Go implementation)
# ---------------------------------------------------------------------------


class Randomizer:
    """
    Incremental Fisher-Yates shuffle over a list of indices.
    Each full pass through all indices is one 'cycle'.
    """

    def __init__(self, seed: int, indices: list[int]) -> None:
        if not indices:
            raise ValueError("indices array cannot be empty")
        self._rng = random.Random(seed)
        self._indices = list(indices)
        self._length = len(self._indices)
        self._i = self._length - 1
        self._cycle = 0

    def next(self) -> int:
        if self._i < 0:
            self._cycle += 1
            self._i = self._length - 1

        j = self._rng.randint(0, self._i)
        k = self._indices[j]
        self._indices[self._i], self._indices[j] = (
            self._indices[j],
            self._indices[self._i],
        )
        self._i -= 1
        return k

    @property
    def cycle(self) -> int:
        return self._cycle


# ---------------------------------------------------------------------------
# Scheduler  (mirrors the Go implementation)
# ---------------------------------------------------------------------------


@dataclass
class DirectiveMapEntry:
    directive: ProbingDirective
    issuance_prob: float = 1.0
    last_hit_near_address: Optional[str] = None
    last_hit_far_address: Optional[str] = None


@dataclass
class AddressImpactMapEntry:
    directives: dict[int, DirectiveMapEntry] = field(default_factory=dict)

    def normalize_greedy(self, impact_cap: float) -> None:
        """Redistribute issuance probabilities so total impact <= impact_cap."""
        if float(len(self.directives)) > impact_cap:
            probs = sorted(
                self.directives.values(), key=lambda e: e.issuance_prob, reverse=True
            )
            remaining = impact_cap
            n = len(probs)
            for i, v in enumerate(probs):
                if remaining <= 0:
                    v.issuance_prob = 0.0
                else:
                    share = remaining / (n - i)
                    if v.issuance_prob > share:
                        v.issuance_prob = share
                    remaining -= v.issuance_prob


class AddressImpactMap:
    def __init__(self) -> None:
        self._map: dict[str, AddressImpactMapEntry] = {}

    def update_and_normalize(
        self,
        old_address: Optional[str],
        new_address: Optional[str],
        entry: DirectiveMapEntry,
        impact_cap: float,
    ) -> None:
        if old_address == new_address:
            return

        # Remove from old address bucket
        if old_address is not None and old_address in self._map:
            bucket = self._map[old_address]
            bucket.directives.pop(entry.directive.probing_directive_id, None)
            if not bucket.directives:
                del self._map[old_address]

        # Insert into new address bucket and normalize
        if new_address is not None:
            if new_address not in self._map:
                self._map[new_address] = AddressImpactMapEntry(
                    directives={entry.directive.probing_directive_id: entry}
                )
            else:
                self._map[new_address].directives[
                    entry.directive.probing_directive_id
                ] = entry
            self._map[new_address].normalize_greedy(impact_cap)

    def impact_count(self, address: Optional[str]) -> Optional[int]:
        if address is None or address not in self._map:
            return None
        return len(self._map[address].directives)


class Scheduler:
    """
    Issues ProbingDirectives in randomized order and tracks address impact.
    """

    def __init__(
        self,
        seed: int,
        issue_rate: float,  # probes per second
        pds: list[ProbingDirective],
    ) -> None:
        if not pds:
            raise ValueError("pds cannot be empty")
        if issue_rate <= 0:
            raise ValueError("issue_rate must have a positive non-zero value")

        self._directive_map: dict[int, DirectiveMapEntry] = {
            pd.probing_directive_id: DirectiveMapEntry(directive=pd) for pd in pds
        }
        self._address_impact_map = AddressImpactMap()
        self._issue_period = 1.0 / issue_rate
        self._last_issue: float = 0.0
        self._randomizer = Randomizer(seed, list(self._directive_map.keys()))

    def issue(self) -> ProbingDirective:
        """Return the next ProbingDirective, respecting the rate limit."""
        idx = self._randomizer.next()
        entry = self._directive_map[idx]

        # Rate limiting
        now = time.monotonic()
        next_allowed = self._last_issue + self._issue_period
        if next_allowed > now:
            time.sleep(next_allowed - now)
        self._last_issue = time.monotonic()

        return entry.directive

    def update(self, fie: ForwardingInfoElement, impact_cap: float) -> None:
        """Update address impact bookkeeping after receiving a FIE."""
        entry = self._directive_map.get(fie.probing_directive_id)
        if entry is None:
            raise KeyError(f"Unknown probing_directive_id: {fie.probing_directive_id}")

        old_near = entry.last_hit_near_address
        old_far = entry.last_hit_far_address

        entry.last_hit_near_address = fie.near_addr
        entry.last_hit_far_address = fie.far_addr

        self._address_impact_map.update_and_normalize(
            old_near, fie.near_addr, entry, impact_cap
        )
        self._address_impact_map.update_and_normalize(
            old_far, fie.far_addr, entry, impact_cap
        )

    def issuance_prob(self, pd_id: int) -> float:
        return self._directive_map[pd_id].issuance_prob

    def impact_count(self, address: Optional[str]) -> Optional[int]:
        return self._address_impact_map.impact_count(address)

    def snapshot_issuance_probs(self) -> dict[int, float]:
        """Return a snapshot of {directive_id: issuance_prob} for all directives."""
        return {
            pd_id: entry.issuance_prob for pd_id, entry in self._directive_map.items()
        }

    def snapshot_impact_table(self) -> dict[str, dict[int, float]]:
        """
        Return a snapshot of the full address impact table:
            { address: { directive_id: issuance_prob, ... }, ... }
        """
        return {
            address: {
                pd_id: entry.issuance_prob for pd_id, entry in bucket.directives.items()
            }
            for address, bucket in self._address_impact_map._map.items()
        }


# ---------------------------------------------------------------------------
# Network Topology + Prober
# ---------------------------------------------------------------------------

# ForwardingTable type alias
# router_ip -> destination_ip -> list of next_hop_ips
ForwardingTable = dict[str, dict[str, list[str]]]


def load_forwarding_table(path: str) -> ForwardingTable:
    """Load a forwarding table from a JSON file."""
    with open(path) as f:
        return json.load(f)


def load_probing_directives(path: str) -> list[ProbingDirective]:
    """
    Load a list of ProbingDirectives from a JSON file.

    Expected format:
        [
            {"probing_directive_id": 1, "destination_addr": "10.0.4.1", "near_ttl": 2},
            ...
        ]
    """
    with open(path) as f:
        raw = json.load(f)
    return [
        ProbingDirective(
            probing_directive_id=entry["probing_directive_id"],
            destination_addr=entry["destination_addr"],
            near_ttl=entry["near_ttl"],
        )
        for entry in raw
    ]


class Prober:
    """
    Simulates sending TTL-limited probes through a network described by a
    forwarding table.

    The forwarding table has the structure:
        router_ip -> destination_ip -> [next_hop_ip, ...]

    When a packet is forwarded at each hop, one next hop is chosen randomly
    from the list (ECMP). This choice is made independently at every hop and
    every probe, so different probes to the same destination may take different
    paths.

    For a given ProbingDirective (destination_addr, near_ttl):
      - Probe at near_ttl   -> IP of the router at that hop
      - Probe at near_ttl+1 -> IP of the router at the next hop

    If the Bernoulli experiment fails, returns None (packet loss / no reply).
    """

    # The source is the ingress router from which all probes originate.
    SOURCE_IP = "10.0.0.1"

    def __init__(
        self,
        forwarding_table: ForwardingTable,
        rng: random.Random,
        loss_prob: float,
    ) -> None:
        self._table = forwarding_table
        self._rng = rng
        self._loss_prob = loss_prob

    def _follow_path(self, destination: str, max_ttl: int) -> list[str]:
        """
        Simulate a packet traversal from SOURCE_IP toward destination,
        recording the IP at each hop up to max_ttl.

        At each router, the next hop is resolved as follows:
          1. Look up the destination IP specifically.
          2. If not found, fall back to the "*" default gateway entry.
          3. If neither exists, the path ends (no route).

        One next hop is chosen randomly from the matched list (ECMP).
        Returns a list of router IPs visited, starting from SOURCE_IP.
        """
        path: list[str] = [self.SOURCE_IP]
        current = self.SOURCE_IP

        for _ in range(max_ttl):
            router_table = self._table.get(current)
            if router_table is None:
                break  # router not in table, path ends
            # Specific route first, then default gateway wildcard
            next_hops = router_table.get(destination) or router_table.get("*")
            if not next_hops:
                break  # no route and no default gateway
            current = self._rng.choice(next_hops)
            path.append(current)
            if current == destination:
                break  # reached destination

        return path

    def _hop_ip(self, path: list[str], ttl: int) -> Optional[str]:
        """Return the IP at hop `ttl`, or None if the path is too short."""
        if ttl < len(path):
            return path[ttl]
        return path[-1]  # reply from the host

    def probe(self, pd: ProbingDirective) -> Optional[ForwardingInfoElement]:
        """
        Issue two probes (near_ttl and near_ttl+1) toward the destination.
        Each probe independently follows the forwarding table hop-by-hop,
        picking randomly among equal-cost next hops at each router.
        Returns a FIE, or None if the Bernoulli experiment fails.
        """
        if self._rng.random() < self._loss_prob:
            return None

        far_ttl = pd.near_ttl + 1

        # Walk the path far enough to cover both TTLs in one traversal.
        path = self._follow_path(pd.destination_addr, far_ttl)

        near_addr = self._hop_ip(path, pd.near_ttl)
        far_addr = self._hop_ip(path, far_ttl)

        return ForwardingInfoElement(
            probing_directive_id=pd.probing_directive_id,
            near_addr=near_addr,
            near_ttl=pd.near_ttl,
            far_addr=far_addr,
            far_ttl=far_ttl,
        )


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------


class Simulator:
    """
    Drives the scheduler + prober loop for `duration` wall-clock seconds,
    records every event, and writes results to a JSON file.
    """

    def __init__(
        self,
        seed: int,
        duration: float,  # seconds to run
        issue_rate: float,  # probes per second
        impact_cap: float,  # max probes per address
        loss_prob: float,  # probability of probe getting no reply
        forwarding_table: ForwardingTable,
        pds: list[ProbingDirective],
        output_path: str = "simulation_results.json",
    ) -> None:
        self._duration = duration
        self._impact_cap = impact_cap
        self._output_path = output_path

        # Single shared RNG for everything except the scheduler's randomizer
        # (scheduler uses its own seeded RNG internally via Randomizer)
        self._rng = random.Random(seed + 1)

        self._prober = Prober(forwarding_table, self._rng, loss_prob)
        self._scheduler = Scheduler(seed=seed, issue_rate=issue_rate, pds=pds)
        self._events: list[SimulationEvent] = []
        # Cumulative probe hit counter per IP address, across all events
        self._cumulative_impacts: dict[str, int] = {}
        # Simulation parameters saved verbatim into the output JSON
        self._params: dict = {}

    def run(self) -> None:
        print(f"Starting simulation for {self._duration}s ...")
        start = time.monotonic()
        event_id = 0

        while (time.monotonic() - start) < self._duration:
            wall_time = time.monotonic() - start

            # 1. Get next directive from scheduler
            pd = self._scheduler.issue()

            # 2. Send probes via prober
            fie = self._prober.probe(pd)

            probe_success = fie is not None

            # 3. Update scheduler only on success
            if probe_success:
                self._scheduler.update(fie, self._impact_cap)
                # Increment cumulative hit counters for near and far addresses
                for addr in (fie.near_addr, fie.far_addr):
                    if addr is not None:
                        self._cumulative_impacts[addr] = (
                            self._cumulative_impacts.get(addr, 0) + 1
                        )

            # 4. Record event — snapshot the full cumulative impact map
            event = SimulationEvent(
                event_id=event_id,
                wall_time=round(wall_time, 6),
                probing_directive_id=pd.probing_directive_id,
                destination_addr=pd.destination_addr,
                near_ttl=pd.near_ttl,
                far_ttl=pd.near_ttl + 1,
                probe_success=probe_success,
                near_addr=fie.near_addr if fie else None,
                far_addr=fie.far_addr if fie else None,
                issuance_probs=self._scheduler.snapshot_issuance_probs(),
                impact_table=self._scheduler.snapshot_impact_table(),
                cumulative_impact_counts=dict(self._cumulative_impacts),
            )
            self._events.append(event)
            event_id += 1

        print(f"Simulation complete. {len(self._events)} events recorded.")
        self._save(self._params)

    def _save(self, params: dict) -> None:
        output = {
            "parameters": params,
            "total_events": len(self._events),
            "successful_probes": sum(1 for e in self._events if e.probe_success),
            "failed_probes": sum(1 for e in self._events if not e.probe_success),
            "events": [asdict(e) for e in self._events],
        }
        import os

        os.makedirs(os.path.dirname(os.path.abspath(self._output_path)), exist_ok=True)
        with open(self._output_path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Results saved to {self._output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Retina responsible prober simulation.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="RNG seed for deterministic runs"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Simulation duration in wall-clock seconds",
    )
    parser.add_argument(
        "--issue-rate", type=float, default=40.0, help="Probes issued per second"
    )
    parser.add_argument(
        "--impact-cap",
        type=float,
        default=1.0,
        help="Max active directives per address",
    )
    parser.add_argument(
        "--loss-prob",
        type=float,
        default=0.1,
        help="Probability of a probe receiving no reply (0.0-1.0)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./sim/results/results.json",
        help="Path for the JSON output file",
    )
    parser.add_argument(
        "--topology",
        type=str,
        default="./sim/topology/topology.json",
        help="Path to the forwarding table JSON (produced by generate_topology.py)",
    )
    parser.add_argument(
        "--pds",
        type=str,
        default="./sim/pds/pds.json",
        help="Path to the probing directives JSON (produced by generate_pds.py)",
    )
    args = parser.parse_args()

    forwarding_table = load_forwarding_table(args.topology)
    pds = load_probing_directives(args.pds)

    sim = Simulator(
        seed=args.seed,
        duration=args.duration,
        issue_rate=args.issue_rate,
        impact_cap=args.impact_cap,
        loss_prob=args.loss_prob,
        forwarding_table=forwarding_table,
        pds=pds,
        output_path=args.output,
    )
    sim._params = {
        "seed": args.seed,
        "duration": args.duration,
        "issue_rate": args.issue_rate,
        "impact_cap": args.impact_cap,
        "loss_prob": args.loss_prob,
        "topology": args.topology,
        "pds": args.pds,
        "output": args.output,
    }
    sim.run()
