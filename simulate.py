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
# RPDemo  (dynamic responsible probing algorithm)
# ---------------------------------------------------------------------------


class RPDemo:
    def __init__(self, num_dirs: int, impact_capacity: float, const: float = 1):
        self._p: dict[int, float] = {i: 1.0 for i in range(num_dirs)}
        self._A: dict[str, set[int]] = dict()
        self._Ar: dict[int, set[str]] = {i: set() for i in range(num_dirs)}
        self._C: float = impact_capacity
        self._const: float = const

    def add(self, directive_id: int, address: str) -> None:
        # if the directive_id is not known.
        if not directive_id in self._p:
            return

        # update the address if it is not seed before
        self._A[address] = self._A.get(address, set())
        self._Ar[directive_id] = self._Ar.get(directive_id, set())

        # populate the new addresses
        self._A[address].add(directive_id)
        self._Ar[directive_id].add(address)

        self._update_prob(directive_id)

    def remove(self, directive_id: int, address: str) -> None:
        # if the directive_id is not known.
        if not directive_id in self._p:
            return

        # update the address if it is not seed before
        self._A[address] = self._A.get(address, set())
        self._Ar[directive_id] = self._Ar.get(directive_id, set())

        # populate the new addresses
        self._A[address].remove(directive_id)
        self._Ar[directive_id].remove(address)

        self._update_prob(directive_id)

        # if there are non directives, remove address from map.
        if not self._A[address]:
            del self._A[address]

    def _update_prob(self, directive_id: int) -> None:
        candidates = {len(self._A.get(a, set())) for a in self._Ar[directive_id]}
        if not candidates:
            # no address seen, always issue
            self._p[directive_id] = 1.0
        else:
            # cap between 0 and 1.
            denom = max(candidates)
            self._p[directive_id] = min(max(self._const / denom, 0.0), 1.0)

    def get_probability(self, directive_id: int) -> float:
        return self._p.get(directive_id, 0.0)


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
    last_hit_near_address: Optional[str] = None
    last_hit_far_address: Optional[str] = None


class Scheduler:
    """
    Issues ProbingDirectives in randomized order and tracks address impact.
    """

    def __init__(
        self,
        seed: int,
        issue_rate: float,  # probes per second
        pds: list[ProbingDirective],
        impact_cap: float,
    ) -> None:
        if not pds:
            raise ValueError("pds cannot be empty")
        if issue_rate <= 0:
            raise ValueError("issue_rate must have a positive non-zero value")

        self._directive_map: dict[int, DirectiveMapEntry] = {
            pd.probing_directive_id: DirectiveMapEntry(directive=pd) for pd in pds
        }
        self._rp = RPDemo(num_dirs=len(pds), impact_capacity=impact_cap)
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

    def update(self, fie: ForwardingInfoElement) -> None:
        """Update address impact bookkeeping after receiving a FIE."""
        entry = self._directive_map.get(fie.probing_directive_id)
        if entry is None:
            raise KeyError(f"Unknown probing_directive_id: {fie.probing_directive_id}")

        old_near = entry.last_hit_near_address
        old_far = entry.last_hit_far_address

        entry.last_hit_near_address = fie.near_addr
        entry.last_hit_far_address = fie.far_addr

        # Remove old addresses if changed
        if old_near != fie.near_addr and old_near is not None:
            self._rp.remove(fie.probing_directive_id, old_near)
        if old_far != fie.far_addr and old_far is not None:
            self._rp.remove(fie.probing_directive_id, old_far)

        # Add new addresses
        if fie.near_addr is not None:
            self._rp.add(fie.probing_directive_id, fie.near_addr)
        if fie.far_addr is not None:
            self._rp.add(fie.probing_directive_id, fie.far_addr)

    def issuance_prob(self, pd_id: int) -> float | None:
        return self._rp.get_probability(pd_id)

    def snapshot_issuance_probs(self) -> dict[int, float]:
        """Return a snapshot of {directive_id: issuance_prob} for all directives."""
        return {pd_id: self._rp.get_probability(pd_id) for pd_id in self._directive_map}

    def snapshot_impact_table(self) -> dict[str, dict[int, float]]:
        """
        Return a snapshot of the full address impact table:
            { address: { directive_id: issuance_prob, ... }, ... }
        """
        return {
            address: {d: self._rp.get_probability(d) for d in directive_ids}
            for address, directive_ids in self._rp._A.items()
        }

    def impact_count(self, address: Optional[str]) -> Optional[int]:
        if address is None or address not in self._rp._A:
            return None
        return len(self._rp._A[address])


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
    """

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
        path: list[str] = [self.SOURCE_IP]
        current = self.SOURCE_IP

        for _ in range(max_ttl):
            router_table = self._table.get(current)
            if router_table is None:
                break
            next_hops = router_table.get(destination) or router_table.get("*")
            if not next_hops:
                break
            current = self._rng.choice(next_hops)
            path.append(current)
            if current == destination:
                break

        return path

    def _hop_ip(self, path: list[str], ttl: int) -> Optional[str]:
        if ttl < len(path):
            return path[ttl]
        return path[-1]

    def probe(self, pd: ProbingDirective) -> Optional[ForwardingInfoElement]:
        if self._rng.random() < self._loss_prob:
            return None

        far_ttl = pd.near_ttl + 1
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
        duration: float,
        issue_rate: float,
        impact_cap: float,
        loss_prob: float,
        forwarding_table: ForwardingTable,
        pds: list[ProbingDirective],
        output_path: str = "simulation_results.json",
    ) -> None:
        self._duration = duration
        self._impact_cap = impact_cap
        self._output_path = output_path

        self._rng = random.Random(seed + 1)
        self._prober = Prober(forwarding_table, self._rng, loss_prob)
        self._scheduler = Scheduler(
            seed=seed, issue_rate=issue_rate, pds=pds, impact_cap=impact_cap
        )
        self._events: list[SimulationEvent] = []
        self._cumulative_impacts: dict[str, int] = {}
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
                self._scheduler.update(fie)
                for addr in (fie.near_addr, fie.far_addr):
                    if addr is not None:
                        self._cumulative_impacts[addr] = (
                            self._cumulative_impacts.get(addr, 0) + 1
                        )

            # 4. Record event
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
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--issue-rate", type=float, default=40.0)
    parser.add_argument("--impact-cap", type=float, default=0.5)
    parser.add_argument("--loss-prob", type=float, default=0.05)
    parser.add_argument("--output", type=str, default="./sim/results/results.json")
    parser.add_argument("--topology", type=str, default="./sim/topology/topology.json")
    parser.add_argument("--pds", type=str, default="./sim/pds/pds.json")
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
    sim._params = vars(args)
    sim.run()
