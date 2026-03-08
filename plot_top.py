#!/usr/bin/python3
"""
Topology Plotter
================
Reads a forwarding table JSON and renders the network as a directed graph,
saved to ./sim/plots/topology.png.

Source node (10.0.0.1) is drawn in red; all other nodes in blue.
Dashed edges represent default gateway ("*") routes.

Usage:
    python plot_topology.py --topology topology.json
    python plot_topology.py --topology topology.json --output ./sim/plots/topology.png
"""

from __future__ import annotations

import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import networkx as nx


SOURCE_IP = "10.0.0.1"
COLOR_SOURCE = "#e05252"  # red
COLOR_NODE = "#5285e0"  # blue
COLOR_EDGE = "#aaaaaa"
COLOR_DEFAULT_EDGE = "#e0a030"  # amber for default gateway edges
BG_COLOR = "#1a1a2e"


def load_forwarding_table(path: str) -> dict[str, dict[str, list[str]]]:
    with open(path) as f:
        return json.load(f)


def build_graph(table: dict) -> tuple[nx.DiGraph, set[tuple[str, str]]]:
    """
    Build a DiGraph from the forwarding table.
    Returns the graph and the set of (src, dst) edges that are default gateway routes.
    """
    G = nx.DiGraph()
    default_edges: set[tuple[str, str]] = set()

    for router, routes in table.items():
        G.add_node(router)
        seen: dict[str, bool] = {}  # next_hop -> is_default_only

        for dest, hops in routes.items():
            is_default = dest == "*"
            for hop in hops:
                G.add_node(hop)
                if (router, hop) not in seen:
                    G.add_edge(router, hop)
                    seen[(router, hop)] = is_default
                elif not is_default:
                    # A specific route also uses this hop: mark as non-default
                    seen[(router, hop)] = False

        for (src, dst), is_def in seen.items():
            if is_def:
                default_edges.add((src, dst))

    return G, default_edges


def hierarchical_layout(G: nx.DiGraph, table: dict) -> dict[str, tuple[float, float]]:
    """Assign positions by layer using topological ordering from source."""
    # BFS from source to assign layers
    layers: dict[str, int] = {}
    queue = [SOURCE_IP]
    layers[SOURCE_IP] = 0
    while queue:
        node = queue.pop(0)
        for nb in G.successors(node):
            if nb not in layers:
                layers[nb] = layers[node] + 1
                queue.append(nb)

    # Group nodes by layer
    from collections import defaultdict

    layer_nodes: dict[int, list[str]] = defaultdict(list)
    for node, layer in layers.items():
        layer_nodes[layer].append(node)

    pos: dict[str, tuple[float, float]] = {}
    for layer, nodes in layer_nodes.items():
        nodes_sorted = sorted(nodes)
        n = len(nodes_sorted)
        for i, node in enumerate(nodes_sorted):
            x = (i - (n - 1) / 2.0) * 2.8
            y = -layer * 2.2
            pos[node] = (x, y)

    return pos


def plot(table: dict, output_path: str) -> None:
    G, default_edges = build_graph(table)
    pos = hierarchical_layout(G, table)

    specific_edges = [(u, v) for u, v in G.edges() if (u, v) not in default_edges]
    default_edge_list = [(u, v) for u, v in G.edges() if (u, v) in default_edges]

    node_colors = [COLOR_SOURCE if n == SOURCE_IP else COLOR_NODE for n in G.nodes()]

    fig, ax = plt.subplots(figsize=(15, 11))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    edge_kwargs = dict(
        ax=ax,
        pos=pos,
        arrowsize=16,
        arrowstyle="-|>",
        connectionstyle="arc3,rad=0.05",
        width=1.4,
        min_source_margin=20,
        min_target_margin=20,
    )

    # Specific route edges (solid)
    nx.draw_networkx_edges(
        G,
        edgelist=specific_edges,
        edge_color=COLOR_EDGE,
        style="solid",
        **edge_kwargs,
    )

    # Default gateway edges (dashed, amber)
    nx.draw_networkx_edges(
        G,
        edgelist=default_edge_list,
        edge_color=COLOR_DEFAULT_EDGE,
        style="dashed",
        **edge_kwargs,
    )

    # Nodes
    nx.draw_networkx_nodes(
        G,
        pos,
        ax=ax,
        node_color=node_colors,
        node_size=950,
        linewidths=0.5,
        edgecolors="#ffffff",
    )

    # Legend
    legend_handles = [
        mlines.Line2D(
            [],
            [],
            color=COLOR_SOURCE,
            marker="o",
            markersize=10,
            linestyle="None",
            label="Source (10.0.0.1)",
        ),
        mlines.Line2D(
            [],
            [],
            color=COLOR_NODE,
            marker="o",
            markersize=10,
            linestyle="None",
            label="Router / Host",
        ),
        mlines.Line2D(
            [],
            [],
            color=COLOR_EDGE,
            linewidth=1.5,
            linestyle="solid",
            label="Specific route",
        ),
        mlines.Line2D(
            [],
            [],
            color=COLOR_DEFAULT_EDGE,
            linewidth=1.5,
            linestyle="dashed",
            label="Default gateway (*)",
        ),
    ]
    ax.legend(
        handles=legend_handles,
        loc="lower right",
        framealpha=0.3,
        facecolor="#2a2a4a",
        edgecolor="#aaaaaa",
        labelcolor="#ffffff",
        fontsize=9,
    )

    # Labels
    nx.draw_networkx_labels(
        G,
        pos,
        ax=ax,
        font_size=14,
        font_color="#ffffff",
        font_family="monospace",
        bbox=dict(
            facecolor="#000000", edgecolor="none", alpha=0.7, boxstyle="round,pad=0.2"
        ),
    )

    ax.set_title("Network Topology", color="#ffffff", fontsize=14, pad=16)
    ax.axis("off")
    plt.tight_layout()

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    plt.savefig(
        output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor()
    )
    print(f"Topology plot saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Plot the network topology from a forwarding table JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--topology",
        type=str,
        default="./sim/topology/topology.json",
        help="Path to the forwarding table JSON",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./sim/plots/topology.png",
        help="Output PNG file path",
    )
    args = parser.parse_args()

    table = load_forwarding_table(args.topology)
    plot(table, args.output)
