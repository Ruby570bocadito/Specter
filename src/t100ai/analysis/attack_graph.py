"""Attack Graph Builder - Finds all exploitation paths in a network."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AttackNode:
    """A node in the attack graph (host, service, vulnerability)."""
    id: str
    node_type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    compromised: bool = False


@dataclass
class AttackEdge:
    """An edge representing an exploitation path between nodes."""
    source: str
    target: str
    technique: str
    cvss: float = 0.0
    mitre_id: str = ""
    description: str = ""


class AttackGraph:
    """Builds and analyzes attack graphs for network pentesting.

    Uses BFS/DFS to find all paths from entry points to critical assets.
    Identifies the most critical nodes using graph centrality.

    Usage:
        graph = AttackGraph()
        graph.add_node("host1", "host", "Web Server", {"os": "linux"})
        graph.add_node("vuln1", "vuln", "CVE-2024-1234", {"cvss": 9.8})
        graph.add_edge("host1", "vuln1", "exploit", 9.8, "T1190")
        paths = graph.find_attack_paths("entry", "crown_jewel")
    """

    def __init__(self) -> None:
        self._nodes: dict[str, AttackNode] = {}
        self._edges: list[AttackEdge] = []
        self._adj: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, label: str, **properties: Any) -> None:
        """Add a node to the attack graph."""
        self._nodes[node_id] = AttackNode(
            id=node_id, node_type=node_type, label=label, properties=properties
        )

    def add_edge(self, source: str, target: str, technique: str, cvss: float = 0.0,
                 mitre_id: str = "", description: str = "") -> None:
        """Add an exploitation path between two nodes."""
        edge = AttackEdge(source, target, technique, cvss, mitre_id, description)
        self._edges.append(edge)
        self._adj[source].append(target)

    def find_attack_paths(self, start: str, goal: str) -> list[list[str]]:
        """Find all attack paths from start to goal using DFS."""
        if start not in self._nodes or goal not in self._nodes:
            return []

        paths = []
        stack = [(start, [start])]

        while stack:
            node, path = stack.pop()
            if node == goal:
                paths.append(path)
                continue
            for neighbor in self._adj.get(node, []):
                if neighbor not in path:
                    stack.append((neighbor, path + [neighbor]))

        return paths

    def find_shortest_path(self, start: str, goal: str) -> Optional[list[str]]:
        """Find the shortest attack path using BFS."""
        if start not in self._nodes or goal not in self._nodes:
            return None

        queue = deque([(start, [start])])
        visited = {start}

        while queue:
            node, path = queue.popleft()
            if node == goal:
                return path
            for neighbor in self._adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def get_critical_nodes(self, top_n: int = 5) -> list[dict[str, Any]]:
        """Find the most critical nodes using PageRank-like centrality."""
        in_degree: dict[str, int] = defaultdict(int)
        out_degree: dict[str, int] = defaultdict(int)

        for edge in self._edges:
            in_degree[edge.target] += 1
            out_degree[edge.source] += 1

        scores = {}
        for node_id, node in self._nodes.items():
            cvss = node.properties.get("cvss", 0.0)
            centrality = in_degree.get(node_id, 0) + out_degree.get(node_id, 0)
            score = (cvss * 0.6) + (centrality * 0.4 * 10.0 / max(len(self._nodes), 1))
            scores[node_id] = round(min(10.0, score), 1)

        sorted_nodes = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [
            {
                "id": nid,
                "label": self._nodes[nid].label,
                "type": self._nodes[nid].node_type,
                "criticality_score": score,
                "in_degree": in_degree.get(nid, 0),
                "out_degree": out_degree.get(nid, 0),
            }
            for nid, score in sorted_nodes
        ]

    def get_stats(self) -> dict[str, Any]:
        """Return graph statistics."""
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "node_types": {nt: sum(1 for n in self._nodes.values() if n.node_type == nt)
                          for nt in set(n.node_type for n in self._nodes.values())},
            "avg_cvss": round(
                sum(e.cvss for e in self._edges) / max(len(self._edges), 1), 1
            ),
        }

    def export_dot(self) -> str:
        """Export graph as DOT format for visualization."""
        lines = ["digraph AttackGraph {", '  rankdir=LR;']
        for nid, node in self._nodes.items():
            color = {"host": "blue", "vuln": "red", "service": "green"}.get(node.node_type, "gray")
            lines.append(f'  "{nid}" [label="{node.label}", color={color}];')
        for edge in self._edges:
            label = f"{edge.technique}\\nCVSS:{edge.cvss}"
            lines.append(f'  "{edge.source}" -> "{edge.target}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)
