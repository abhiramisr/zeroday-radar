"""
Graph Visualizer for Attack Paths
Creates visual representations of infrastructure and attack paths
"""

import networkx as nx
from typing import List, Dict, Optional
from dataclasses import dataclass

class GraphVisualizer:
    """Visualizes infrastructure graphs and attack paths"""

    def __init__(self, graph: nx.DiGraph):
        """
        Initialize visualizer

        Args:
            graph: NetworkX directed graph of infrastructure
        """
        self.graph = graph

    def visualize_ascii(self, highlight_paths: Optional[List[List[str]]] = None) -> str:
        """
        Create ASCII art visualization of the graph

        Args:
            highlight_paths: Paths to highlight (attack paths)

        Returns:
            ASCII art string representation
        """
        output = []
        output.append("\n" + "=" * 70)
        output.append("  INFRASTRUCTURE TOPOLOGY")
        output.append("=" * 70 + "\n")

        # Get all nodes and organize by level
        levels = self._compute_levels()

        # Create path set for highlighting
        path_edges = set()
        if highlight_paths:
            for path in highlight_paths:
                for i in range(len(path) - 1):
                    path_edges.add((path[i], path[i+1]))

        # Display by levels
        for level, nodes in sorted(levels.items()):
            output.append(f"Level {level}:")
            for node in nodes:
                node_attrs = self.graph.nodes[node]
                node_type = node_attrs.get('type', 'unknown')
                is_critical = node_attrs.get('critical', False)
                exposure = node_attrs.get('exposure', '')

                # Node symbol
                if is_critical:
                    symbol = "🎯"
                elif exposure == "internet":
                    symbol = "🌐"
                elif node_type == "database":
                    symbol = "💾"
                elif node_type == "api":
                    symbol = "⚡"
                elif node_type == "web":
                    symbol = "🌍"
                else:
                    symbol = "📦"

                critical_marker = " [CRITICAL]" if is_critical else ""
                output.append(f"  {symbol} {node}{critical_marker}")

                # Show connections
                successors = list(self.graph.successors(node))
                if successors:
                    for succ in successors:
                        edge_marker = "═══>" if (node, succ) in path_edges else "───>"
                        output.append(f"      {edge_marker} {succ}")

            output.append("")

        return "\n".join(output)

    def visualize_attack_path(self, path: List[str], risk_score: float) -> str:
        """
        Visualize a single attack path

        Args:
            path: List of nodes in the attack path
            risk_score: Risk score for the path

        Returns:
            Formatted string representation
        """
        output = []

        # Risk level indicator
        if risk_score >= 8:
            risk_emoji = "🔴"
            risk_level = "CRITICAL"
        elif risk_score >= 6:
            risk_emoji = "🟠"
            risk_level = "HIGH"
        elif risk_score >= 4:
            risk_emoji = "🟡"
            risk_level = "MEDIUM"
        else:
            risk_emoji = "🟢"
            risk_level = "LOW"

        output.append(f"\n{risk_emoji} Risk Score: {risk_score:.1f}/10 ({risk_level})")
        output.append(f"Attack Path ({len(path)} hops):")
        output.append("")

        # Draw the path
        for i, node in enumerate(path):
            node_attrs = self.graph.nodes.get(node, {})
            node_type = node_attrs.get('type', 'unknown')
            is_critical = node_attrs.get('critical', False)

            # Node symbol
            if is_critical:
                symbol = "🎯"
            elif i == 0:
                symbol = "🚪"  # Entry point
            elif node_type == "database":
                symbol = "💾"
            elif node_type == "api":
                symbol = "⚡"
            elif node_type == "web":
                symbol = "🌍"
            else:
                symbol = "📦"

            # Node info
            prefix = f"  Step {i+1}: " if i > 0 else "  Entry:  "
            output.append(f"{prefix}{symbol} {node}")

            # Draw arrow to next node
            if i < len(path) - 1:
                output.append("           ⬇️")

        return "\n".join(output)

    def generate_report(self, attack_paths: List, top_n: int = 5) -> str:
        """
        Generate comprehensive visual report

        Args:
            attack_paths: List of AttackPath objects
            top_n: Number of top paths to show

        Returns:
            Formatted report string
        """
        output = []

        output.append("\n" + "╔" + "═" * 68 + "╗")
        output.append("║" + " " * 68 + "║")
        output.append("║" + "  VULNPATH ANALYSIS REPORT".center(68) + "║")
        output.append("║" + " " * 68 + "║")
        output.append("╚" + "═" * 68 + "╝")

        # Summary statistics
        output.append("\n" + "=" * 70)
        output.append("  SUMMARY")
        output.append("=" * 70)
        output.append(f"\n  Total attack paths found: {len(attack_paths)}")

        if not attack_paths:
            output.append("\n  ✅ No attack paths detected!")
            output.append("     Your critical assets are well protected.\n")
            return "\n".join(output)

        # Calculate statistics
        avg_risk = sum(p.risk_score for p in attack_paths) / len(attack_paths)
        max_risk = max(p.risk_score for p in attack_paths)
        avg_hops = sum(len(p.path) for p in attack_paths) / len(attack_paths)

        output.append(f"  Average risk score: {avg_risk:.1f}/10")
        output.append(f"  Maximum risk score: {max_risk:.1f}/10")
        output.append(f"  Average path length: {avg_hops:.1f} hops")

        # Critical paths
        critical_paths = [p for p in attack_paths if p.risk_score >= 8]
        high_paths = [p for p in attack_paths if 6 <= p.risk_score < 8]

        if critical_paths:
            output.append(f"\n  🔴 {len(critical_paths)} CRITICAL risk paths")
        if high_paths:
            output.append(f"  🟠 {len(high_paths)} HIGH risk paths")

        # Show top paths
        sorted_paths = sorted(attack_paths, key=lambda x: x.risk_score, reverse=True)

        output.append("\n" + "=" * 70)
        output.append(f"  TOP {min(top_n, len(sorted_paths))} ATTACK PATHS")
        output.append("=" * 70)

        for i, path in enumerate(sorted_paths[:top_n], 1):
            output.append(f"\n--- Attack Path #{i} ---")
            output.append(self.visualize_attack_path(path.path, path.risk_score))

        # Recommendations
        output.append("\n" + "=" * 70)
        output.append("  RECOMMENDATIONS")
        output.append("=" * 70 + "\n")

        if critical_paths:
            output.append("  ⚠️  IMMEDIATE ACTION REQUIRED:")
            output.append("     • Review access controls on critical paths")
            output.append("     • Implement network segmentation")
            output.append("     • Deploy additional monitoring on high-risk segments")
        elif high_paths:
            output.append("  ⚡ SUGGESTED ACTIONS:")
            output.append("     • Strengthen authentication on exposed services")
            output.append("     • Consider adding additional security layers")
            output.append("     • Review firewall rules")
        else:
            output.append("  ✅ GOOD SECURITY POSTURE:")
            output.append("     • Continue regular security audits")
            output.append("     • Maintain current security controls")
            output.append("     • Monitor for infrastructure changes")

        output.append("")
        return "\n".join(output)

    def _compute_levels(self) -> Dict[int, List[str]]:
        """
        Compute hierarchical levels for nodes

        Returns:
            Dictionary mapping level to list of nodes
        """
        levels = {}

        # Find root nodes (nodes with no predecessors)
        roots = [n for n in self.graph.nodes() if self.graph.in_degree(n) == 0]

        if not roots:
            # If no roots, start with all nodes at level 0
            return {0: list(self.graph.nodes())}

        # BFS to assign levels
        visited = set()
        current_level = roots
        level_num = 0

        while current_level:
            levels[level_num] = current_level
            visited.update(current_level)

            next_level = []
            for node in current_level:
                for successor in self.graph.successors(node):
                    if successor not in visited and successor not in next_level:
                        next_level.append(successor)

            current_level = next_level
            level_num += 1

        return levels

    def export_json(self) -> Dict:
        """
        Export graph structure as JSON for web visualization

        Returns:
            Dictionary with nodes and edges
        """
        nodes = []
        for node_id in self.graph.nodes():
            node_data = self.graph.nodes[node_id]
            nodes.append({
                'id': node_id,
                'type': node_data.get('type', 'unknown'),
                'critical': node_data.get('critical', False),
                'exposure': node_data.get('exposure', '')
            })

        edges = []
        for source, target in self.graph.edges():
            edges.append({
                'source': source,
                'target': target
            })

        return {
            'nodes': nodes,
            'edges': edges
        }
