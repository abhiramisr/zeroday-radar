"""
Attack Path Analyzer
Uses network analysis to find vulnerable paths through infrastructure
"""

import networkx as nx
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field

@dataclass
class AttackPath:
    entry_point: str
    target: str
    path: List[str]
    risk_score: float
    vulnerabilities: List = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)

class VulnPathAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.component_cves = {}  # Maps component to list of CVEs

    def add_component(self, component_id: str, **attributes):
        """Add a component to the infrastructure graph"""
        self.graph.add_node(component_id, **attributes)

    def add_connection(self, source: str, target: str, **attributes):
        """Add network connection between components"""
        self.graph.add_edge(source, target, **attributes)

    def add_vulnerabilities(self, component_id: str, cves: List):
        """Add CVE vulnerabilities to a component"""
        self.component_cves[component_id] = cves

    def find_attack_paths(self, entry_points: List[str],
                         critical_assets: List[str],
                         max_hops: int = 10) -> List[AttackPath]:
        """
        Find all possible attack paths to critical assets

        Args:
            entry_points: List of entry point component IDs
            critical_assets: List of critical asset component IDs
            max_hops: Maximum path length to consider

        Returns:
            List of AttackPath objects sorted by risk score
        """
        paths = []
        for entry in entry_points:
            for asset in critical_assets:
                try:
                    simple_paths = nx.all_simple_paths(
                        self.graph, entry, asset, cutoff=max_hops
                    )
                    for path in simple_paths:
                        risk_score = self._calculate_path_risk(path)
                        vulnerabilities = self._get_path_vulnerabilities(path)
                        mitigations = self._generate_mitigations(path, vulnerabilities)

                        paths.append(AttackPath(
                            entry_point=entry,
                            target=asset,
                            path=path,
                            risk_score=risk_score,
                            vulnerabilities=vulnerabilities,
                            mitigation_steps=mitigations
                        ))
                except nx.NetworkXNoPath:
                    pass

        return sorted(paths, key=lambda x: x.risk_score, reverse=True)

    def _calculate_path_risk(self, path: List[str]) -> float:
        """
        Calculate risk score for an attack path

        Factors:
        - Path length (shorter = higher risk)
        - Component vulnerabilities
        - Exposure to internet
        - Criticality of target

        Returns:
            Risk score (0-10)
        """
        base_risk = 0.0

        # Path length factor (shorter paths are riskier)
        # 2 hops = 8.0, 3 hops = 6.0, 4 hops = 4.5, etc.
        if len(path) == 2:
            base_risk = 8.0
        elif len(path) == 3:
            base_risk = 6.0
        elif len(path) == 4:
            base_risk = 4.5
        else:
            base_risk = max(10.0 / len(path), 1.0)

        # Vulnerability factor
        vuln_multiplier = 1.0
        for component in path[1:-1]:  # Exclude entry and target
            if component in self.component_cves:
                cves = self.component_cves[component]
                if any(cve.severity == "CRITICAL" for cve in cves):
                    vuln_multiplier *= 1.5
                elif any(cve.severity == "HIGH" for cve in cves):
                    vuln_multiplier *= 1.3
                elif cves:
                    vuln_multiplier *= 1.1

        # Internet exposure factor
        for component in path:
            node_data = self.graph.nodes.get(component, {})
            if node_data.get('exposure') == 'internet':
                vuln_multiplier *= 1.2

        # Target criticality factor
        target = path[-1]
        target_data = self.graph.nodes.get(target, {})
        if target_data.get('critical', False):
            vuln_multiplier *= 1.3

        final_risk = base_risk * vuln_multiplier
        return min(final_risk, 10.0)

    def _get_path_vulnerabilities(self, path: List[str]) -> List:
        """Get all vulnerabilities along a path"""
        vulnerabilities = []
        for component in path:
            if component in self.component_cves:
                for cve in self.component_cves[component]:
                    vulnerabilities.append({
                        'component': component,
                        'cve': cve
                    })
        return vulnerabilities

    def _generate_mitigations(self, path: List[str], vulnerabilities: List) -> List[str]:
        """Generate mitigation recommendations for a path"""
        mitigations = []

        # Path-specific mitigations
        if len(path) == 2:
            mitigations.append("Direct exposure detected - implement WAF or reverse proxy")

        if len(path) <= 3:
            mitigations.append("Short attack path - add network segmentation")

        # Vulnerability-based mitigations
        critical_vulns = [v for v in vulnerabilities if v['cve'].severity == "CRITICAL"]
        if critical_vulns:
            mitigations.append(f"URGENT: Patch {len(critical_vulns)} critical vulnerabilities")

        # Internet exposure mitigations
        for component in path:
            node_data = self.graph.nodes.get(component, {})
            if node_data.get('exposure') == 'internet':
                mitigations.append(f"Review access controls on {component} (internet-facing)")
                break

        return mitigations

    def get_most_vulnerable_components(self, top_n: int = 5) -> List[Dict]:
        """
        Identify most vulnerable components based on CVEs and position

        Args:
            top_n: Number of top vulnerable components to return

        Returns:
            List of component vulnerability information
        """
        component_risks = []

        for component in self.graph.nodes():
            risk_score = 0.0
            factors = []

            # CVE risk
            if component in self.component_cves:
                cves = self.component_cves[component]
                critical_count = sum(1 for cve in cves if cve.severity == "CRITICAL")
                high_count = sum(1 for cve in cves if cve.severity == "HIGH")

                risk_score += critical_count * 3.0
                risk_score += high_count * 1.5

                if cves:
                    factors.append(f"{len(cves)} CVEs")

            # Position risk (centrality in network)
            in_degree = self.graph.in_degree(component)
            out_degree = self.graph.out_degree(component)

            if in_degree + out_degree > 2:
                risk_score += (in_degree + out_degree) * 0.5
                factors.append(f"Central node ({in_degree+out_degree} connections)")

            # Exposure risk
            node_data = self.graph.nodes.get(component, {})
            if node_data.get('exposure') == 'internet':
                risk_score += 2.0
                factors.append("Internet-facing")

            if risk_score > 0:
                component_risks.append({
                    'component': component,
                    'risk_score': min(risk_score, 10.0),
                    'factors': factors,
                    'cve_count': len(self.component_cves.get(component, []))
                })

        return sorted(component_risks, key=lambda x: x['risk_score'], reverse=True)[:top_n]