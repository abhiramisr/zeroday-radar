"""
Attack Path Analyzer
Uses network analysis to find vulnerable paths through infrastructure
"""

import networkx as nx
from typing import List, Dict, Set
from dataclasses import dataclass

@dataclass
class AttackPath:
    entry_point: str
    target: str
    path: List[str]
    risk_score: float

class VulnPathAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()
    
    def add_component(self, component_id: str, **attributes):
        """Add a component to the infrastructure graph"""
        self.graph.add_node(component_id, **attributes)
    
    def add_connection(self, source: str, target: str):
        """Add network connection between components"""
        self.graph.add_edge(source, target)
    
    def find_attack_paths(self, entry_points: List[str], 
                         critical_assets: List[str]) -> List[AttackPath]:
        """Find all possible attack paths to critical assets"""
        paths = []
        for entry in entry_points:
            for asset in critical_assets:
                try:
                    simple_paths = nx.all_simple_paths(
                        self.graph, entry, asset, cutoff=5
                    )
                    for path in simple_paths:
                        paths.append(AttackPath(
                            entry_point=entry,
                            target=asset,
                            path=path,
                            risk_score=len(path) * 0.2
                        ))
                except nx.NetworkXNoPath:
                    pass
        return paths