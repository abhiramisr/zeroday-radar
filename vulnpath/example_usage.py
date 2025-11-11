"""
Example: Simple infrastructure analysis
"""

from src.analyzers.path_analyzer import VulnPathAnalyzer

# Create analyzer
analyzer = VulnPathAnalyzer()

# Add components
analyzer.add_component("internet", exposure="internet")
analyzer.add_component("web_app", type="web")
analyzer.add_component("api", type="api")
analyzer.add_component("database", type="database", critical=True)

# Add connections
analyzer.add_connection("internet", "web_app")
analyzer.add_connection("web_app", "api")
analyzer.add_connection("api", "database")

# Find attack paths
paths = analyzer.find_attack_paths(
    entry_points=["internet"],
    critical_assets=["database"]
)

print(f"Found {len(paths)} attack paths")
for path in paths:
    print(f"  Path: {' -> '.join(path.path)}")