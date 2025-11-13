"""
VulnPath Demo
Comprehensive demonstration of attack path analysis with CVE integration
"""

from src.analyzers.path_analyzer import VulnPathAnalyzer
from src.visualizers.graph_visualizer import GraphVisualizer
from src.integrations.cve_integration import CVEIntegration

def print_header(title: str):
    """Print a formatted section header"""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + f"  {title}".ljust(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")

def build_sample_infrastructure(analyzer: VulnPathAnalyzer):
    """Build a realistic sample infrastructure"""
    print("\n🏗️  Building sample infrastructure...")

    # External/Internet layer
    analyzer.add_component("internet", exposure="internet", type="external")

    # DMZ layer
    analyzer.add_component("load_balancer", type="network", exposure="internet")
    analyzer.add_component("web_server", type="web", technology=["nginx", "django"])
    analyzer.add_component("api_gateway", type="api", technology=["spring", "spring_framework"])

    # Application layer
    analyzer.add_component("app_server_1", type="application", technology=["java", "spring_framework"])
    analyzer.add_component("app_server_2", type="application", technology=["java", "spring_framework"])
    analyzer.add_component("auth_service", type="service", technology=["oauth"])

    # Data layer
    analyzer.add_component("database_primary", type="database", critical=True, technology=["postgresql"])
    analyzer.add_component("database_replica", type="database", technology=["postgresql"])
    analyzer.add_component("redis_cache", type="cache", technology=["redis"])

    # Management/Admin
    analyzer.add_component("admin_panel", type="admin", technology=["django"], exposure="vpn")
    analyzer.add_component("backup_server", type="backup", critical=True, technology=["rsync"])

    # Define connections
    connections = [
        # Internet to DMZ
        ("internet", "load_balancer"),

        # DMZ to Application
        ("load_balancer", "web_server"),
        ("load_balancer", "api_gateway"),
        ("web_server", "app_server_1"),
        ("web_server", "app_server_2"),
        ("api_gateway", "app_server_1"),
        ("api_gateway", "app_server_2"),

        # Application to Data
        ("app_server_1", "database_primary"),
        ("app_server_2", "database_primary"),
        ("app_server_1", "redis_cache"),
        ("app_server_2", "redis_cache"),
        ("app_server_1", "auth_service"),
        ("app_server_2", "auth_service"),

        # Data replication
        ("database_primary", "database_replica"),
        ("database_primary", "backup_server"),

        # Admin access
        ("admin_panel", "database_primary"),
        ("admin_panel", "app_server_1"),
    ]

    for source, target in connections:
        analyzer.add_connection(source, target)

    print(f"   ✓ Created {len(analyzer.graph.nodes())} components")
    print(f"   ✓ Created {len(analyzer.graph.edges())} connections")

def integrate_cve_data(analyzer: VulnPathAnalyzer):
    """Integrate recent CVE data into infrastructure"""
    print("\n🔍 Fetching recent CVE data...")

    cve_integration = CVEIntegration(use_api=False)
    recent_cves = cve_integration.get_recent_cves(days=30, min_severity="MEDIUM")

    print(f"   ✓ Found {len(recent_cves)} recent CVEs")

    # Map CVEs to components based on technology
    component_tech_map = {
        "web_server": ["nginx", "django"],
        "api_gateway": ["spring", "spring_framework"],
        "app_server_1": ["spring", "spring_framework", "java"],
        "app_server_2": ["spring", "spring_framework", "java"],
        "admin_panel": ["django"],
        "database_primary": ["postgresql"],
        "database_replica": ["postgresql"],
    }

    cve_matches = cve_integration.match_cves_to_components(recent_cves, component_tech_map)

    # Add vulnerabilities to components
    total_mappings = 0
    for component, cves in cve_matches.items():
        if cves:
            analyzer.add_vulnerabilities(component, cves)
            total_mappings += len(cves)
            print(f"   • {component}: {len(cves)} CVEs")

    print(f"\n   ✓ Mapped {total_mappings} CVE instances to components")

    return cve_integration, recent_cves

def demonstrate_infrastructure_visualization(analyzer: VulnPathAnalyzer):
    """Show infrastructure topology"""
    print_header("INFRASTRUCTURE TOPOLOGY")

    visualizer = GraphVisualizer(analyzer.graph)
    topology = visualizer.visualize_ascii()
    print(topology)

def demonstrate_attack_path_analysis(analyzer: VulnPathAnalyzer):
    """Find and analyze attack paths"""
    print_header("ATTACK PATH ANALYSIS")

    print("\n🎯 Analyzing attack paths...")
    print("   Entry points: Internet-facing components")
    print("   Targets: Critical assets (databases, backup systems)")

    # Find attack paths
    entry_points = ["internet"]
    critical_assets = ["database_primary", "backup_server"]

    paths = analyzer.find_attack_paths(
        entry_points=entry_points,
        critical_assets=critical_assets,
        max_hops=8
    )

    print(f"\n   ✓ Found {len(paths)} possible attack paths")

    if paths:
        # Show statistics
        critical_paths = [p for p in paths if p.risk_score >= 8]
        high_paths = [p for p in paths if 6 <= p.risk_score < 8]
        medium_paths = [p for p in paths if 4 <= p.risk_score < 6]

        print(f"\n   Risk Distribution:")
        print(f"      🔴 Critical (8-10): {len(critical_paths)} paths")
        print(f"      🟠 High (6-8):      {len(high_paths)} paths")
        print(f"      🟡 Medium (4-6):    {len(medium_paths)} paths")

        # Generate and display full report
        visualizer = GraphVisualizer(analyzer.graph)
        report = visualizer.generate_report(paths, top_n=3)
        print(report)

        # Show vulnerabilities for top path
        if paths[0].vulnerabilities:
            print("\n" + "=" * 70)
            print("  VULNERABILITY DETAILS - Top Risk Path")
            print("=" * 70 + "\n")

            for vuln in paths[0].vulnerabilities[:3]:
                cve = vuln['cve']
                print(f"  CVE: {cve.cve_id} ({cve.severity})")
                print(f"  Component: {vuln['component']}")
                print(f"  CVSS Score: {cve.cvss_score}/10")
                print(f"  Description: {cve.description[:80]}...")
                print()

def demonstrate_component_risk_analysis(analyzer: VulnPathAnalyzer, cve_integration: CVEIntegration):
    """Analyze individual component risks"""
    print_header("COMPONENT RISK ANALYSIS")

    print("\n📊 Analyzing component vulnerabilities...")

    vulnerable_components = analyzer.get_most_vulnerable_components(top_n=5)

    if vulnerable_components:
        print(f"\n   Top {len(vulnerable_components)} Most Vulnerable Components:\n")

        for i, comp in enumerate(vulnerable_components, 1):
            risk_emoji = "🔴" if comp['risk_score'] >= 8 else "🟠" if comp['risk_score'] >= 6 else "🟡"
            print(f"   {i}. {risk_emoji} {comp['component']}")
            print(f"      Risk Score: {comp['risk_score']:.1f}/10")
            print(f"      Factors: {', '.join(comp['factors'])}")

            # Show specific CVEs
            if comp['cve_count'] > 0:
                component_cves = analyzer.component_cves.get(comp['component'], [])
                if component_cves:
                    print(f"      Top CVE: {component_cves[0].cve_id} (CVSS: {component_cves[0].cvss_score})")

                    # Show mitigation advice
                    advice = cve_integration.get_mitigation_advice(component_cves[0])
                    if advice:
                        print(f"      Mitigation: {advice[0]}")
            print()
    else:
        print("   ✅ No high-risk components detected!")

def demonstrate_mitigation_recommendations(analyzer: VulnPathAnalyzer):
    """Show actionable mitigation recommendations"""
    print_header("MITIGATION RECOMMENDATIONS")

    print("\n💡 Recommended Security Improvements:\n")

    # Find highest risk paths
    paths = analyzer.find_attack_paths(
        entry_points=["internet"],
        critical_assets=["database_primary", "backup_server"],
        max_hops=8
    )

    if paths:
        top_path = paths[0]

        print(f"   Priority 1: Secure highest risk path")
        print(f"   Risk Score: {top_path.risk_score:.1f}/10")
        print(f"   Path: {' → '.join(top_path.path)}")
        print(f"\n   Actions:")

        for i, mitigation in enumerate(top_path.mitigation_steps, 1):
            print(f"      {i}. {mitigation}")

    print("\n   General Recommendations:")
    print("      • Implement network segmentation between layers")
    print("      • Deploy Web Application Firewall (WAF)")
    print("      • Enable comprehensive logging and monitoring")
    print("      • Regular vulnerability scanning and patching")
    print("      • Review and harden authentication mechanisms")

def main():
    """Run the complete VulnPath demo"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  🎯 VULNPATH - ATTACK PATH ANALYZER".center(68) + "║")
    print("║" + "  Map Your Infrastructure. Find Critical Paths.".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")

    # Initialize analyzer
    analyzer = VulnPathAnalyzer()

    # Build infrastructure
    build_sample_infrastructure(analyzer)

    # Integrate CVE data
    cve_integration, recent_cves = integrate_cve_data(analyzer)

    # Show visualizations and analysis
    demonstrate_infrastructure_visualization(analyzer)
    demonstrate_attack_path_analysis(analyzer)
    demonstrate_component_risk_analysis(analyzer, cve_integration)
    demonstrate_mitigation_recommendations(analyzer)

    # Summary
    print("\n" + "=" * 70)
    print("  ANALYSIS COMPLETE")
    print("=" * 70)
    print("\n  ✅ Infrastructure analyzed")
    print(f"  ✅ {len(recent_cves)} CVEs evaluated")
    print("  ✅ Attack paths identified")
    print("  ✅ Mitigation recommendations generated")

    print("\n  📊 Use this analysis to prioritize security improvements")
    print("  🎯 Focus on high-risk paths first")
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    main()
