"""
CVE Data Integration
Fetches and processes CVE (Common Vulnerabilities and Exposures) data
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

@dataclass
class CVEInfo:
    """CVE information"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    affected_products: List[str]
    published_date: datetime
    exploitable: bool = False

class CVEIntegration:
    """Integrates CVE vulnerability data"""

    def __init__(self, use_api: bool = False):
        """
        Initialize CVE integration

        Args:
            use_api: If True, fetch from NVD API. If False, use simulated data
        """
        self.use_api = use_api

    def get_recent_cves(self, days: int = 30, min_severity: str = "MEDIUM") -> List[CVEInfo]:
        """
        Get recent high-impact CVEs

        Args:
            days: Number of days to look back
            min_severity: Minimum severity level to include

        Returns:
            List of CVE information
        """
        if self.use_api:
            return self._fetch_from_nvd(days, min_severity)
        else:
            return self._get_simulated_cves(days, min_severity)

    def _fetch_from_nvd(self, days: int, min_severity: str) -> List[CVEInfo]:
        """Fetch real CVE data from NVD API"""
        # In production, would use NIST NVD API
        # https://nvd.nist.gov/developers/vulnerabilities
        cves = []

        try:
            import requests

            since_date = datetime.now() - timedelta(days=days)
            start_date = since_date.strftime('%Y-%m-%dT%H:%M:%S.000')

            params = {
                'pubStartDate': start_date,
                'resultsPerPage': 20
            }

            # Note: Real implementation would need API key
            response = requests.get(
                'https://services.nvd.nist.gov/rest/json/cves/2.0',
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve_data = item.get('cve', {})

                    # Extract CVE ID
                    cve_id = cve_data.get('id', 'UNKNOWN')

                    # Extract description
                    descriptions = cve_data.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''

                    # Extract CVSS score
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [])
                    if cvss_v3:
                        cvss_data = cvss_v3[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    else:
                        cvss_score = 0.0
                        severity = 'UNKNOWN'

                    # Extract affected products
                    affected_products = self._extract_affected_products(cve_data)

                    # Published date
                    published = cve_data.get('published', '')
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00')) if published else datetime.now()

                    cves.append(CVEInfo(
                        cve_id=cve_id,
                        description=description[:200],
                        cvss_score=cvss_score,
                        severity=severity,
                        affected_products=affected_products,
                        published_date=pub_date
                    ))

        except Exception as e:
            print(f"Warning: CVE API fetch failed: {e}. Using simulated data.")
            return self._get_simulated_cves(days, min_severity)

        return cves

    def _extract_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected product names from CVE data"""
        products = []
        configurations = cve_data.get('configurations', [])

        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for match in cpe_matches:
                    cpe_uri = match.get('criteria', '')
                    # Extract product name from CPE URI
                    # Format: cpe:2.3:a:vendor:product:version:...
                    parts = cpe_uri.split(':')
                    if len(parts) >= 5:
                        product = parts[4]
                        if product and product not in products:
                            products.append(product)

        return products[:5]  # Limit to top 5

    def _get_simulated_cves(self, days: int, min_severity: str) -> List[CVEInfo]:
        """Generate realistic simulated CVE data"""
        now = datetime.now()

        simulated_cves = [
            CVEInfo(
                cve_id="CVE-2024-45678",
                description="Remote code execution vulnerability in Apache Struts 2 due to improper input validation",
                cvss_score=9.8,
                severity="CRITICAL",
                affected_products=["apache_struts", "struts2"],
                published_date=now - timedelta(days=5),
                exploitable=True
            ),
            CVEInfo(
                cve_id="CVE-2024-34567",
                description="SQL injection vulnerability in Spring Framework JdbcTemplate",
                cvss_score=8.1,
                severity="HIGH",
                affected_products=["spring_framework", "spring"],
                published_date=now - timedelta(days=10),
                exploitable=True
            ),
            CVEInfo(
                cve_id="CVE-2024-23456",
                description="Authentication bypass in Django admin interface",
                cvss_score=7.5,
                severity="HIGH",
                affected_products=["django"],
                published_date=now - timedelta(days=15),
                exploitable=False
            ),
            CVEInfo(
                cve_id="CVE-2024-12345",
                description="Cross-site scripting (XSS) vulnerability in React component library",
                cvss_score=6.1,
                severity="MEDIUM",
                affected_products=["react", "react-dom"],
                published_date=now - timedelta(days=20),
                exploitable=False
            ),
            CVEInfo(
                cve_id="CVE-2024-98765",
                description="Deserialization vulnerability in Log4j 2.x allows remote code execution",
                cvss_score=10.0,
                severity="CRITICAL",
                affected_products=["log4j", "log4j-core"],
                published_date=now - timedelta(days=2),
                exploitable=True
            ),
            CVEInfo(
                cve_id="CVE-2024-11111",
                description="Buffer overflow in OpenSSL TLS implementation",
                cvss_score=7.8,
                severity="HIGH",
                affected_products=["openssl"],
                published_date=now - timedelta(days=8),
                exploitable=False
            )
        ]

        # Filter by severity
        severity_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = severity_levels.get(min_severity, 0)

        filtered_cves = [
            cve for cve in simulated_cves
            if severity_levels.get(cve.severity, 0) >= min_level
            and (now - cve.published_date).days <= days
        ]

        return sorted(filtered_cves, key=lambda x: x.cvss_score, reverse=True)

    def match_cves_to_components(self, cves: List[CVEInfo],
                                   component_tech: Dict[str, List[str]]) -> Dict[str, List[CVEInfo]]:
        """
        Match CVEs to infrastructure components based on technology

        Args:
            cves: List of CVE information
            component_tech: Dict mapping component names to technology keywords

        Returns:
            Dict mapping component names to matching CVEs
        """
        matches = {component: [] for component in component_tech}

        for component, tech_keywords in component_tech.items():
            for cve in cves:
                # Check if any affected product matches component's technology
                for product in cve.affected_products:
                    for keyword in tech_keywords:
                        if keyword.lower() in product.lower():
                            matches[component].append(cve)
                            break

        return matches

    def calculate_component_risk(self, cves: List[CVEInfo]) -> float:
        """
        Calculate risk score for a component based on its CVEs

        Args:
            cves: List of CVEs affecting the component

        Returns:
            Risk score (0-10)
        """
        if not cves:
            return 0.0

        # Weight by severity and exploitability
        total_risk = 0.0

        for cve in cves:
            risk = cve.cvss_score / 10.0  # Normalize to 0-1

            # Boost for exploitable vulnerabilities
            if cve.exploitable:
                risk *= 1.5

            # Boost for recent CVEs
            days_old = (datetime.now() - cve.published_date).days
            if days_old < 7:
                risk *= 1.3
            elif days_old < 30:
                risk *= 1.1

            total_risk += risk

        # Average and cap at 10
        avg_risk = total_risk / len(cves)
        return min(avg_risk * 10, 10.0)

    def get_mitigation_advice(self, cve: CVEInfo) -> List[str]:
        """
        Get mitigation advice for a specific CVE

        Args:
            cve: CVE information

        Returns:
            List of mitigation recommendations
        """
        advice = []

        # General advice based on severity
        if cve.severity == "CRITICAL":
            advice.append("🔴 URGENT: Apply patch immediately or isolate affected systems")
            advice.append("Monitor logs for signs of exploitation")
            advice.append("Consider temporary service shutdown if patch unavailable")
        elif cve.severity == "HIGH":
            advice.append("🟠 HIGH PRIORITY: Schedule patching within 24-48 hours")
            advice.append("Review access controls to affected components")
        else:
            advice.append("🟡 Schedule patching in next maintenance window")

        # Specific advice based on CVE type
        description_lower = cve.description.lower()

        if "remote code execution" in description_lower or "rce" in description_lower:
            advice.append("Implement network segmentation to limit blast radius")
            advice.append("Deploy WAF rules if available")

        if "authentication" in description_lower or "bypass" in description_lower:
            advice.append("Review authentication logs for suspicious activity")
            advice.append("Enforce MFA where possible")

        if "sql injection" in description_lower:
            advice.append("Review database query sanitization")
            advice.append("Enable database activity monitoring")

        if "deserialization" in description_lower:
            advice.append("Disable deserialization if not required")
            advice.append("Implement input validation")

        return advice
