"""
GitHub Collector for VulnPredict
Monitors GitHub for early vulnerability signals
"""

import re
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import Counter
import json

class GitHubCollector:
    """Collects and analyzes security signals from GitHub"""

    def __init__(self, use_api: bool = False, api_token: Optional[str] = None):
        """
        Initialize GitHub collector

        Args:
            use_api: If True, use actual GitHub API
            api_token: GitHub personal access token (optional)
        """
        self.use_api = use_api
        self.api_token = api_token
        self.github_client = None

        # Security-related search terms
        self.security_keywords = [
            'security', 'vulnerability', 'exploit', 'cve', 'patch',
            'fix', 'rce', 'xss', 'sql injection', 'authentication',
            'authorization', 'sanitize', 'escape'
        ]

        # Popular libraries to monitor
        self.monitored_libraries = [
            'apache/log4j', 'spring-projects/spring-framework',
            'apache/struts', 'openssl/openssl', 'nodejs/node',
            'rails/rails', 'django/django', 'webpack/webpack',
            'facebook/react', 'angular/angular'
        ]

        if use_api:
            self._init_github_api()

    def _init_github_api(self):
        """Initialize GitHub API client"""
        try:
            # In production, would use PyGithub or requests
            import requests
            self.github_client = requests
        except ImportError:
            print("Warning: requests not installed. Using simulation mode.")
            self.use_api = False

    def get_trending_repos(self, language: Optional[str] = None, limit: int = 25) -> List[Dict]:
        """
        Get trending repositories (focusing on security-related)

        Args:
            language: Programming language filter (e.g., 'python', 'java')
            limit: Maximum number of repos to return

        Returns:
            List of repository data dictionaries
        """
        if self.use_api and self.github_client:
            return self._get_repos_from_api(language, limit)
        else:
            return self._get_simulated_repos(language, limit)

    def _get_repos_from_api(self, language: Optional[str], limit: int) -> List[Dict]:
        """Fetch real trending repos from GitHub API"""
        repos = []
        try:
            # GitHub API search for trending security-related repos
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'token {self.api_token}'

            # Search for repos with security-related activity
            query = 'security+vulnerability'
            if language:
                query += f'+language:{language}'

            url = f'https://api.github.com/search/repositories?q={query}&sort=updated&per_page={limit}'
            response = self.github_client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    repos.append({
                        'name': item['full_name'],
                        'stars': item['stargazers_count'],
                        'language': item['language'],
                        'description': item['description'] or '',
                        'updated_at': datetime.strptime(item['updated_at'], '%Y-%m-%dT%H:%M:%SZ'),
                        'url': item['html_url']
                    })
        except Exception as e:
            print(f"Error fetching from GitHub API: {e}")

        return repos

    def _get_simulated_repos(self, language: Optional[str], limit: int) -> List[Dict]:
        """Generate simulated repository data for demo"""
        sample_repos = [
            {
                'name': 'apache/log4j-critical-patch',
                'stars': 1250,
                'language': 'Java',
                'description': 'Critical security patch for Log4j deserialization vulnerability',
                'updated_at': datetime.now() - timedelta(hours=2),
                'url': 'https://github.com/apache/log4j'
            },
            {
                'name': 'spring-projects/spring-framework',
                'stars': 45000,
                'language': 'Java',
                'description': 'Spring Framework - now with security updates',
                'updated_at': datetime.now() - timedelta(hours=5),
                'url': 'https://github.com/spring-projects/spring-framework'
            },
            {
                'name': 'openssl/openssl',
                'stars': 23000,
                'language': 'C',
                'description': 'TLS/SSL and crypto library',
                'updated_at': datetime.now() - timedelta(days=1),
                'url': 'https://github.com/openssl/openssl'
            },
            {
                'name': 'security-tools/vulnerability-scanner',
                'stars': 3400,
                'language': 'Python',
                'description': 'Automated vulnerability scanning tool',
                'updated_at': datetime.now() - timedelta(days=2),
                'url': 'https://github.com/security-tools/scanner'
            },
            {
                'name': 'exploit-db/exploits',
                'stars': 8900,
                'language': 'Python',
                'description': 'Exploit database for security research',
                'updated_at': datetime.now() - timedelta(hours=12),
                'url': 'https://github.com/exploit-db/exploits'
            }
        ]

        # Filter by language if specified
        if language:
            sample_repos = [r for r in sample_repos if r['language'].lower() == language.lower()]

        return sample_repos[:limit]

    def monitor_repo_activity(self, repo_name: str) -> Dict:
        """
        Monitor a specific repository for unusual security activity

        Args:
            repo_name: Full repository name (e.g., 'apache/log4j')

        Returns:
            Dictionary with activity analysis
        """
        if self.use_api and self.github_client:
            return self._monitor_repo_api(repo_name)
        else:
            return self._simulate_repo_activity(repo_name)

    def _monitor_repo_api(self, repo_name: str) -> Dict:
        """Monitor repository using GitHub API"""
        activity = {
            'repo': repo_name,
            'commit_velocity': 0,
            'issue_velocity': 0,
            'security_commits': 0,
            'security_issues': 0,
            'risk_score': 0
        }

        try:
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'token {self.api_token}'

            # Get recent commits
            commits_url = f'https://api.github.com/repos/{repo_name}/commits?per_page=30'
            commits_response = self.github_client.get(commits_url, headers=headers)

            if commits_response.status_code == 200:
                commits = commits_response.json()
                activity['commit_velocity'] = len(commits)

                # Analyze commit messages
                for commit in commits:
                    message = commit.get('commit', {}).get('message', '').lower()
                    if any(kw in message for kw in self.security_keywords):
                        activity['security_commits'] += 1

            # Get recent issues
            issues_url = f'https://api.github.com/repos/{repo_name}/issues?per_page=30'
            issues_response = self.github_client.get(issues_url, headers=headers)

            if issues_response.status_code == 200:
                issues = issues_response.json()
                activity['issue_velocity'] = len(issues)

                # Analyze issue titles
                for issue in issues:
                    title = issue.get('title', '').lower()
                    if any(kw in title for kw in self.security_keywords):
                        activity['security_issues'] += 1

            # Calculate risk score
            activity['risk_score'] = self._calculate_risk_score(activity)

        except Exception as e:
            print(f"Error monitoring repo {repo_name}: {e}")

        return activity

    def _simulate_repo_activity(self, repo_name: str) -> Dict:
        """Simulate repository activity for demo"""
        # Simulate different activity levels based on repo name
        if 'log4j' in repo_name.lower():
            return {
                'repo': repo_name,
                'commit_velocity': 25,
                'issue_velocity': 42,
                'security_commits': 18,
                'security_issues': 31,
                'risk_score': 8.5,
                'alert': 'HIGH - Unusual security activity detected'
            }
        elif 'spring' in repo_name.lower():
            return {
                'repo': repo_name,
                'commit_velocity': 15,
                'issue_velocity': 23,
                'security_commits': 8,
                'security_issues': 12,
                'risk_score': 5.5,
                'alert': 'MEDIUM - Elevated security activity'
            }
        else:
            return {
                'repo': repo_name,
                'commit_velocity': 8,
                'issue_velocity': 12,
                'security_commits': 2,
                'security_issues': 3,
                'risk_score': 2.0,
                'alert': 'LOW - Normal activity levels'
            }

    def _calculate_risk_score(self, activity: Dict) -> float:
        """Calculate risk score based on activity metrics"""
        score = 0.0

        # High commit velocity on security issues
        if activity['security_commits'] > 10:
            score += 4.0
        elif activity['security_commits'] > 5:
            score += 2.0

        # High issue velocity on security topics
        if activity['security_issues'] > 15:
            score += 3.0
        elif activity['security_issues'] > 8:
            score += 1.5

        # Overall activity spike
        if activity['commit_velocity'] > 20 or activity['issue_velocity'] > 30:
            score += 2.0

        return min(score, 10.0)

    def detect_anomalies(self, repos: List[Dict]) -> List[Dict]:
        """
        Detect anomalous patterns in repository activity

        Args:
            repos: List of repository data

        Returns:
            List of detected anomalies
        """
        anomalies = []

        for repo in repos:
            anomaly_data = self._analyze_repo(repo)
            if anomaly_data['is_anomaly']:
                anomalies.append(anomaly_data)

        return sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)

    def _analyze_repo(self, repo: Dict) -> Dict:
        """Analyze a single repository for anomalies"""
        description = repo.get('description', '').lower()
        name = repo.get('name', '').lower()

        # Check for security indicators
        has_security_keywords = any(kw in description or kw in name for kw in self.security_keywords)

        # Check for high star velocity (popularity spike)
        stars = repo.get('stars', 0)
        high_popularity = stars > 1000

        # Check update recency
        updated_at = repo.get('updated_at')
        if isinstance(updated_at, datetime):
            hours_since_update = (datetime.now() - updated_at).total_seconds() / 3600
            recently_updated = hours_since_update < 24
        else:
            recently_updated = False

        # Calculate risk score
        risk_score = 0
        reasons = []

        if has_security_keywords:
            risk_score += 3
            reasons.append('Security-related activity')

        if high_popularity:
            risk_score += 2
            reasons.append('High-impact library')

        if recently_updated:
            risk_score += 2
            reasons.append('Recently updated')

        # Check for specific high-risk patterns
        if 'critical' in description or 'urgent' in description:
            risk_score += 3
            reasons.append('Critical security update')

        is_anomaly = risk_score >= 4

        return {
            'repo': repo['name'],
            'risk_score': min(risk_score, 10),
            'is_anomaly': is_anomaly,
            'reasons': reasons,
            'stars': repo.get('stars', 0),
            'language': repo.get('language', 'Unknown'),
            'url': repo.get('url', ''),
            'updated_at': repo.get('updated_at')
        }

    def get_security_commits(self, repo_name: str, days: int = 7) -> List[Dict]:
        """
        Get recent security-related commits from a repository

        Args:
            repo_name: Repository name
            days: Number of days to look back

        Returns:
            List of security-related commits
        """
        # Simulated for demo
        since_date = datetime.now() - timedelta(days=days)

        return [
            {
                'sha': 'abc123',
                'message': 'Fix authentication bypass vulnerability',
                'author': 'security-team',
                'date': datetime.now() - timedelta(hours=3),
                'files_changed': 5
            },
            {
                'sha': 'def456',
                'message': 'Patch SQL injection in user input handler',
                'author': 'dev-lead',
                'date': datetime.now() - timedelta(days=2),
                'files_changed': 3
            }
        ]
