"""
Reddit Collector for VulnPredict
Monitors security subreddits for early vulnerability signals
"""

import re
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import Counter

class RedditCollector:
    """Collects and analyzes security discussions from Reddit"""

    def __init__(self, use_api: bool = False):
        """
        Initialize Reddit collector

        Args:
            use_api: If True, use actual Reddit API (requires PRAW).
                     If False, use simulation mode for demo
        """
        self.use_api = use_api
        self.reddit_client = None

        # Security-related keywords for detection
        self.vulnerability_keywords = [
            'vulnerability', 'exploit', 'zero-day', 'zeroday', 'cve',
            'rce', 'remote code execution', 'sql injection', 'xss',
            'authentication bypass', 'privilege escalation', 'buffer overflow',
            'memory leak', 'use after free', 'deserialization',
            'log4j', 'log4shell', 'spring4shell', 'heartbleed'
        ]

        self.library_keywords = [
            'apache', 'nginx', 'openssl', 'spring', 'struts', 'jenkins',
            'wordpress', 'drupal', 'joomla', 'django', 'rails', 'express',
            'react', 'angular', 'vue', 'node.js', 'npm', 'pip', 'maven'
        ]

        if use_api:
            self._init_reddit_api()

    def _init_reddit_api(self):
        """Initialize Reddit API client (PRAW)"""
        try:
            import praw
            # In production, use environment variables for credentials
            self.reddit_client = praw.Reddit(
                client_id="your_client_id",
                client_secret="your_client_secret",
                user_agent="VulnPredict/1.0"
            )
        except ImportError:
            print("Warning: PRAW not installed. Using simulation mode.")
            self.use_api = False
        except Exception as e:
            print(f"Warning: Reddit API init failed: {e}. Using simulation mode.")
            self.use_api = False

    def get_hot_posts(self, subreddit: str, limit: int = 25) -> List[Dict]:
        """
        Get hot posts from a subreddit

        Args:
            subreddit: Name of subreddit (e.g., 'netsec')
            limit: Maximum number of posts to fetch

        Returns:
            List of post dictionaries with title, score, comments, etc.
        """
        if self.use_api and self.reddit_client:
            return self._get_posts_from_api(subreddit, limit)
        else:
            return self._get_simulated_posts(subreddit, limit)

    def _get_posts_from_api(self, subreddit: str, limit: int) -> List[Dict]:
        """Fetch real posts from Reddit API"""
        posts = []
        try:
            subreddit_obj = self.reddit_client.subreddit(subreddit)
            for post in subreddit_obj.hot(limit=limit):
                posts.append({
                    'id': post.id,
                    'title': post.title,
                    'score': post.score,
                    'num_comments': post.num_comments,
                    'created_utc': datetime.fromtimestamp(post.created_utc),
                    'url': post.url,
                    'selftext': post.selftext[:500] if post.selftext else ''
                })
        except Exception as e:
            print(f"Error fetching from Reddit: {e}")

        return posts

    def _get_simulated_posts(self, subreddit: str, limit: int) -> List[Dict]:
        """Generate simulated posts for demo purposes"""
        base_time = datetime.now()

        # Realistic security discussion titles
        sample_titles = [
            "Critical RCE found in popular Java logging library",
            "New technique for bypassing Windows Defender",
            "Discussion: Best practices for API authentication",
            "OpenSSL 3.0 performance benchmarks",
            "Spring Framework update addresses security concerns",
            "Analysis of recent npm package compromise",
            "Zero-day exploitation in the wild - what we know",
            "CVE-2024-XXXX: Remote code execution in Apache Struts",
            "Unusual activity in Log4j GitHub repository",
            "Multiple security researchers posting about same library",
            "New memory corruption bug class discovered",
            "Is anyone else seeing weird behavior in library X?",
            "PSA: Update your dependencies immediately",
            "Deep dive into deserialization vulnerabilities",
            "Container escape techniques and mitigations",
            "Bug bounty writeup: Authentication bypass via race condition",
            "Security implications of new JavaScript feature",
            "Weekly security news roundup",
            "APT group using novel persistence mechanism",
            "SQL injection still going strong in 2024"
        ]

        posts = []
        for i in range(min(limit, len(sample_titles))):
            # Vary the creation time
            created_time = base_time - timedelta(hours=i*2)

            # Generate realistic engagement metrics
            score = 150 - (i * 5) + (i % 3) * 20
            num_comments = 30 - (i * 1) + (i % 5) * 10

            posts.append({
                'id': f'post_{i}',
                'title': sample_titles[i],
                'score': max(score, 10),
                'num_comments': max(num_comments, 2),
                'created_utc': created_time,
                'url': f'https://reddit.com/r/{subreddit}/comments/fake_{i}',
                'selftext': ''
            })

        return posts

    def detect_anomalies(self, posts: List[Dict]) -> List[Dict]:
        """
        Detect anomalous security discussions that might indicate emerging threats

        Args:
            posts: List of Reddit posts

        Returns:
            List of detected anomalies with risk scores
        """
        anomalies = []

        for post in posts:
            anomaly_data = self._analyze_post(post)
            if anomaly_data['is_anomaly']:
                anomalies.append(anomaly_data)

        return sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)

    def _analyze_post(self, post: Dict) -> Dict:
        """Analyze a single post for anomaly signals"""
        title_lower = post['title'].lower()
        text_lower = post.get('selftext', '').lower()
        combined_text = title_lower + ' ' + text_lower

        # Calculate various signals
        signals = {
            'has_vuln_keywords': self._check_keywords(combined_text, self.vulnerability_keywords),
            'has_library_keywords': self._check_keywords(combined_text, self.library_keywords),
            'high_engagement': post['score'] > 100 or post['num_comments'] > 50,
            'urgent_language': self._check_urgency(title_lower),
            'cve_mention': 'cve-' in combined_text or 'cve' in combined_text.split(),
            'zero_day_mention': 'zero-day' in combined_text or 'zeroday' in combined_text
        }

        # Calculate risk score (0-10)
        risk_score = 0
        reasons = []

        if signals['zero_day_mention']:
            risk_score += 4
            reasons.append('Zero-day mentioned')

        if signals['cve_mention']:
            risk_score += 3
            reasons.append('CVE reference found')

        if signals['has_vuln_keywords']:
            risk_score += 2
            reasons.append('Vulnerability keywords detected')

        if signals['high_engagement']:
            risk_score += 2
            reasons.append('High community engagement')

        if signals['urgent_language']:
            risk_score += 1
            reasons.append('Urgent language used')

        if signals['has_library_keywords']:
            risk_score += 1
            # Extract specific library names
            libraries = self._extract_libraries(combined_text)
            if libraries:
                reasons.append(f'Affects libraries: {", ".join(libraries[:3])}')

        is_anomaly = risk_score >= 3  # Threshold for considering it anomalous

        return {
            'post_id': post['id'],
            'title': post['title'],
            'risk_score': min(risk_score, 10),
            'is_anomaly': is_anomaly,
            'signals': signals,
            'reasons': reasons,
            'score': post['score'],
            'num_comments': post['num_comments'],
            'created_utc': post['created_utc'],
            'url': post['url']
        }

    def _check_keywords(self, text: str, keywords: List[str]) -> bool:
        """Check if any keywords are present in text"""
        return any(keyword in text for keyword in keywords)

    def _check_urgency(self, text: str) -> bool:
        """Check for urgent language patterns"""
        urgent_patterns = [
            'critical', 'urgent', 'immediate', 'emergency',
            'update now', 'patch immediately', 'actively exploited',
            'in the wild', 'breaking'
        ]
        return any(pattern in text for pattern in urgent_patterns)

    def _extract_libraries(self, text: str) -> List[str]:
        """Extract mentioned library/framework names"""
        found_libraries = []
        for lib in self.library_keywords:
            if lib in text:
                found_libraries.append(lib)
        return found_libraries

    def get_trending_topics(self, posts: List[Dict]) -> Dict[str, int]:
        """
        Extract trending topics from posts

        Returns:
            Dictionary of topics and their mention counts
        """
        all_words = []

        for post in posts:
            title_words = post['title'].lower().split()
            all_words.extend(title_words)

        # Filter for relevant technical terms
        technical_terms = [
            word for word in all_words
            if len(word) > 4 and not word.startswith('http')
        ]

        # Get most common
        word_counts = Counter(technical_terms)

        return dict(word_counts.most_common(10))
