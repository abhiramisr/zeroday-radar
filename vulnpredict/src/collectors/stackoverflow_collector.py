"""
Stack Overflow Collector for VulnPredict
Detects unusual question spikes that might indicate emerging vulnerabilities
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import Counter
import re

class StackOverflowCollector:
    """Monitors Stack Overflow for anomalous question patterns"""

    def __init__(self, use_api: bool = False, api_key: Optional[str] = None):
        """
        Initialize Stack Overflow collector

        Args:
            use_api: If True, use Stack Exchange API
            api_key: Stack Exchange API key (optional, increases rate limits)
        """
        self.use_api = use_api
        self.api_key = api_key
        self.base_url = 'https://api.stackexchange.com/2.3'

        # Libraries to monitor
        self.monitored_tags = [
            'log4j', 'spring', 'struts', 'openssl', 'nodejs',
            'django', 'rails', 'express', 'react', 'angular',
            'authentication', 'security', 'encryption'
        ]

        # Error/issue keywords
        self.error_keywords = [
            'vulnerability', 'exploit', 'security', 'bypass',
            'injection', 'error', 'exception', 'crash', 'fail',
            'broken', 'not working', 'stopped working', 'suddenly'
        ]

    def get_recent_questions(self, tag: str, days: int = 7, limit: int = 100) -> List[Dict]:
        """
        Get recent questions for a specific tag

        Args:
            tag: Stack Overflow tag (e.g., 'log4j', 'spring')
            days: Number of days to look back
            limit: Maximum questions to fetch

        Returns:
            List of question dictionaries
        """
        if self.use_api:
            return self._get_questions_from_api(tag, days, limit)
        else:
            return self._get_simulated_questions(tag, days, limit)

    def _get_questions_from_api(self, tag: str, days: int, limit: int) -> List[Dict]:
        """Fetch real questions from Stack Exchange API"""
        questions = []
        try:
            import requests

            since_date = int((datetime.now() - timedelta(days=days)).timestamp())

            params = {
                'tagged': tag,
                'fromdate': since_date,
                'site': 'stackoverflow',
                'pagesize': limit,
                'order': 'desc',
                'sort': 'creation'
            }

            if self.api_key:
                params['key'] = self.api_key

            response = requests.get(f'{self.base_url}/questions', params=params)

            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    questions.append({
                        'question_id': item['question_id'],
                        'title': item['title'],
                        'tags': item['tags'],
                        'score': item['score'],
                        'view_count': item['view_count'],
                        'answer_count': item['answer_count'],
                        'created_at': datetime.fromtimestamp(item['creation_date']),
                        'link': item['link']
                    })
        except Exception as e:
            print(f"Error fetching from Stack Overflow API: {e}")

        return questions

    def _get_simulated_questions(self, tag: str, days: int, limit: int) -> List[Dict]:
        """Generate simulated questions for demo"""
        now = datetime.now()

        # Different patterns based on tag
        if tag.lower() in ['log4j', 'spring', 'struts']:
            # Simulate a vulnerability spike
            base_questions = [
                f"{tag} suddenly throwing security exceptions",
                f"How to fix {tag} authentication bypass?",
                f"{tag} vulnerability - getting remote code execution",
                f"Is {tag} safe to use in production?",
                f"{tag} security patch not working",
                f"Critical error in {tag} after update",
                f"{tag} deserialization vulnerability workaround",
                f"Multiple {tag} servers compromised",
                f"{tag} CVE - how to mitigate?",
                f"Emergency {tag} update required?",
                f"{tag} exploit detected in logs",
                f"Best practices for securing {tag}",
                f"{tag} configuration to prevent attacks",
                f"Why is {tag} being targeted?",
                f"Alternative to {tag} due to security concerns"
            ]
            question_count = min(15, limit)
        else:
            # Normal activity
            base_questions = [
                f"How to use {tag} in production?",
                f"Best practices for {tag}",
                f"{tag} configuration help",
                f"Getting started with {tag}",
                f"{tag} vs alternatives"
            ]
            question_count = min(5, limit)

        questions = []
        for i in range(question_count):
            # Vary creation times
            created_time = now - timedelta(hours=i*4, minutes=i*15)

            # Simulate higher engagement for security questions
            is_security = any(word in base_questions[i % len(base_questions)].lower()
                            for word in ['security', 'vulnerability', 'exploit', 'attack'])

            if is_security:
                score = 20 + (i % 10) * 5
                views = 1500 + (i % 5) * 300
                answers = 3 + (i % 4)
            else:
                score = 5 + (i % 5)
                views = 200 + (i % 5) * 50
                answers = 1 + (i % 3)

            questions.append({
                'question_id': 70000000 + i,
                'title': base_questions[i % len(base_questions)],
                'tags': [tag, 'security', 'vulnerability'] if is_security else [tag],
                'score': score,
                'view_count': views,
                'answer_count': answers,
                'created_at': created_time,
                'link': f'https://stackoverflow.com/questions/{70000000 + i}'
            })

        return questions

    def detect_question_spikes(self, tag: str, days: int = 7) -> Dict:
        """
        Detect unusual spikes in questions for a tag

        Args:
            tag: Tag to analyze
            days: Time window for analysis

        Returns:
            Spike analysis dictionary
        """
        questions = self.get_recent_questions(tag, days=days)

        if not questions:
            return {
                'tag': tag,
                'is_spike': False,
                'risk_score': 0,
                'question_count': 0
            }

        # Analyze question velocity
        question_count = len(questions)
        avg_per_day = question_count / max(days, 1)

        # Analyze question content
        security_questions = []
        high_engagement_questions = []

        for q in questions:
            title_lower = q['title'].lower()

            # Check for security keywords
            if any(kw in title_lower for kw in self.error_keywords):
                security_questions.append(q)

            # Check for high engagement (indicator of widespread issue)
            if q['view_count'] > 1000 or q['score'] > 15:
                high_engagement_questions.append(q)

        security_ratio = len(security_questions) / max(question_count, 1)

        # Calculate risk score
        risk_score = 0
        indicators = []

        # High question velocity
        if avg_per_day > 5:
            risk_score += 3
            indicators.append(f'High question rate ({avg_per_day:.1f}/day)')

        # High security content ratio
        if security_ratio > 0.3:
            risk_score += 4
            indicators.append(f'{int(security_ratio*100)}% security-related')

        # High engagement (widespread issue)
        if len(high_engagement_questions) > 3:
            risk_score += 2
            indicators.append(f'{len(high_engagement_questions)} high-engagement questions')

        # Recent spike detection (more questions in last 2 days)
        recent_questions = [q for q in questions
                          if (datetime.now() - q['created_at']).days < 2]
        if len(recent_questions) > question_count * 0.5:
            risk_score += 3
            indicators.append('Recent activity spike')

        is_spike = risk_score >= 5

        return {
            'tag': tag,
            'is_spike': is_spike,
            'risk_score': min(risk_score, 10),
            'question_count': question_count,
            'security_questions': len(security_questions),
            'security_ratio': round(security_ratio, 2),
            'avg_questions_per_day': round(avg_per_day, 1),
            'indicators': indicators,
            'sample_questions': [q['title'] for q in security_questions[:3]]
        }

    def monitor_multiple_tags(self, tags: List[str] = None, days: int = 7) -> List[Dict]:
        """
        Monitor multiple tags for spikes

        Args:
            tags: List of tags to monitor (uses default if None)
            days: Time window for analysis

        Returns:
            List of spike analyses sorted by risk score
        """
        if tags is None:
            tags = self.monitored_tags

        results = []
        for tag in tags:
            spike_data = self.detect_question_spikes(tag, days=days)
            if spike_data['is_spike']:
                results.append(spike_data)

        return sorted(results, key=lambda x: x['risk_score'], reverse=True)

    def detect_anomalies(self, questions: List[Dict]) -> List[Dict]:
        """
        Detect anomalous individual questions

        Args:
            questions: List of questions to analyze

        Returns:
            List of anomalous questions
        """
        anomalies = []

        for question in questions:
            anomaly_data = self._analyze_question(question)
            if anomaly_data['is_anomaly']:
                anomalies.append(anomaly_data)

        return sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)

    def _analyze_question(self, question: Dict) -> Dict:
        """Analyze a single question for anomaly signals"""
        title = question['title'].lower()

        # Check for various signals
        has_error_keywords = any(kw in title for kw in self.error_keywords)
        has_urgency = any(word in title for word in ['urgent', 'critical', 'emergency', 'suddenly', 'stopped working'])
        high_engagement = question['view_count'] > 1000 or question['score'] > 10
        recent = (datetime.now() - question['created_at']).days < 2

        # Calculate risk score
        risk_score = 0
        signals = []

        if has_error_keywords:
            risk_score += 3
            signals.append('Security/error keywords')

        if has_urgency:
            risk_score += 2
            signals.append('Urgent language')

        if high_engagement:
            risk_score += 2
            signals.append('High engagement')

        if recent:
            risk_score += 1
            signals.append('Very recent')

        # Check for specific high-risk patterns
        if 'vulnerability' in title or 'exploit' in title:
            risk_score += 3
            signals.append('Explicit vulnerability mention')

        is_anomaly = risk_score >= 4

        return {
            'question_id': question['question_id'],
            'title': question['title'],
            'risk_score': min(risk_score, 10),
            'is_anomaly': is_anomaly,
            'signals': signals,
            'tags': question.get('tags', []),
            'views': question['view_count'],
            'score': question['score'],
            'link': question['link']
        }

    def get_trending_topics(self, questions: List[Dict]) -> Dict[str, int]:
        """
        Extract trending topics from question titles

        Args:
            questions: List of questions

        Returns:
            Dictionary of topics and their counts
        """
        all_words = []

        for q in questions:
            # Tokenize title
            words = re.findall(r'\b\w+\b', q['title'].lower())
            # Filter out common words
            filtered_words = [
                w for w in words
                if len(w) > 4 and w not in {'about', 'using', 'error', 'issue', 'question'}
            ]
            all_words.extend(filtered_words)

        # Get most common technical terms
        word_counts = Counter(all_words)
        return dict(word_counts.most_common(10))
