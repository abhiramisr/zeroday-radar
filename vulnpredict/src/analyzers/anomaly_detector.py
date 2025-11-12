"""
Anomaly Detector for VulnPredict
Identifies unusual patterns that might indicate emerging vulnerabilities
"""

from typing import List, Dict, Tuple
from datetime import datetime, timedelta
from collections import Counter

class AnomalyDetector:
    def __init__(self):
        self.thresholds = {
            'commit_velocity': 5,  # commits per day
            'issue_velocity': 10,  # issues per week
            'keyword_density': 0.3,  # percentage of concerning keywords
        }
        
    def analyze_commit_patterns(self, commits: List[Dict]) -> Dict:
        """Analyze commit patterns for anomalies"""
        if not commits:
            return {'risk_level': 'low', 'score': 0}
        
        # Keywords that might indicate security fixes
        security_keywords = [
            'fix', 'patch', 'security', 'vulnerability', 'exploit',
            'sanitize', 'escape', 'injection', 'overflow', 'leak'
        ]
        
        # Analyze commit messages
        security_commits = []
        for commit in commits:
            message = commit.get('message', '').lower()
            if any(keyword in message for keyword in security_keywords):
                security_commits.append(commit)
        
        # Calculate velocity (commits per day)
        if len(commits) > 1:
            time_span = (commits[-1]['date'] - commits[0]['date']).days or 1
            velocity = len(security_commits) / time_span
        else:
            velocity = 0
            
        # Determine risk level
        if velocity > self.thresholds['commit_velocity']:
            risk_level = 'high'
            score = min(velocity / self.thresholds['commit_velocity'], 10)
        elif velocity > self.thresholds['commit_velocity'] * 0.5:
            risk_level = 'medium'
            score = velocity / self.thresholds['commit_velocity'] * 5
        else:
            risk_level = 'low'
            score = velocity / self.thresholds['commit_velocity'] * 2
            
        return {
            'risk_level': risk_level,
            'score': round(score, 2),
            'security_commits': len(security_commits),
            'total_commits': len(commits),
            'velocity': round(velocity, 2)
        }
    
    def detect_library_anomalies(self, library_data: Dict) -> List[Dict]:
        """Detect libraries showing unusual activity"""
        anomalies = []
        
        for library, data in library_data.items():
            anomaly_score = 0
            reasons = []
            
            # Check commit velocity
            if data.get('commit_velocity', 0) > self.thresholds['commit_velocity']:
                anomaly_score += 3
                reasons.append('High commit velocity')
            
            # Check issue velocity
            if data.get('issue_velocity', 0) > self.thresholds['issue_velocity']:
                anomaly_score += 2
                reasons.append('High issue velocity')
            
            # Check for security-related discussions
            if data.get('security_mentions', 0) > 5:
                anomaly_score += 4
                reasons.append('Multiple security discussions')
            
            if anomaly_score >= 5:
                anomalies.append({
                    'library': library,
                    'anomaly_score': anomaly_score,
                    'reasons': reasons,
                    'recommendation': 'Monitor closely' if anomaly_score < 7 else 'Investigate immediately'
                })
        
        return sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)