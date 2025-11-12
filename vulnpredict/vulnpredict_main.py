"""
VulnPredict Main Module
Orchestrates collection and analysis for early vulnerability detection
"""

from src.collectors.reddit_collector import RedditCollector
from src.analyzers.anomaly_detector import AnomalyDetector
from datetime import datetime
import json

class VulnPredict:
    def __init__(self):
        self.reddit_collector = RedditCollector()
        self.anomaly_detector = AnomalyDetector()
        
    def run_analysis(self) -> Dict:
        """Run complete VulnPredict analysis"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'sources_analyzed': [],
            'anomalies_detected': [],
            'risk_summary': {}
        }
        
        # Collect from Reddit
        print("Collecting from Reddit...")
        reddit_anomalies = []
        for subreddit in ['netsec', 'cybersecurity']:
            posts = self.reddit_collector.get_hot_posts(subreddit)
            anomalies = self.reddit_collector.detect_anomalies(posts)
            reddit_anomalies.extend(anomalies)
        
        report['sources_analyzed'].append('Reddit')
        report['anomalies_detected'] = reddit_anomalies
        
        # Calculate overall risk
        if len(reddit_anomalies) > 5:
            report['risk_summary']['level'] = 'HIGH'
            report['risk_summary']['message'] = 'Multiple security discussions detected'
        elif len(reddit_anomalies) > 2:
            report['risk_summary']['level'] = 'MEDIUM'
            report['risk_summary']['message'] = 'Some security activity detected'
        else:
            report['risk_summary']['level'] = 'LOW'
            report['risk_summary']['message'] = 'Normal activity levels'
        
        return report

if __name__ == "__main__":
    predictor = VulnPredict()
    report = predictor.run_analysis()
    
    print("\n=== VulnPredict Analysis Report ===")
    print(f"Risk Level: {report['risk_summary']['level']}")
    print(f"Message: {report['risk_summary']['message']}")
    
    if report['anomalies_detected']:
        print(f"\nFound {len(report['anomalies_detected'])} anomalies:")
        for anomaly in report['anomalies_detected'][:3]:
            print(f"  - {anomaly['title'][:60]}...")