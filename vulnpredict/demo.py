"""
VulnPredict Demo
Comprehensive demonstration of early vulnerability detection capabilities
"""

from src.collectors.reddit_collector import RedditCollector
from src.collectors.github_collector import GitHubCollector
from src.collectors.stackoverflow_collector import StackOverflowCollector
from datetime import datetime
import json

def print_header(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def print_subheader(title: str):
    """Print a formatted subsection header"""
    print(f"\n--- {title} ---")

def demo_reddit_monitoring():
    """Demonstrate Reddit monitoring capabilities"""
    print_header("REDDIT SECURITY MONITORING")

    collector = RedditCollector(use_api=False)

    # Monitor security subreddits
    subreddits = ['netsec', 'cybersecurity']

    for subreddit in subreddits:
        print_subheader(f"Monitoring r/{subreddit}")

        posts = collector.get_hot_posts(subreddit, limit=10)
        print(f"Collected {len(posts)} posts")

        anomalies = collector.detect_anomalies(posts)

        if anomalies:
            print(f"\n⚠️  Found {len(anomalies)} anomalies:")
            for i, anomaly in enumerate(anomalies[:3], 1):
                print(f"\n  {i}. Risk Score: {anomaly['risk_score']}/10")
                print(f"     Title: {anomaly['title'][:65]}...")
                print(f"     Signals: {', '.join(anomaly['reasons'])}")
                print(f"     Engagement: {anomaly['score']} upvotes, {anomaly['num_comments']} comments")
        else:
            print("✓ No significant anomalies detected")

    # Show trending topics
    all_posts = collector.get_hot_posts('netsec', limit=25)
    trending = collector.get_trending_topics(all_posts)
    print_subheader("Trending Security Topics")
    for topic, count in list(trending.items())[:5]:
        print(f"  • {topic}: {count} mentions")

def demo_github_monitoring():
    """Demonstrate GitHub monitoring capabilities"""
    print_header("GITHUB REPOSITORY MONITORING")

    collector = GitHubCollector(use_api=False)

    # Get trending security-related repos
    print_subheader("Trending Security Repositories")
    repos = collector.get_trending_repos(limit=5)

    for repo in repos:
        print(f"\n  📦 {repo['name']}")
        print(f"     ⭐ {repo['stars']} stars | {repo['language']}")
        print(f"     {repo['description'][:60]}...")

    # Detect anomalies
    anomalies = collector.detect_anomalies(repos)
    if anomalies:
        print_subheader("Repository Anomalies Detected")
        for anomaly in anomalies[:3]:
            print(f"\n  ⚠️  {anomaly['repo']}")
            print(f"     Risk Score: {anomaly['risk_score']}/10")
            print(f"     Signals: {', '.join(anomaly['reasons'])}")

    # Monitor specific high-risk repos
    print_subheader("Monitoring High-Risk Repositories")
    high_risk_repos = ['apache/log4j', 'spring-projects/spring-framework']

    for repo_name in high_risk_repos:
        activity = collector.monitor_repo_activity(repo_name)
        print(f"\n  📊 {activity['repo']}")
        print(f"     Commit velocity: {activity['commit_velocity']}")
        print(f"     Security commits: {activity['security_commits']}")
        print(f"     Risk score: {activity['risk_score']}/10")
        print(f"     Alert: {activity.get('alert', 'N/A')}")

def demo_stackoverflow_monitoring():
    """Demonstrate Stack Overflow monitoring capabilities"""
    print_header("STACK OVERFLOW SPIKE DETECTION")

    collector = StackOverflowCollector(use_api=False)

    # Monitor for question spikes on key libraries
    monitored_tags = ['log4j', 'spring', 'openssl', 'django']

    print_subheader("Monitoring Library Tags")

    spikes = []
    for tag in monitored_tags:
        spike_data = collector.detect_question_spikes(tag, days=7)

        status = "🔴 SPIKE" if spike_data['is_spike'] else "✓ Normal"
        print(f"\n  {status} - {tag}")
        print(f"     Questions: {spike_data['question_count']} ({spike_data['avg_questions_per_day']:.1f}/day)")
        print(f"     Security ratio: {spike_data['security_ratio']*100:.0f}%")
        print(f"     Risk score: {spike_data['risk_score']}/10")

        if spike_data['is_spike']:
            spikes.append(spike_data)
            if spike_data['indicators']:
                print(f"     Indicators: {', '.join(spike_data['indicators'])}")

    # Show details of detected spikes
    if spikes:
        print_subheader("Spike Details")
        for spike in spikes[:2]:
            print(f"\n  🚨 {spike['tag']} - DETAILED ANALYSIS")
            print(f"     {spike['security_questions']} security-related questions")
            if spike['sample_questions']:
                print(f"     Sample questions:")
                for q in spike['sample_questions']:
                    print(f"       • {q[:60]}...")

def generate_comprehensive_report():
    """Generate a comprehensive vulnerability prediction report"""
    print_header("VULNPREDICT COMPREHENSIVE REPORT")

    # Initialize all collectors
    reddit = RedditCollector(use_api=False)
    github = GitHubCollector(use_api=False)
    stackoverflow = StackOverflowCollector(use_api=False)

    report = {
        'timestamp': datetime.now().isoformat(),
        'sources': {
            'reddit': {'status': 'active'},
            'github': {'status': 'active'},
            'stackoverflow': {'status': 'active'}
        },
        'high_risk_libraries': [],
        'overall_risk': 'LOW'
    }

    # Collect data from all sources
    reddit_anomalies = []
    for subreddit in ['netsec', 'cybersecurity']:
        posts = reddit.get_hot_posts(subreddit, limit=15)
        anomalies = reddit.detect_anomalies(posts)
        reddit_anomalies.extend(anomalies)

    github_anomalies = []
    repos = github.get_trending_repos(limit=10)
    github_anomalies = github.detect_anomalies(repos)

    so_spikes = stackoverflow.monitor_multiple_tags(['log4j', 'spring', 'openssl'])

    # Identify high-risk libraries
    library_risks = {}

    # From GitHub
    for anomaly in github_anomalies:
        lib = anomaly['repo'].split('/')[-1]
        if lib not in library_risks:
            library_risks[lib] = {'sources': [], 'total_risk': 0}
        library_risks[lib]['sources'].append('GitHub')
        library_risks[lib]['total_risk'] += anomaly['risk_score']

    # From Stack Overflow
    for spike in so_spikes:
        lib = spike['tag']
        if lib not in library_risks:
            library_risks[lib] = {'sources': [], 'total_risk': 0}
        library_risks[lib]['sources'].append('Stack Overflow')
        library_risks[lib]['total_risk'] += spike['risk_score']

    # Sort by risk
    sorted_risks = sorted(library_risks.items(), key=lambda x: x[1]['total_risk'], reverse=True)

    print_subheader("Data Collection Summary")
    print(f"  • Reddit: {len(reddit_anomalies)} anomalies detected")
    print(f"  • GitHub: {len(github_anomalies)} repository anomalies")
    print(f"  • Stack Overflow: {len(so_spikes)} question spikes")

    print_subheader("High-Risk Libraries")
    if sorted_risks:
        for i, (lib, data) in enumerate(sorted_risks[:5], 1):
            risk_level = "🔴 CRITICAL" if data['total_risk'] > 8 else "🟠 HIGH" if data['total_risk'] > 5 else "🟡 MEDIUM"
            print(f"\n  {i}. {lib} - {risk_level}")
            print(f"     Risk Score: {data['total_risk']:.1f}/10")
            print(f"     Signal sources: {', '.join(set(data['sources']))}")
            report['high_risk_libraries'].append({
                'library': lib,
                'risk_score': data['total_risk'],
                'sources': data['sources']
            })
    else:
        print("  ✓ No high-risk libraries detected")

    # Calculate overall risk
    if sorted_risks:
        max_risk = sorted_risks[0][1]['total_risk']
        if max_risk > 8:
            report['overall_risk'] = 'CRITICAL'
        elif max_risk > 5:
            report['overall_risk'] = 'HIGH'
        elif max_risk > 3:
            report['overall_risk'] = 'MEDIUM'

    print_subheader("Overall Risk Assessment")
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    print(f"\n  {risk_emoji.get(report['overall_risk'], '⚪')} Overall Risk Level: {report['overall_risk']}")

    if report['overall_risk'] in ['CRITICAL', 'HIGH']:
        print("\n  ⚠️  RECOMMENDATIONS:")
        print("     1. Review dependencies for high-risk libraries")
        print("     2. Monitor vendor security advisories closely")
        print("     3. Prepare incident response procedures")
        print("     4. Consider temporary mitigations if available")
    else:
        print("\n  ✓ Security posture appears normal")
        print("    Continue routine monitoring")

    return report

def main():
    """Run the complete VulnPredict demo"""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  🛡️  VULNPREDICT - ZERO-DAY EARLY WARNING SYSTEM".center(68) + "║")
    print("║" + "  AI-Powered Vulnerability Prediction Platform".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")

    # Run demonstrations
    demo_reddit_monitoring()
    demo_github_monitoring()
    demo_stackoverflow_monitoring()

    # Generate comprehensive report
    report = generate_comprehensive_report()

    # Save report
    print_header("REPORT SAVED")
    report_filename = f"vulnpredict_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  📄 Report saved to: {report_filename}")

    print("\n" + "=" * 70)
    print("  Demo completed successfully!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
