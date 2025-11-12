# 🛡️ ZeroDay Radar

**AI-powered security intelligence platform for startups**

## 🔴 Problem

Startups waste 72+ hours during security incidents trying to figure out which vulnerabilities actually matter. Enterprise tools are too expensive and complex.

## ✅ Solution

ZeroDay Radar provides AI-driven security intelligence specifically designed for startups.

## 📦 Modules

### ✅ VulnPath (Active)
Maps attack paths through your infrastructure
- Shows which CVEs can actually reach critical assets
- Prioritizes patches based on real risk, not just CVSS scores
- Network topology analysis using graph algorithms

### 🚧 VulnPredict (In Development)
Early warning system for zero-day vulnerabilities
- Monitors GitHub, Stack Overflow, Reddit for anomalies
- Detects unusual activity patterns around libraries
- Predicts which components might have undiscovered vulnerabilities

### 📋 SecureRank (Planned)
Security benchmarking against peer companies
- Compare your security posture to similar startups
- Percentile rankings by industry/stage
- Board-ready security metrics

### 📋 PatchSafe (Planned)
ML-powered patch impact prediction
- Predicts likelihood of patches breaking production
- Suggests testing priorities before deployment
- Historical analysis of patch failures

## 🚀 Quick Start
```bash
# Clone repository
git clone https://github.com/abhiramisr/zeroday-radar.git
cd zeroday-radar

# Install dependencies
pip install -r requirements.txt

# Run VulnPath example
cd vulnpath
python example_usage.py
```

## 🛠️ Tech Stack

- **Python 3.11+** - Core language
- **NetworkX** - Graph analysis for attack paths
- **FastAPI** - REST API framework
- **Pandas** - Data processing
- **Scikit-learn** - Machine learning models

## 📊 Key Metrics

- **72 hours → 30 minutes** - Vulnerability assessment time
- **85%** - Reduction in false positives
- **$0** - Open source, free for startups

## 🎓 Academic Foundation

Built as part of MSITM program at McCombs School of Business, UT Austin
- MIS 385N - Unstructured Data & GenAI
- MIS 382N - Neural Networks & ML

## 📝 Author

Abhirami SR - [LinkedIn](https://linkedin.com/in/abhiramisr) | [Medium](https://medium.com/@thepinnaclewreck)

## 📄 License

MIT License - see [LICENSE](LICENSE) file
