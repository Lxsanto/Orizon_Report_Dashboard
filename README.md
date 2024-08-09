# Enhanced Cybersecurity Assessment Dashboard

## Overview
This project is an advanced cybersecurity assessment dashboard built with Streamlit. It provides a comprehensive view of an organization's security posture through various visualizations and AI-powered analyses.

## Features
- Security Posture Overview
- Vulnerability Severity Distribution
- Vulnerability Discovery Timeline
- Top 10 Critical Vulnerabilities Analysis
- Network Topology Analysis
- CVSS Score Distribution
- Vulnerability Age Analysis
- Remediation Priority Matrix
- Trend Forecasting
- Comparative Analysis
- Security Posture Improvement Suggestions

## Prerequisites
- Python 3.7+
- pip (Python package installer)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/YOUR_USERNAME/cybersecurity-dashboard.git
   cd cybersecurity-dashboard
   ```

2. (Optional but recommended) Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the Streamlit app:
   ```
   streamlit run cybersecurity_dashboard_copy.py
   ```

2. Open a web browser and go to `http://localhost:8501`

3. Upload a JSON file containing vulnerability data when prompted by the dashboard.

## Data Format
The dashboard expects a JSON file with vulnerability data. The JSON should contain an array of objects, each representing a vulnerability with the following fields:
- severity
- description
- created_at
- host
- template_name
- cvss_score (optional)
- exploit_available (optional)

Example:
```json
[
  {
    "severity": "high",
    "description": "SQL Injection vulnerability in login form",
    "created_at": "2023-08-15T14:30:00Z",
    "host": "web-server-01",
    "template_name": "SQL_Injection",
    "cvss_score": 8.5,
    "exploit_available": true
  },
  ...
]
```

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments
- Streamlit for the excellent web app framework
- Plotly for interactive visualizations
- NetworkX for network analysis capabilities
