import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import networkx as nx
from datetime import datetime, timedelta
import pytz
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
from docx import Document
from docx.shared import Inches
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM, pipeline
import torch

# Do you want to clear cached model?
clear = False
if clear:
    st.cache_resource.clear()

# select here LLM setups
model_id = "meta-llama/Meta-Llama-3.1-8B-Instruct"
auth_token = ""

# Set page config
st.set_page_config(page_title="Orizon Security", layout="wide", page_icon="🛡️", initial_sidebar_state="expanded")



### Utility functions ###

@st.cache_resource
def load_llama_model(model_id = "", auth_token = ''):

    if not torch.cuda.is_available():
        print("CUDA GPU not available. Model will be loaded on CPU.")
    else:
        print("CUDA GPU available")

    tokenizer = AutoTokenizer.from_pretrained(model_id, token=auth_token)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_id, 
                                                    torch_dtype=torch.bfloat16, 
                                                    device_map="auto", 
                                                    token=auth_token
                                                    )

    if tokenizer is None or model is None:
        st.error("Failed to load Orizon Engine!")
        return None
    else:
        print(f"Model loaded on {model.device}")
        return tokenizer, model

@st.cache_data
def load_data(file):
    if file is not None:
        try:
            data = json.loads(file.getvalue().decode('utf-8'))
            if isinstance(data, dict):
                return pd.DataFrame(data)
            elif isinstance(data, list):
                return pd.DataFrame(data)
            else:
                st.error("Unrecognized data format. Please upload a valid JSON file.")
                return None
        except Exception as e:
            st.error(f"Error loading data: {str(e)}")
            return None
    return None

def calculate_risk_score(vulnerabilities, severity_column):
    severity_weights = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2, 'info': 1}
    total_weight = sum(severity_weights.get(str(v).lower(), 0) for v in vulnerabilities[severity_column])
    max_weight = len(vulnerabilities) * 10
    return 100 - int((total_weight / max_weight) * 100) if max_weight > 0 else 100

@st.cache_data
def generate_orizon_analysis(_tokenizer, _model, prompt, max_length=None):
    try:
        chat_pipeline = pipeline(
                                "text-generation",
                                model=_model,
                                tokenizer=_tokenizer,
                                device_map="auto")
        
        response = chat_pipeline(prompt)[0]['generated_text']
        
        return response
    except Exception as e:
        st.error(f"Error generating analysis: {str(e)}")
        return "Analysis generation failed. Please try again."
    


### Streamlit CSS dashboard setups ###

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
    
    body {
        font-family: 'Inter', sans-serif;
        background-color: #f8f9fa;
        color: #1a2f4e;
    }
    
    h1, h2, h3 {
        color: #1a2f4e;
        font-weight: 600;
    }
    
    .stAlert {
        background-color: #f8f9fa;
        color: #1a2f4e;
        border: none;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    }
    
    .stButton>button {
        border-radius: 6px;
        background-color: #3b82f6;
        color: #f8f9fa;
        font-weight: 500;
        padding: 0.5rem 1rem;
        border: none;
        transition: all 0.2s ease;
    }
    
    .stButton>button:hover {
        opacity: 0.8;
        box-shadow: 0 2px 4px rgba(59, 130, 246, 0.3);
    }
    
    .stProgress .st-bo {
        background-color: #3b82f6;
    }
    
    div[data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 600;
        color: #1a2f4e;
    }
    
    div[data-testid="stMetricLabel"] {
        font-size: 0.9rem;
        font-weight: 400;
        color: #64748b;
    }
    
    .plot-container {
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        background-color: #f8f9fa;
        padding: 1rem;
        margin-bottom: 1.5rem;
    }
    
    .stSelectbox, .stMultiSelect {
        background-color: #f8f9fa;
        color: #1a2f4e;
        border-radius: 6px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    }
    
    .sidebar .sidebar-content {
        background-color: #f8f9fa;
    }

    .tooltip {
        position: relative;
        display: inline-block;
        border-bottom: 1px dotted #1a2f4e;
    }

    .tooltip .tooltiptext {
        visibility: hidden;
        width: 200px;
        background-color: #1a2f4e;
        color: #f8f9fa;
        text-align: center;
        border-radius: 6px;
        padding: 5px 0;
        position: absolute;
        z-index: 1;
        bottom: 125%;
        left: 50%;
        margin-left: -100px;
        opacity: 0;
        transition: opacity 0.3s;
    }

    .tooltip:hover .tooltiptext {
        visibility: visible;
        opacity: 1;
    }

    .kpi-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        padding: 1rem;
        text-align: center;
    }

    .kpi-value {
        font-size: 2rem;
        font-weight: 600;
        color: #3b82f6;
    }

    .kpi-label {
        font-size: 0.9rem;
        color: #64748b;
    }

    .section-nav {
        position: sticky;
        top: 0;
        background-color: #f8f9fa;
        z-index: 1000;
        padding: 1rem 0;
        margin-bottom: 1rem;
        border-bottom: 1px solid #64748b;
    }

    .section-nav a {
        color: #1a2f4e;
        text-decoration: none;
        margin-right: 1rem;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        transition: background-color 0.2s ease;
    }

    .section-nav a:hover {
        background-color: #3b82f6;
        color: #f8f9fa;
    }
    </style>
    """, unsafe_allow_html=True)


### Prompt eng ### 

def analyze_overview(_tokenizer, _model, total, risk_score, critical, high, medium, low):
    prompt = f"""As a cybersecurity expert, provide a comprehensive analysis of the following security overview:

- Total vulnerabilities: {total}
- Risk score: {risk_score}/100
- Critical vulnerabilities: {critical}
- High vulnerabilities: {high}
- Medium vulnerabilities: {medium}
- Low vulnerabilities: {low}

Your analysis should include:

1. Executive Summary (2-3 sentences):
   - Concise overview of the current security posture
   - High-level assessment of the overall risk

2. Key Findings (4-5 bullet points):
   - Most significant results from the data
   - Patterns or trends in vulnerability distribution
   - Comparison to industry benchmarks or standards (if applicable)

3. Risk Assessment:
   - Detailed interpretation of the risk score
   - Breakdown of vulnerability severity distribution
   - Potential impact on business operations

4. Critical and High Vulnerabilities:
   - In-depth analysis of critical and high vulnerabilities
   - Potential consequences if exploited
   - Urgency of remediation

5. Medium and Low Vulnerabilities:
   - Assessment of medium and low vulnerabilities
   - Cumulative impact on overall security posture
   - Prioritization strategy for addressing these issues

6. Areas of Concern (3-4 points):
   - Identification of main security weak points
   - Potential root causes of vulnerabilities
   - Systemic issues that may be contributing to vulnerabilities

7. Recommendations (5-6 points):
   - Specific, actionable advice to improve security posture
   - Short-term and long-term strategies
   - Suggested timelines for implementation

8. Next Steps (3-4 points):
   - Immediate actions to take within the next 24-48 hours
   - Key stakeholders to involve in the remediation process
   - Metrics to track for measuring improvement

Ensure each section is clearly separated, concise, and provides valuable insights for both technical and non-technical stakeholders."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_severity_distribution(_tokenizer, _model, severity_counts):
    prompt = f"""As a cybersecurity analyst, provide a detailed analysis of the following vulnerability severity distribution:

{severity_counts.to_dict()}

Your analysis should include:

1. Distribution Overview (2-3 sentences):
   - Summary of the overall severity distribution
   - Identification of the most prevalent severity level

2. Detailed Breakdown:
   - Percentage of each severity level (calculate and provide exact percentages)
   - Ratio of high severity (critical + high) to low severity (medium + low) vulnerabilities
   - Comparison to industry average distributions (if known)

3. Critical and High Severity Analysis:
   - Deep dive into critical and high severity vulnerabilities
   - Potential impact on the organization's security posture
   - Urgency of addressing these vulnerabilities

4. Medium and Low Severity Considerations:
   - Analysis of medium and low severity vulnerabilities
   - Cumulative risk assessment of these lower severity issues
   - Importance of addressing these alongside high-priority items

5. Trend Analysis:
   - Identification of any patterns or trends in the severity distribution
   - Comparison to previous assessments or industry trends (if data available)

6. Risk Implications:
   - Overall risk assessment based on the severity distribution
   - Potential consequences if the current distribution persists
   - Impact on the organization's compliance and security standards

7. Remediation Strategy:
   - Proposed approach for addressing vulnerabilities across all severity levels
   - Prioritization framework for balancing high-severity fixes with lower-severity maintenance

8. Recommendations (4-5 points):
   - Specific advice to improve the severity distribution
   - Strategies to reduce the percentage of high and critical severity vulnerabilities
   - Suggestions for ongoing vulnerability management processes

9. Key Performance Indicators:
   - Metrics to monitor for tracking improvements in severity distribution
   - Suggested targets or benchmarks for each severity level
   - Frequency of reassessment and reporting

Ensure each section provides actionable insights and is tailored to both technical and management audiences."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_timeline(_tokenizer, _model, recent_vulnerabilities, recent_critical_high):
    prompt = f"""As a cybersecurity trend analyst, provide a comprehensive analysis of the following vulnerability discovery trend:

- New vulnerabilities discovered in the last 30 days: {len(recent_vulnerabilities)}
- Of which are critical or high severity: {recent_critical_high}

Your analysis should include:

1. Trend Summary (2-3 sentences):
   - Overview of the vulnerability discovery rate in the last 30 days
   - Highlight of the proportion of critical/high severity vulnerabilities

2. Discovery Rate Analysis:
   - Calculation of average new vulnerabilities per day
   - Week-over-week or month-over-month comparison (if historical data is available)
   - Identification of any spikes or anomalies in the discovery rate

3. Severity Breakdown:
   - Detailed analysis of the {recent_critical_high} critical/high severity vulnerabilities
   - Percentage of critical/high vulnerabilities compared to total discoveries
   - Potential reasons for the current severity distribution

4. Impact Assessment:
   - Evaluation of how this discovery trend affects the overall security posture
   - Potential consequences if the current trend continues
   - Comparison to industry benchmarks or expected discovery rates

5. Root Cause Analysis:
   - Potential factors contributing to the current discovery trend
   - Correlation with any recent changes in the IT environment, security practices, or scanning methodologies

6. Resource Implications:
   - Assessment of the organization's capacity to address the current rate of discoveries
   - Potential strain on security teams and remediation resources

7. Projections and Forecasting:
   - Estimated trend for the next 30-60 days based on current data
   - Best-case and worst-case scenarios for vulnerability accumulation

8. Risk Mitigation Strategies:
   - Proposed approaches to manage the flow of new vulnerabilities
   - Strategies to prioritize and address critical/high severity issues rapidly

9. Recommendations (5-6 points):
   - Specific actions to improve vulnerability discovery and remediation processes
   - Suggestions for enhancing the security posture to reduce new vulnerability introductions
   - Advice on balancing proactive security measures with reactive vulnerability management

10. Continuous Monitoring Plan:
    - Key metrics to track for ongoing trend analysis
    - Suggested frequency of assessments and reporting
    - Thresholds or triggers for escalating concern or action

Ensure the analysis is data-driven, provides actionable insights, and considers both immediate tactical responses and long-term strategic improvements."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_top_vulnerabilities(_tokenizer, _model, most_common_type, common_types, hosts_affected, most_affected_host):
    prompt = f"""As a senior vulnerability analyst, provide an in-depth analysis of the top vulnerabilities in the system:

- Most common vulnerability type: '{most_common_type}' (Frequency: {common_types.iloc[0]})
- Number of affected hosts: {hosts_affected}
- Most vulnerable host: {most_affected_host}

Your analysis should include:

1. Overview of Top Vulnerabilities (2-3 sentences):
   - Summary of the most prevalent vulnerability types
   - Quick assessment of the potential impact on the system

2. Analysis of Most Common Vulnerability Type:
   - Detailed description of the '{most_common_type}' vulnerability
   - Common causes and attack vectors associated with this vulnerability
   - Potential consequences if exploited
   - Industry context: how common is this vulnerability type across similar systems?

3. Vulnerability Spread Assessment:
   - Analysis of the number of affected hosts ({hosts_affected})
   - Percentage of total network affected
   - Potential for lateral movement or escalation across the network

4. Most Vulnerable Host Analysis:
   - Detailed examination of why {most_affected_host} is the most affected
   - Potential reasons for its heightened vulnerability (e.g., outdated software, misconfigurations)
   - Risks associated with this host being compromised
   - Recommendations for immediate mitigation specific to this host

5. Patterns and Trends:
   - Identification of common themes among top vulnerabilities
   - Any correlations between vulnerability types and specific systems or software
   - Possible systemic issues contributing to these vulnerabilities

6. Risk Assessment:
   - Overall risk evaluation based on the top vulnerabilities
   - Potential business impact if these vulnerabilities are exploited
   - Compliance implications, if any

7. Mitigation Strategies (5-6 points):
   - Prioritized list of remediation actions
   - Both short-term fixes and long-term preventive measures
   - Specific recommendations for addressing the most common vulnerability types
   - Suggestions for improving overall system hardening

8. Resource Allocation:
   - Estimated effort required for addressing top vulnerabilities
   - Suggestions for prioritizing remediation efforts
   - Potential tools or processes to aid in vulnerability management

9. Monitoring and Follow-up:
   - Key metrics to track for assessing progress in vulnerability reduction
   - Recommended timeframes for reassessment
   - Suggestions for ongoing vulnerability management processes

10. Learning Opportunities:
    - Insights gained from this vulnerability analysis
    - Recommendations for staff training or awareness programs
    - Suggestions for improving the vulnerability detection and analysis process

Ensure the analysis is thorough, provides actionable insights, and considers both immediate security improvements and long-term strategic enhancements to the security posture."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def generate_network_analysis(_tokenizer, _model, top_central, density, communities):
    prompt = f"""As a network security architect, analyze the following network topology information:

- Number of central nodes identified: {len(top_central)}
- Network density: {density:.4f}
- Number of identified communities: {len(communities)}

Provide a comprehensive analysis including:

1. Topology Overview (2-3 sentences):
   - Brief description of the overall network structure
   - Initial assessment of the network's complexity and interconnectedness

2. Central Nodes Analysis:
   - Importance and role of the {len(top_central)} most central nodes
   - Potential security implications of these central nodes (e.g., single points of failure, high-value targets)
   - Recommendations for protecting and monitoring these critical nodes

3. Network Density Interpretation:
   - Explanation of the density value {density:.4f} in context
   - Implications for threat propagation and network resilience
   - Comparison to ideal density ranges for security and performance

4. Community Structure Evaluation:
   - Significance of having {len(communities)} identified communities
   - Potential security advantages or vulnerabilities of this community structure
   - Recommendations for inter-community security measures

5. Topological Vulnerabilities:
   - Identification of potential weak points based on the network structure
   - Analysis of possible attack vectors that could exploit the current topology
   - Assessment of the ease of lateral movement within the network

6. Resilience and Redundancy:
   - Evaluation of the network's ability to withstand targeted attacks
   - Analysis of redundancy in critical paths and systems
   - Recommendations for improving network resilience

7. Segmentation Analysis:
   - Assessment of current network segmentation based on the topology
   - Recommendations for optimizing segmentation to enhance security
   - Potential implementation of zero trust architecture principles

8. Traffic Flow Implications:
   - Analysis of how the network structure might affect traffic patterns
   - Identification of potential bottlenecks or high-traffic areas
   - Recommendations for traffic monitoring and analysis

9. Scalability and Future Growth:
   - Assessment of the network's ability to scale based on its current structure
   - Potential challenges in maintaining security with network growth
   - Recommendations for scalable security architectures

10. Improvement Recommendations (5-6 points):
    - Prioritized list of actions to enhance network security based on topological analysis
    - Suggestions for redesigning problematic areas of the network
    - Recommendations for implementing advanced security measures (e.g., microsegmentation, SDN)

11. Monitoring and Maintenance Strategy:
    - Key metrics to monitor for assessing ongoing network health and security
    - Recommended frequency for topology reassessment and security audits
    - Suggestions for automated tools or processes for continuous network analysis

12. Compliance and Best Practices:
    - Evaluation of the network topology against industry standards and best practices
    - Identification of any compliance issues based on the network structure
    - Recommendations for aligning the network with security frameworks and regulations

Ensure each section provides actionable insights and considers both immediate security enhancements and long-term strategic improvements to the network architecture."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_cvss_distribution(_tokenizer, _model, avg_cvss, high_cvss_count, total_vulns):
    prompt = f"""As a CVSS expert, provide a detailed analysis of the following CVSS score distribution:

- Average CVSS score: {avg_cvss:.2f}
- Number of high-risk vulnerabilities (CVSS > 7.0): {high_cvss_count}
- Total number of vulnerabilities: {total_vulns}

Your analysis should include:

1. Overview (2-3 sentences):
   - Summary of the CVSS score distribution
   - Initial assessment of the overall severity landscape

2. Average Score Analysis:
   - Interpretation of the average CVSS score of {avg_cvss:.2f}
   - Comparison with industry standards and benchmarks
   - Implications of this average score on the overall security posture

3. High-Risk Vulnerabilities Deep Dive:
   - Analysis of the {high_cvss_count} high-risk vulnerabilities
   - Percentage of high-risk vulnerabilities in relation to total vulnerabilities
   - Potential impact and urgency of addressing these high-risk issues

4. CVSS Score Breakdown:
   - Distribution of scores across different ranges (e.g., 0-3.9, 4.0-6.9, 7.0-8.9, 9.0-10)
   - Identification of any patterns or clusters in the score distribution
   - Analysis of the lowest and highest CVSS scores in the dataset

5. Temporal and Environmental Considerations:
   - Discussion on how temporal and environmental metrics might affect the base CVSS scores
   - Recommendations for incorporating these factors into the risk assessment

6. Impact on Security Posture:
   - Assessment of how this CVSS distribution affects overall organizational risk
   - Potential consequences if the current distribution persists
   - Comparison of the organization's CVSS profile to industry averages or best practices

7. Remediation Prioritization:
   - Strategies for addressing vulnerabilities based on CVSS scores
   - Balancing the focus between high-risk and lower-risk vulnerabilities
   - Recommended approach for continuous vulnerability management

8. Resource Allocation:
   - Suggestions for allocating security resources based on the CVSS distribution
   - Estimated effort required to address vulnerabilities at different severity levels

9. Recommendations (5-6 points):
   - Specific actions to improve the CVSS score distribution
   - Strategies to reduce the number and impact of high-risk vulnerabilities
   - Suggestions for enhancing the vulnerability assessment and scoring process

10. Compliance and Reporting:
    - Implications of the CVSS distribution on regulatory compliance
    - Recommendations for reporting CVSS metrics to different stakeholders (e.g., management, board, auditors)

11. Trend Analysis and Forecasting:
    - If historical data is available, analysis of CVSS score trends over time
    - Predictions for future CVSS distributions if current patterns continue

12. Key Performance Indicators:
    - Metrics to monitor for tracking improvements in CVSS distribution
    - Suggested targets or benchmarks for CVSS scores
    - Frequency of reassessment and reporting on CVSS metrics

Ensure the analysis is thorough, provides actionable insights, and considers both immediate tactical responses and long-term strategic improvements to vulnerability management based on CVSS scores."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_vulnerability_age(_tokenizer, _model, avg_age, old_vulnerabilities_count, total_vulns):
    prompt = f"""As a vulnerability lifecycle management expert, provide a comprehensive analysis of the following vulnerability age distribution:

- Average age of vulnerabilities: {avg_age:.1f} days
- Number of vulnerabilities older than 90 days: {old_vulnerabilities_count}
- Total number of vulnerabilities: {total_vulns}

Your analysis should include:

1. Overview (2-3 sentences):
   - Summary of the vulnerability age distribution
   - Initial assessment of the vulnerability management efficiency

2. Average Age Analysis:
   - Interpretation of the average age of {avg_age:.1f} days
   - Comparison with industry best practices and benchmarks
   - Implications of this average age on the overall security posture

3. Persistent Vulnerabilities Deep Dive:
   - Analysis of the {old_vulnerabilities_count} vulnerabilities older than 90 days
   - Percentage of old vulnerabilities in relation to total vulnerabilities
   - Potential reasons for their persistence (e.g., complexity, resource constraints, risk acceptance)

4. Age Distribution Breakdown:
   - Distribution of vulnerabilities across different age ranges (e.g., 0-30 days, 31-60 days, 61-90 days, 90+ days)
   - Identification of any patterns or trends in the age distribution
   - Analysis of the oldest and newest vulnerabilities in the dataset

5. Risk Accumulation:
   - Assessment of how vulnerability age contributes to cumulative risk
   - Potential consequences of allowing vulnerabilities to persist
   - Correlation between vulnerability age and severity (if data available)

6. Remediation Velocity:
   - Analysis of the organization's speed in addressing vulnerabilities
   - Comparison of remediation times for different severity levels (if data available)
   - Identification of bottlenecks in the remediation process

7. Impact on Security Posture:
   - Evaluation of how the current age distribution affects overall organizational risk
   - Potential exposure to threats due to unpatched vulnerabilities
   - Compliance implications of vulnerability persistence

8. Remediation Strategy:
   - Proposed approach for addressing vulnerabilities based on their age and severity
   - Strategies to reduce the average age of vulnerabilities
   - Recommendations for dealing with persistent, old vulnerabilities

9. Resource Allocation:
   - Suggestions for allocating security resources based on the age distribution
   - Estimated effort required to address vulnerabilities of different ages

10. Recommendations (5-6 points):
    - Specific actions to improve vulnerability lifecycle management
    - Strategies to prevent vulnerabilities from aging beyond acceptable thresholds
    - Suggestions for enhancing the vulnerability assessment and remediation processes

11. Continuous Improvement:
    - Recommendations for ongoing vulnerability management processes
    - Strategies for preventing the introduction of new vulnerabilities
    - Suggestions for improving collaboration between security, IT, and development teams

12. Key Performance Indicators:
    - Metrics to monitor for tracking improvements in vulnerability age management
    - Suggested targets or benchmarks for vulnerability age
    - Frequency of reassessment and reporting on vulnerability lifecycle metrics

13. Tools and Automation:
    - Recommendations for tools or automation to assist in vulnerability lifecycle management
    - Suggestions for integrating vulnerability management into CI/CD pipelines (if applicable)

Ensure the analysis is thorough, provides actionable insights, and considers both immediate tactical responses and long-term strategic improvements to vulnerability lifecycle management."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_vulnerability_types(_tokenizer, _model, most_common_type, frequency, top_10_types):
    prompt = f"""As a vulnerability categorization expert, provide a detailed analysis of the following vulnerability type distribution:

- Most common vulnerability type: '{most_common_type}' (Frequency: {frequency})
- Top 10 vulnerability types: {', '.join(top_10_types)}

Your analysis should include:

1. Overview (2-3 sentences):
   - Summary of the vulnerability type distribution
   - Initial assessment of the organization's security challenges based on prevalent vulnerability types

2. Most Common Vulnerability Type Analysis:
   - Detailed description of the '{most_common_type}' vulnerability
   - Common causes and attack vectors associated with this vulnerability type
   - Potential impact and exploitation scenarios
   - Prevalence of this vulnerability type in the industry

3. Top 10 Vulnerability Types Breakdown:
   - Brief description of each vulnerability type in the top 10 list
   - Analysis of the distribution and frequency of these types
   - Identification of any patterns or correlations among the top vulnerability types

4. Root Cause Analysis:
   - Exploration of potential systemic issues leading to the most common vulnerability types
   - Analysis of whether certain vulnerability types are linked to specific technologies, practices, or areas of the infrastructure

5. Risk Assessment:
   - Evaluation of the overall risk posed by the current vulnerability type distribution
   - Analysis of how different vulnerability types might compound or interact to create more significant risks

6. Industry Comparison:
   - Comparison of the organization's vulnerability type distribution to industry norms or benchmarks
   - Identification of any unusual or organization-specific patterns in vulnerability types

7. Remediation Strategies:
   - Targeted approaches for addressing each of the top vulnerability types
   - Prioritization framework for tackling different vulnerability categories
   - Recommendations for tools, processes, or practices to prevent recurrence of common vulnerability types

8. Security Posture Improvement:
   - Suggestions for enhancing overall security based on the vulnerability type analysis
   - Recommendations for security controls or practices that could mitigate multiple vulnerability types simultaneously

9. Training and Awareness:
   - Proposals for staff training programs based on prevalent vulnerability types
   - Suggestions for developer education to prevent introduction of common vulnerabilities

10. Trend Analysis:
    - If historical data is available, analysis of how vulnerability types have evolved over time
    - Predictions for future vulnerability landscapes based on current trends

11. Recommendations (5-6 points):
    - Specific actions to address the most critical vulnerability types
    - Strategies for reducing the occurrence of common vulnerabilities
    - Suggestions for improving vulnerability detection and categorization processes

12. Continuous Monitoring Plan:
    - Key metrics to track for ongoing analysis of vulnerability type distribution
    - Suggested frequency of assessments and reporting
    - Thresholds or triggers for escalating concern or action based on vulnerability type prevalence

13. Tool and Process Evaluation:
    - Assessment of current vulnerability scanning and management tools' effectiveness in identifying various vulnerability types
    - Recommendations for tool improvements or new tools to enhance vulnerability type detection and analysis

Ensure the analysis is comprehensive, provides actionable insights, and considers both immediate tactical responses to current vulnerability types and long-term strategic improvements to prevent future occurrences."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_remediation_priority(_tokenizer, _model, high_priority_count, total_vulns):
    prompt = f"""As a vulnerability remediation strategist, provide a comprehensive analysis of the current remediation priority situation:

- Number of high-priority vulnerabilities: {high_priority_count}
- Total number of vulnerabilities: {total_vulns}

Your analysis should include:

1. Overview (2-3 sentences):
   - Summary of the current remediation situation
   - Initial assessment of the urgency and scale of remediation efforts required

2. High-Priority Vulnerabilities Analysis:
   - Detailed examination of the {high_priority_count} high-priority vulnerabilities
   - Percentage of high-priority vulnerabilities in relation to total vulnerabilities
   - Potential impact and risks associated with these high-priority issues
   - Estimation of the overall risk represented by these vulnerabilities

3. Remediation Challenges:
   - Identification of potential obstacles in addressing high-priority vulnerabilities
   - Analysis of resource requirements (time, personnel, budget) for effective remediation
   - Consideration of potential business impact during remediation processes

4. Prioritization Strategy:
   - Proposed framework for prioritizing vulnerability remediation
   - Criteria to consider beyond just severity (e.g., exploitability, business impact, data sensitivity)
   - Suggestions for balancing high-priority fixes with ongoing maintenance of lower-priority issues

5. Risk-Based Approach:
   - Recommendations for adopting a risk-based approach to remediation
   - Strategies for quantifying and comparing risks across different vulnerabilities
   - Suggestions for involving business stakeholders in risk assessment and prioritization

6. Remediation Timeline:
   - Proposed timeline for addressing high-priority vulnerabilities
   - Estimation of time required for full remediation of all identified issues
   - Suggestions for phased approach to remediation, if applicable

7. Resource Allocation:
   - Recommendations for allocating personnel and resources to remediation efforts
   - Suggestions for training or upskilling required for effective remediation
   - Consideration of potential need for external assistance or specialized tools

8. Continuous Monitoring and Reassessment:
   - Strategies for ongoing monitoring of remediation progress
   - Suggestions for regular reassessment of vulnerability priorities
   - Recommendations for adjusting remediation strategies based on new findings or changing threat landscape

9. Recommendations (5-6 points):
   - Specific, actionable steps to begin addressing high-priority vulnerabilities
   - Strategies for improving overall remediation processes
   - Suggestions for enhancing vulnerability management lifecycle

10. Metrics and KPIs:
    - Key performance indicators to track remediation progress
    - Suggested targets or benchmarks for remediation timelines
    - Metrics to measure the effectiveness of the remediation process

11. Communication Plan:
    - Recommendations for reporting remediation progress to various stakeholders
    - Strategies for maintaining transparency about security risks and remediation efforts
    - Suggestions for educating the organization about the importance of timely remediation

12. Long-term Preventive Measures:
    - Recommendations for reducing the introduction of new vulnerabilities
    - Strategies for improving secure development practices, if applicable
    - Suggestions for enhancing the overall security posture to minimize future high-priority vulnerabilities

13. Compliance Considerations:
    - Analysis of how the current remediation priorities align with relevant compliance requirements
    - Recommendations for ensuring remediation efforts satisfy regulatory obligations

14. Incident Response Integration:
    - Suggestions for integrating remediation priorities with incident response planning
    - Strategies for rapidly addressing high-priority vulnerabilities in the event of an active threat

Ensure the analysis is thorough, provides actionable insights, and balances the need for urgent remediation of high-priority issues with sustainable, long-term vulnerability management practices."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_vulnerability_trend(_tokenizer, _model, current_avg, trend, historical_data):
    prompt = f"""As a cybersecurity trend analyst, provide a comprehensive analysis of the following vulnerability trend:

- Current 7-day moving average of new vulnerabilities: {current_avg:.2f}
- Observed trend: {trend}
- Historical data: {historical_data}

Your analysis should include:

1. Overview (2-3 sentences):
   - Summary of the current vulnerability trend
   - Initial assessment of the direction and significance of the trend

2. 7-Day Moving Average Analysis:
   - Detailed interpretation of the current average of {current_avg:.2f} new vulnerabilities
   - Comparison with previous periods (week-over-week, month-over-month)
   - Identification of any significant changes or anomalies in the moving average

3. Trend Assessment:
   - In-depth analysis of the {trend} trend
   - Quantification of the trend (e.g., percentage increase/decrease over time)
   - Identification of any patterns, cycles, or seasonality in vulnerability discovery

4. Historical Context:
   - Comparison of current trend with historical data
   - Identification of long-term patterns or shifts in vulnerability discovery rates
   - Analysis of factors that may have influenced historical trends

5. Root Cause Analysis:
   - Exploration of potential causes for the observed trend
   - Consideration of internal factors (e.g., changes in scanning practices, system updates)
   - Analysis of external factors (e.g., new threat landscapes, industry-wide vulnerabilities)

6. Impact on Security Posture:
   - Assessment of how the current trend affects overall organizational risk
   - Projection of potential consequences if the trend continues
   - Analysis of the organization's capacity to manage vulnerabilities at the current rate

7. Benchmarking:
   - Comparison of the organization's vulnerability trend with industry standards or peers
   - Analysis of how the current trend positions the organization in terms of security maturity

8. Forecasting:
   - Short-term projections for vulnerability discovery rates (next 30-60 days)
   - Long-term forecast if current trends persist
   - Best-case and worst-case scenarios for future vulnerability landscapes

9. Recommendations (5-6 points):
   - Specific actions based on the current trend and projections
   - Strategies to capitalize on a positive trend or reverse a negative one
   - Suggestions for improving vulnerability discovery and management processes

10. Resource Implications:
    - Analysis of resource requirements to address vulnerabilities at the current rate
    - Recommendations for scaling remediation efforts if needed
    - Suggestions for optimizing resource allocation based on trend analysis

11. Risk Management Strategies:
    - Proposed approaches for managing risk in light of the current trend
    - Recommendations for adjusting security controls or practices
    - Suggestions for enhancing resilience against potential increases in vulnerabilities

12. Continuous Monitoring Plan:
    - Key metrics to track for a more comprehensive understanding of vulnerability trends
    - Recommended frequency for trend analysis and reporting
    - Thresholds or triggers for escalating concern or action based on trend data

13. Communication Strategy:
    - Recommendations for reporting trend data to various stakeholders
    - Strategies for contextualizing trend information for different audiences (e.g., technical teams, management, board)

14. Trend Correlation Analysis:
    - Exploration of correlations between vulnerability trends and other security metrics
    - Analysis of how vulnerability trends might impact or be impacted by other areas of cybersecurity

Ensure the analysis is data-driven, provides actionable insights, and considers both short-term tactical responses and long-term strategic adjustments based on the observed vulnerability trends."""
    return generate_orizon_analysis(_tokenizer, _model, prompt)

# Function to format responses
def format_analysis_response(analysis_content):
    formatted_response = f"""
# Orizon Security Analysis

{analysis_content}
"""
    return formatted_response

# Function to apply consistent style to all charts
def apply_custom_style(fig):
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(family="Inter, sans-serif", size=12, color="#1a2f4e"),
        title=dict(font=dict(size=18, color="#1a2f4e")),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        margin=dict(l=20, r=20, t=40, b=20)
    )
    fig.update_xaxes(showgrid=False, showline=True, linecolor='#64748b')
    fig.update_yaxes(showgrid=True, gridcolor='#64748b', showline=True, linecolor='#64748b')
    return fig

# Color palette definition
color_palette = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#6366f1']

# New functions for cybersecurity-themed charts
def create_vulnerability_heatmap(vulnerabilities, host_column, severity_column):
    pivot = vulnerabilities.pivot_table(index=host_column, columns=severity_column, aggfunc='size', fill_value=0)
    fig = px.imshow(pivot, 
                    labels=dict(x="Severity", y="Host", color="Count"),
                    title="Vulnerability Heatmap by Host and Severity")
    fig = apply_custom_style(fig)
    return fig

def create_vulnerability_radar(vulnerabilities, type_column):
    type_counts = vulnerabilities[type_column].value_counts().nlargest(5)
    fig = go.Figure(data=go.Scatterpolar(
      r=type_counts.values,
      theta=type_counts.index,
      fill='toself'
    ))
    fig.update_layout(
      polar=dict(
        radialaxis=dict(
          visible=True,
          range=[0, max(type_counts.values)]
        )),
      showlegend=False,
      title="Top 5 Vulnerability Types"
    )
    fig = apply_custom_style(fig)
    return fig

def create_attack_timeline(vulnerabilities, created_at_column, severity_column):
    vulnerabilities['date'] = pd.to_datetime(vulnerabilities[created_at_column]).dt.date
    timeline = vulnerabilities.groupby(['date', severity_column]).size().unstack(fill_value=0)
    fig = px.area(timeline, 
                  labels={'date': 'Date', 'value': 'Number of Vulnerabilities', 'variable': 'Severity'},
                  title="Vulnerability Discovery Timeline")
    fig = apply_custom_style(fig)
    return fig

def create_severity_impact_bubble(vulnerabilities, severity_column, cvss_column, host_column):
    if all(col in vulnerabilities.columns for col in [severity_column, cvss_column, host_column]):
        vulnerability_counts = vulnerabilities.groupby([severity_column, host_column]).size().reset_index(name='count')
        avg_cvss = vulnerabilities.groupby([severity_column, host_column])[cvss_column].mean().reset_index(name='avg_cvss')
        bubble_data = pd.merge(vulnerability_counts, avg_cvss, on=[severity_column, host_column])
        
        fig = px.scatter(bubble_data, 
                         x='count', 
                         y='avg_cvss', 
                         size='count', 
                         color=severity_column,
                         hover_name=host_column,
                         labels={'count': 'Number of Vulnerabilities', 'avg_cvss': 'Average CVSS Score'},
                         title="Severity, Impact, and Prevalence Correlation")
        fig = apply_custom_style(fig)
        return fig
    else:
        return None

# Improved PDF report generation
def generate_pdf_report(vulnerabilities, analyses, figures):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []

    styles = getSampleStyleSheet()
    
    # Modifica gli stili esistenti invece di aggiungerne di nuovi
    styles['Title'].fontSize = 24
    styles['Title'].spaceAfter = 12
    styles['Heading1'].fontSize = 18
    styles['Heading1'].spaceAfter = 6
    
    # Se vuoi aggiungere un nuovo stile, usa un nome che sicuramente non esiste
    styles.add(ParagraphStyle(name='BodyTextCustom', fontSize=10, spaceAfter=6))

    # Cover page
    elements.append(Paragraph("Orizon Security Dashboard Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyTextCustom']))
    elements.append(PageBreak())

    # Table of Contents
    toc = []
    toc.append(Paragraph("Table of Contents", styles['Heading1']))
    for section in analyses.keys():
        toc.append(Paragraph(section.capitalize(), styles['BodyTextCustom']))
    elements.extend(toc)
    elements.append(PageBreak())

    for section, content in analyses.items():
        elements.append(Paragraph(section.capitalize(), styles['Heading1']))
        elements.append(Paragraph(content, styles['BodyTextCustom']))
        elements.append(Spacer(1, 12))
        
        if section in figures:
            img_buffer = BytesIO()
            figures[section].write_image(img_buffer, format="png", width=800, height=400, scale=2)
            img = Image(img_buffer, width=7.5*inch, height=3.75*inch)
            elements.append(img)
            elements.append(Spacer(1, 12))

    # Add summary tables
    elements.append(Paragraph("Vulnerability Summary", styles['Heading1']))
    
    # Severity Distribution Table
    severity_counts = vulnerabilities['severity'].value_counts()
    severity_data = [['Severity', 'Count', 'Percentage']]
    for severity, count in severity_counts.items():
        percentage = (count / len(vulnerabilities)) * 100
        severity_data.append([severity, str(count), f"{percentage:.2f}%"])
    
    severity_table = Table(severity_data)
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(severity_table)
    elements.append(Spacer(1, 12))

    # Top 10 Vulnerabilities Table
    top_10 = vulnerabilities.sort_values('severity', ascending=False).head(10)
    top_10_data = [['Host', 'Severity', 'Vulnerability', 'Description']]
    for _, row in top_10.iterrows():
        top_10_data.append([row['host'], row['severity'], row['template_name'], row['description'][:50] + '...'])
    
    top_10_table = Table(top_10_data, colWidths=[1*inch, 1*inch, 2*inch, 3*inch])
    top_10_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(top_10_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer

# Function to generate Word report
def generate_word_report(vulnerabilities, analyses, figures):
    doc = Document()
    doc.add_heading('Orizon Security Dashboard Report', 0)

    doc.add_paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    doc.add_page_break()

    # Table of Contents
    doc.add_heading('Table of Contents', level=1)
    for section in analyses.keys():
        doc.add_paragraph(section.capitalize(), style='List Bullet')
    doc.add_page_break()

    for section, content in analyses.items():
        doc.add_heading(section.capitalize(), level=1)
        doc.add_paragraph(content)
        
        if section in figures:
            img_buffer = BytesIO()
            figures[section].write_image(img_buffer, format="png", width=800, height=400, scale=2)
            doc.add_picture(img_buffer, width=Inches(7.5))

    # Add summary tables
    doc.add_heading('Vulnerability Summary', level=1)
    
    # Severity Distribution Table
    severity_counts = vulnerabilities['severity'].value_counts()
    table = doc.add_table(rows=1, cols=3)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Severity'
    hdr_cells[1].text = 'Count'
    hdr_cells[2].text = 'Percentage'
    for severity, count in severity_counts.items():
        percentage = (count / len(vulnerabilities)) * 100
        row_cells = table.add_row().cells
        row_cells[0].text = severity
        row_cells[1].text = str(count)
        row_cells[2].text = f"{percentage:.2f}%"

    doc.add_paragraph()

    # Top 10 Vulnerabilities Table
    doc.add_heading('Top 10 Vulnerabilities', level=2)
    top_10 = vulnerabilities.sort_values('severity', ascending=False).head(10)
    table = doc.add_table(rows=1, cols=4)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Host'
    hdr_cells[1].text = 'Severity'
    hdr_cells[2].text = 'Vulnerability'
    hdr_cells[3].text = 'Description'
    for _, row in top_10.iterrows():
        row_cells = table.add_row().cells
        row_cells[0].text = row['host']
        row_cells[1].text = row['severity']
        row_cells[2].text = row['template_name']
        row_cells[3].text = row['description'][:50] + '...'

    buffer = BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer

def main():
    st.sidebar.title("🛡️ Orizon Security")
    
    st.sidebar.header("Dashboard Controls")
    uploaded_file = st.sidebar.file_uploader("Upload Vulnerability JSON", type="json", key="vuln_upload")
    
    if uploaded_file:
        with st.spinner("Processing vulnerability data..."):
            vulnerabilities = load_data(uploaded_file)
        if vulnerabilities is not None and not vulnerabilities.empty:
            st.sidebar.success("File processed successfully!")
            
            # Ensure 'created_at' is in datetime format
            if 'created_at' in vulnerabilities.columns:
                vulnerabilities['created_at'] = pd.to_datetime(vulnerabilities['created_at'], errors='coerce')
                
                # Remove rows with invalid dates
                vulnerabilities = vulnerabilities.dropna(subset=['created_at'])
                
                if not vulnerabilities.empty:
                    # Global filters
                    st.sidebar.subheader("Global Filters")
                    min_date = vulnerabilities['created_at'].min().date()
                    max_date = vulnerabilities['created_at'].max().date()
                    date_range = st.sidebar.date_input(
                        "Date Range",
                        value=(min_date, max_date),
                        min_value=min_date,
                        max_value=max_date,
                        key="date_filter"
                    )
                    severity_filter = st.sidebar.multiselect(
                        "Severity",
                        options=vulnerabilities['severity'].unique(),
                        default=vulnerabilities['severity'].unique(),
                        key="severity_filter"
                    )
                    
                    # Apply filters
                    mask = (
                        (vulnerabilities['created_at'].dt.date >= date_range[0]) &
                        (vulnerabilities['created_at'].dt.date <= date_range[1]) &
                        (vulnerabilities['severity'].isin(severity_filter))
                    )
                    filtered_vulnerabilities = vulnerabilities[mask]
                    
                    st.sidebar.info(f"Showing {len(filtered_vulnerabilities)} out of {len(vulnerabilities)} vulnerabilities")
                else:
                    st.error("No valid data after date conversion. Please check your data format.")
                    return
            else:
                st.error("The 'created_at' column is missing from the data. Please check your JSON file.")
                return

        # Main content
        st.title("Orizon Security Dashboard")
        st.markdown("Powered by advanced AI for comprehensive cybersecurity analysis")

        # Load model
        tokenizer, model = load_llama_model()

        # Automatic column detection
        severity_column = 'severity' if 'severity' in filtered_vulnerabilities.columns else None
        description_column = 'description' if 'description' in filtered_vulnerabilities.columns else None
        created_at_column = 'created_at' if 'created_at' in filtered_vulnerabilities.columns else None
        host_column = 'host' if 'host' in filtered_vulnerabilities.columns else None

        # Navigation
        st.markdown("""
        <div class="section-nav">
            <a href="#security-posture-overview">Overview</a>
            <a href="#vulnerability-severity-distribution">Severity</a>
            <a href="#vulnerability-discovery-timeline">Timeline</a>
            <a href="#top-10-critical-vulnerabilities">Top Vulnerabilities</a>
            <a href="#network-topology-analysis">Network Analysis</a>
            <a href="#additional-cybersecurity-insights">Additional Insights</a>
        </div>
        """, unsafe_allow_html=True)

        # Executive Summary
        st.header("Executive Summary", anchor="executive-summary")
        total_vulns = len(filtered_vulnerabilities)
        risk_score = calculate_risk_score(filtered_vulnerabilities, severity_column)
        critical_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'critical'])
        high_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'high'])
        medium_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'medium'])
        low_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'low'])
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{total_vulns}</div>
                <div class="kpi-label">Total Vulnerabilities</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{risk_score}/100</div>
                <div class="kpi-label">Risk Score</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{critical_vulns}</div>
                <div class="kpi-label">Critical Vulnerabilities</div>
            </div>
            """, unsafe_allow_html=True)
        with col4:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{high_vulns}</div>
                <div class="kpi-label">High Vulnerabilities</div>
            </div>
            """, unsafe_allow_html=True)

        with st.expander("View Executive Summary"):
            st.markdown(format_analysis_response(analyze_overview(tokenizer, model, total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns)))

        # Security Posture Overview
        st.header("Security Posture Overview", anchor="security-posture-overview")
        col1, col2 = st.columns([3, 2])
        with col1:
            fig_risk_score = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Score"},
                gauge = {
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#1a2f4e"},
                    'bar': {'color': color_palette[0]},
                    'steps' : [
                        {'range': [0, 50], 'color': color_palette[1]},
                        {'range': [50, 75], 'color': color_palette[3]},
                        {'range': [75, 100], 'color': color_palette[2]}],
                    'threshold': {
                        'line': {'color': color_palette[1], 'width': 4},
                        'thickness': 0.75,
                        'value': risk_score}}))
            fig_risk_score = apply_custom_style(fig_risk_score)
            fig_risk_score.update_layout(height=300)
            st.plotly_chart(fig_risk_score, use_container_width=True, config={'displayModeBar': False})
        
        with col2:
            st.subheader("Orizon Engine Analysis")
            with st.spinner("Generating overview analysis..."):
                overview_analysis = analyze_overview(tokenizer, model, total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns)
            st.markdown(format_analysis_response(overview_analysis))

        # Severity Distribution
        st.header("Vulnerability Severity Distribution", anchor="vulnerability-severity-distribution")
        col1, col2 = st.columns([2, 1])
        with col1:
            severity_counts = filtered_vulnerabilities[severity_column].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values, 
                names=severity_counts.index, 
                title="Vulnerability Severity Distribution",
                color=severity_counts.index,
                color_discrete_map={'critical': color_palette[1], 'high': color_palette[3], 'medium': color_palette[2], 'low': color_palette[0], 'info': color_palette[4]}
            )
            fig_severity.update_traces(textposition='inside', textinfo='percent+label')
            fig_severity = apply_custom_style(fig_severity)
            st.plotly_chart(fig_severity, use_container_width=True, config={'displayModeBar': False})
        with col2:
            st.subheader("Orizon Engine Analysis")
            with st.spinner("Generating severity analysis..."):
                severity_analysis = analyze_severity_distribution(tokenizer, model, severity_counts)
            st.markdown(format_analysis_response(severity_analysis))

        # Vulnerability Timeline
        st.header("Vulnerability Discovery Timeline", anchor="vulnerability-discovery-timeline")
        col1, col2 = st.columns([2, 1])
        with col1:
            fig_timeline = create_attack_timeline(filtered_vulnerabilities, created_at_column, severity_column)
            st.plotly_chart(fig_timeline, use_container_width=True, config={'displayModeBar': False})
        with col2:
            st.subheader("Orizon Engine Analysis")
            recent_vulnerabilities = filtered_vulnerabilities[filtered_vulnerabilities[created_at_column] > (datetime.now(pytz.utc) - timedelta(days=30))]
            recent_critical_high = len(recent_vulnerabilities[recent_vulnerabilities[severity_column].str.lower().isin(['critical', 'high'])])
            with st.spinner("Generating trend analysis..."):
                trend_analysis = analyze_timeline(tokenizer, model, recent_vulnerabilities, recent_critical_high)
            st.markdown(format_analysis_response(trend_analysis))

        # Top 10 Vulnerabilities
        st.header("Top 10 Critical Vulnerabilities", anchor="top-10-critical-vulnerabilities")
        top_10 = filtered_vulnerabilities.sort_values(severity_column, ascending=False).head(10)
        fig_top_10 = go.Figure(data=[go.Table(
            header=dict(values=['Host', 'Severity', 'Vulnerability', 'Description'],
                        fill_color=color_palette[0],
                        align='left',
                        font=dict(color='white', size=12)),
            cells=dict(values=[top_10[host_column], top_10[severity_column], top_10['template_name'], top_10[description_column]],
                       fill_color='rgba(0,0,0,0)',
                       align='left'))
        ])
        fig_top_10 = apply_custom_style(fig_top_10)
        st.plotly_chart(fig_top_10, use_container_width=True, config={'displayModeBar': False})
        st.subheader("Orizon Engine Analysis")
        common_types = top_10['template_name'].value_counts()
        most_common_type = common_types.index[0]
        hosts_affected = top_10[host_column].nunique()
        most_affected_host = top_10[host_column].value_counts().index[0]
        with st.spinner("Analyzing top vulnerabilities..."):
            top_vuln_analysis = analyze_top_vulnerabilities(tokenizer, model, most_common_type, common_types, hosts_affected, most_affected_host)
        st.markdown(format_analysis_response(top_vuln_analysis))

        # Network Topology View
        st.header("Network Topology Analysis", anchor="network-topology-analysis")
        G = nx.Graph()
        for _, row in filtered_vulnerabilities.iterrows():
            G.add_edge(row[host_column], row['template_name'])
        pos = nx.spring_layout(G)
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color=color_palette[4]), hoverinfo='none', mode='lines')
        node_x = [pos[node][0] for node in G.nodes()]
        node_y = [pos[node][1] for node in G.nodes()]
        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers', hoverinfo='text',
                                marker=dict(showscale=True, colorscale='Viridis', size=10, 
                                            color=[], colorbar=dict(thickness=15, title='Node Connections'),
                                            line_width=2))
        node_adjacencies = []
        node_text = []
        for node, adjacencies in enumerate(G.adjacency()):
            node_adjacencies.append(len(adjacencies[1]))
            node_text.append(f'{adjacencies[0]} - # of connections: {len(adjacencies[1])}')
        node_trace.marker.color = node_adjacencies
        node_trace.text = node_text
        fig_network = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(showlegend=False, hovermode='closest',
                                         title="Network Topology Visualization"))
        fig_network = apply_custom_style(fig_network)
        st.plotly_chart(fig_network, use_container_width=True, config={'displayModeBar': False})
        st.subheader("Orizon Engine Analysis")
        centrality = nx.degree_centrality(G)
        top_central = sorted(centrality, key=centrality.get, reverse=True)[:5]
        density = nx.density(G)
        communities = list(nx.community.greedy_modularity_communities(G))
        with st.spinner("Analyzing network topology..."):
            network_analysis = generate_network_analysis(tokenizer, model, top_central, density, communities)
        st.markdown(format_analysis_response(network_analysis))

        # Additional Cybersecurity Insights
        st.header("Additional Cybersecurity Insights", anchor="additional-cybersecurity-insights")
        
        # CVSS Score Distribution (if available)
        if 'cvss_score' in filtered_vulnerabilities.columns:
            st.subheader("CVSS Score Distribution")
            fig_cvss = px.histogram(
                filtered_vulnerabilities, 
                x='cvss_score', 
                nbins=20, 
                title="Distribution of CVSS Scores",
                labels={'cvss_score': 'CVSS Score', 'count': 'Number of Vulnerabilities'},
                color_discrete_sequence=[color_palette[0]]
            )
            fig_cvss.update_layout(bargap=0.1)
            fig_cvss = apply_custom_style(fig_cvss)
            st.plotly_chart(fig_cvss, use_container_width=True, config={'displayModeBar': False})
            
            avg_cvss = filtered_vulnerabilities['cvss_score'].mean()
            high_cvss = filtered_vulnerabilities[filtered_vulnerabilities['cvss_score'] > 7]
            with st.spinner("Analyzing CVSS distribution..."):
                cvss_analysis = analyze_cvss_distribution(tokenizer, model, avg_cvss, len(high_cvss), total_vulns)
            st.markdown(format_analysis_response(cvss_analysis))

        # Vulnerability Age Analysis
        if created_at_column:
            st.subheader("Vulnerability Age Analysis")
            filtered_vulnerabilities['age'] = (datetime.now(pytz.utc) - filtered_vulnerabilities[created_at_column]).dt.days
            fig_age = px.box(
                filtered_vulnerabilities, 
                y='age', 
                title="Distribution of Vulnerability Age",
                labels={'age': 'Age (days)'},
                color_discrete_sequence=[color_palette[0]]
            )
            fig_age = apply_custom_style(fig_age)
            st.plotly_chart(fig_age, use_container_width=True, config={'displayModeBar': False})
            
            avg_age = filtered_vulnerabilities['age'].mean()
            old_vulnerabilities = filtered_vulnerabilities[filtered_vulnerabilities['age'] > 90]
            with st.spinner("Analyzing vulnerability age..."):
                age_analysis = analyze_vulnerability_age(tokenizer, model, avg_age, len(old_vulnerabilities), total_vulns)
            st.markdown(format_analysis_response(age_analysis))

        # Vulnerability Types Analysis
        st.subheader("Top Vulnerability Types")
        vuln_types = filtered_vulnerabilities['template_name'].value_counts().head(10)
        fig_types = px.bar(
            x=vuln_types.index, 
            y=vuln_types.values, 
            title="Top 10 Vulnerability Types",
            labels={'x': 'Vulnerability Type', 'y': 'Count'},
            color_discrete_sequence=[color_palette[0]]
        )
        fig_types = apply_custom_style(fig_types)
        st.plotly_chart(fig_types, use_container_width=True, config={'displayModeBar': False})
        
        with st.spinner("Analyzing vulnerability types..."):
            types_analysis = analyze_vulnerability_types(tokenizer, model, vuln_types.index[0], vuln_types.values[0], vuln_types.index.tolist())
        st.markdown(format_analysis_response(types_analysis))

        # Remediation Priority Matrix
        st.header("Remediation Priority Matrix")
        if all(col in filtered_vulnerabilities.columns for col in [severity_column, 'cvss_score', 'exploit_available']):
            fig_remediation = create_severity_impact_bubble(filtered_vulnerabilities, severity_column, 'cvss_score', host_column)
            if fig_remediation:
                st.plotly_chart(fig_remediation, use_container_width=True, config={'displayModeBar': False})
            
            high_priority = filtered_vulnerabilities[(filtered_vulnerabilities['cvss_score'] > 7) & (filtered_vulnerabilities['exploit_available'] == True)]
            with st.spinner("Analyzing remediation priorities..."):
                remediation_analysis = analyze_remediation_priority(tokenizer, model, len(high_priority), total_vulns)
            st.markdown(format_analysis_response(remediation_analysis))
        else:
            st.info("Not enough information available for remediation priority analysis.")

        # Trend Forecasting
        st.header("Vulnerability Trend Forecasting")
        if created_at_column:
            vulnerabilities_per_day = filtered_vulnerabilities.groupby(created_at_column).size().reset_index(name='count')
            vulnerabilities_per_day = vulnerabilities_per_day.set_index(created_at_column)

            # Simple moving average for forecasting
            window_size = 7  # 7-day moving average
            vulnerabilities_per_day['SMA'] = vulnerabilities_per_day['count'].rolling(window=window_size).mean()

            # Forecast next 30 days
            last_date = vulnerabilities_per_day.index[-1]
            forecast_dates = pd.date_range(start=last_date + pd.Timedelta(days=1), periods=30)
            forecast_values = [vulnerabilities_per_day['SMA'].iloc[-1]] * 30

            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(x=vulnerabilities_per_day.index, y=vulnerabilities_per_day['count'], mode='lines', name='Actual', line=dict(color=color_palette[0])))
            fig_trend.add_trace(go.Scatter(x=vulnerabilities_per_day.index, y=vulnerabilities_per_day['SMA'], mode='lines', name='7-day Moving Average', line=dict(color=color_palette[2])))
            fig_trend.add_trace(go.Scatter(x=forecast_dates, y=forecast_values, mode='lines', name='Forecast', line=dict(color=color_palette[3], dash='dash')))
            fig_trend.update_layout(title='Vulnerability Trend and 30-day Forecast', xaxis_title='Date', yaxis_title='Number of Vulnerabilities')
            fig_trend = apply_custom_style(fig_trend)
            st.plotly_chart(fig_trend, use_container_width=True, config={'displayModeBar': False})

            current_avg = vulnerabilities_per_day['SMA'].iloc[-1]
            trend = 'Increasing' if vulnerabilities_per_day['SMA'].iloc[-1] > vulnerabilities_per_day['SMA'].iloc[-8] else 'Decreasing or Stable'
            with st.spinner("Analyzing vulnerability trend..."):
                trend_analysis = analyze_vulnerability_trend(tokenizer, model, current_avg, trend, vulnerabilities_per_day.to_dict())
            st.markdown(format_analysis_response(trend_analysis))

        # Export Options
        st.header("Export Dashboard")
        col1, col2 = st.columns(2)
        with col1:
            export_format = st.selectbox("Choose export format:", ["PDF", "Word", "CSV", "JSON"], key="export_format")
        with col2:
            if st.button("Generate Report", key="generate_report"):
                with st.spinner(f"Generating {export_format} report..."):
                    analyses = {
                        'overview': overview_analysis,
                        'severity': severity_analysis,
                        'timeline': trend_analysis,
                        'top_vulnerabilities': top_vuln_analysis,
                        'network': network_analysis,
                        'types': types_analysis,
                        'trend': trend_analysis
                    }
                    if 'cvss_score' in filtered_vulnerabilities.columns:
                        analyses['cvss'] = cvss_analysis
                    if created_at_column:
                        analyses['age'] = age_analysis
                    if 'remediation_analysis' in locals():
                        analyses['remediation'] = remediation_analysis
                    
                    figures = {
                        'risk_score': fig_risk_score,
                        'severity': fig_severity,
                        'timeline': fig_timeline,
                        'network': fig_network,
                        'types': fig_types,
                        'trend': fig_trend
                    }
                    if 'cvss_score' in filtered_vulnerabilities.columns:
                        figures['cvss'] = fig_cvss
                    if created_at_column:
                        figures['age'] = fig_age
                    if 'fig_remediation' in locals():
                        figures['remediation'] = fig_remediation
                    
                    if export_format == "PDF":
                        pdf_buffer = generate_pdf_report(filtered_vulnerabilities, analyses, figures)
                        st.download_button(
                            label="Download PDF Report",
                            data=pdf_buffer,
                            file_name="orizon_security_report.pdf",
                            mime="application/pdf",
                        )
                    elif export_format == "Word":
                        word_buffer = generate_word_report(filtered_vulnerabilities, analyses, figures)
                        st.download_button(
                            label="Download Word Report",
                            data=word_buffer,
                            file_name="orizon_security_report.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        )
                    elif export_format == "CSV":
                        csv = filtered_vulnerabilities.to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name="vulnerability_report.csv",
                            mime="text/csv",
                        )
                    elif export_format == "JSON":
                        json_str = filtered_vulnerabilities.to_json(orient="records")
                        st.download_button(
                            label="Download JSON",
                            data=json_str,
                            file_name="vulnerability_report.json",
                            mime="application/json",
                        )

        # Interactive Vulnerability Explorer
        st.header("Interactive Vulnerability Explorer")
        
        # Add search functionality
        search_term = st.text_input("Search vulnerabilities", "")
        
        # Select columns to display
        selected_columns = st.multiselect(
            "Select columns to display",
            options=filtered_vulnerabilities.columns,
            default=[host_column, severity_column, 'template_name', description_column],
            key="column_selector"
        )
        
        # Filter vulnerabilities based on search term
        if search_term:
            filtered_data = filtered_vulnerabilities[filtered_vulnerabilities.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)]
        else:
            filtered_data = filtered_vulnerabilities
        
        # Display filtered data
        st.dataframe(filtered_data[selected_columns], height=400, use_container_width=True)
        
        # Add pagination
        items_per_page = st.slider("Items per page", min_value=10, max_value=100, value=50, step=10)
        total_pages = len(filtered_data) // items_per_page + (1 if len(filtered_data) % items_per_page > 0 else 0)
        current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1)
        
        start_idx = (current_page - 1) * items_per_page
        end_idx = start_idx + items_per_page
        st.dataframe(filtered_data[selected_columns].iloc[start_idx:end_idx], height=400, use_container_width=True)
        
        st.write(f"Showing {start_idx+1} to {min(end_idx, len(filtered_data))} of {len(filtered_data)} entries")

    else:
        st.info("Please upload a JSON file in the sidebar to begin the analysis.")

if __name__ == "__main__":
    main()
