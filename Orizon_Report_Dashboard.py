import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import networkx as nx
import time
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
from transformers import AutoTokenizer, pipeline
import torch
import os
from GPU_utils import print_gpu_utilization, print_summary

# Set PYTORCH_CUDA_ALLOC_CONF environment variable
os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'

# Do you want to clear cached model?
clear = False
if clear:
    st.cache_resource.clear()

# select here LLM setups
model_id = "Qwen/Qwen2-1.5B-Instruct"
auth_token = "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"
_pipeline = None

# Set page config
st.set_page_config(page_title="Orizon Security", layout="wide", page_icon="🛡️", initial_sidebar_state="expanded")



### Utility functions ###

@st.cache_resource
def load_llama_model(model_id = model_id, auth_token = auth_token):

    if not torch.cuda.is_available():
        print("CUDA GPU not available. Model will be loaded on CPU.")
    else:
        print("CUDA is available. Backend and pinned memory configurations are applied.")
        print_gpu_utilization()

    
    try:
        model_kwargs = {
                "torch_dtype": torch.bfloat16
        }
        _tokenizer = AutoTokenizer.from_pretrained(model_id, 
                                                   use_fast= True)
        chat_pipeline = pipeline("text-generation", 
                             model=model_id,
                             token=auth_token,
                             tokenizer=_tokenizer,
                             device_map="auto",
                             model_kwargs=model_kwargs)
        
        print(f'Pipeline loaded on {chat_pipeline.device}')

        # save the model in a global variable
        global _pipeline
        _pipeline = chat_pipeline
    
    except Exception as e:
        st.error(f"Error loading the model: {str(e)}")

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
def generate_orizon_analysis(prompt, max_new_tokens=256):

    try:
        messages = [{'role': 'system', 'content': 'You are a Cybersecurity expert, i need your help'},
            {'role': 'user', 'content': prompt}]
        response = _pipeline(messages, max_new_tokens=1000)[0]['generated_text']
        response_text = response[-1]['content'] 
        print_gpu_utilization()

        return response_text
    
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

def analyze_overview(total, risk_score, critical, high, medium, low):
    prompt = f"""Provide a detailed analysis of the following security overview:

- Total vulnerabilities: {total}
- Risk score: {risk_score}/100
- Critical vulnerabilities: {critical}
- High vulnerabilities: {high}
- Medium vulnerabilities: {medium}
- Low vulnerabilities: {low}

Your analysis should cover:

1. Executive Summary (2-3 sentences):
   - Brief overview of the security posture and overall risk level.

2. Key Findings (4-5 bullet points):
   - Highlight significant results, trends in vulnerability distribution, and any comparisons to industry standards.

3. Risk Assessment:
   - Interpret the risk score, detail vulnerability severity, and assess potential business impact.

4. Critical and High Vulnerabilities:
   - Analyze critical/high vulnerabilities, potential exploitation consequences, and remediation urgency.

5. Medium and Low Vulnerabilities:
   - Evaluate these vulnerabilities' impact and suggest a prioritization strategy.

6. Areas of Concern (3-4 points):
   - Identify key weak points, root causes, and any systemic issues.

7. Recommendations (5-6 points):
   - Provide actionable advice with short-term and long-term strategies and suggested timelines.

8. Next Steps (3-4 points):
   - Outline immediate actions, key stakeholders to involve, and metrics to track improvement.
"""
    return generate_orizon_analysis(prompt)

def analyze_severity_distribution(severity_counts):
    prompt = f"""Provide an analysis of the following vulnerability severity distribution:

{severity_counts.to_dict()}

Your analysis should cover:

1. Distribution Overview:
   - Summary of severity distribution
   - Most prevalent severity level

2. Detailed Breakdown:
   - Percentage of each severity level
   - High (critical + high) vs. low (medium + low) severity ratio
   - Industry comparison (if applicable)

3. Critical/High Severity:
   - Impact of critical and high vulnerabilities
   - Urgency of remediation

4. Medium/Low Severity:
   - Cumulative risk of medium and low vulnerabilities
   - Importance of addressing alongside high-priority items

5. Trend Analysis:
   - Patterns in severity distribution
   - Comparison to past data or industry trends

6. Risk Implications:
   - Overall risk from current distribution
   - Potential compliance/security impact

7. Remediation Strategy:
   - Approach to address vulnerabilities across all severities
   - Prioritization framework

8. Recommendations:
   - Advice to improve severity distribution
   - Strategies to reduce high/critical vulnerabilities
   - Ongoing management suggestions

9. KPIs:
   - Metrics for tracking severity distribution improvements
   - Targets and reassessment frequency

Provide actionable insights suitable for both technical and management audiences."""
    return generate_orizon_analysis(prompt)

def analyze_timeline(recent_vulnerabilities, recent_critical_high):
    prompt = f"""Provide an analysis of the following vulnerability discovery trend:

- New vulnerabilities in the last 30 days: {len(recent_vulnerabilities)}
- Critical/High severity: {recent_critical_high}

Your analysis should cover:

1. Trend Summary:
   - Overview of the discovery rate and critical/high proportion in the last 30 days.

2. Discovery Rate Analysis:
   - Average new vulnerabilities per day, with comparisons to previous periods and identification of anomalies.

3. Severity Breakdown:
   - Analysis of the {recent_critical_high} critical/high vulnerabilities and their percentage of total discoveries.

4. Impact Assessment:
   - How this trend affects security posture, potential consequences, and comparison to industry benchmarks.

5. Root Cause Analysis:
   - Factors behind the discovery trend, including recent changes in IT or security practices.

6. Resource Implications:
   - Organization’s capacity to address the discovery rate and impact on security resources.

7. Projections:
   - Estimated trends for the next 30-60 days with best-case and worst-case scenarios.

8. Risk Mitigation Strategies:
   - Approaches to manage new vulnerabilities and prioritize critical/high severity issues.

9. Recommendations:
   - Actions to improve discovery and remediation processes, enhance security posture, and balance proactive/reactive measures.

10. Continuous Monitoring:
    - Key metrics for ongoing analysis, frequency of assessments, and escalation thresholds.

Ensure the analysis is data-driven, actionable, and considers both tactical and strategic improvements."""
    return generate_orizon_analysis(prompt)

def analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host):
    prompt = f"""Provide an in-depth analysis of the system's top vulnerabilities:

- Most common vulnerability: '{most_common_type}' (Frequency: {common_types.iloc[0]})
- Affected hosts: {hosts_affected}
- Most vulnerable host: {most_affected_host}

Your analysis should cover:

1. Top Vulnerabilities Overview:
   - Summary of prevalent types and potential impact.

2. Most Common Vulnerability:
   - Description of '{most_common_type}', causes, attack vectors, and potential consequences.
   - Industry context: commonality in similar systems.

3. Spread Assessment:
   - Analysis of affected hosts ({hosts_affected}), percentage of network affected, and risk of lateral movement.

4. Most Vulnerable Host:
   - Examination of why {most_affected_host} is most affected, associated risks, and immediate mitigation recommendations.

5. Patterns and Trends:
   - Identification of common themes, correlations, and systemic issues.

6. Risk Assessment:
   - Evaluation of overall risk, potential business impact, and compliance implications.

7. Mitigation Strategies:
   - Prioritized remediation actions, short-term fixes, long-term measures, and system hardening recommendations.

8. Resource Allocation:
   - Effort estimation, prioritization, and tools/processes for vulnerability management.

9. Monitoring and Follow-up:
   - Key metrics, reassessment timeframes, and ongoing management suggestions.

10. Learning Opportunities:
    - Insights, staff training recommendations, and improvements to detection and analysis processes.

Ensure the analysis is thorough, actionable, and considers both immediate and long-term security enhancements."""
    return generate_orizon_analysis(prompt)

def generate_network_analysis(top_central, density, communities):
    prompt = f"""Analyze the following network topology:

- Central nodes: {len(top_central)}
- Network density: {density:.4f}
- Identified communities: {len(communities)}

Provide an analysis including:

1. Topology Overview:
   - Summary of network structure and complexity.

2. Central Nodes:
   - Role and security implications of {len(top_central)} central nodes.
   - Protection and monitoring recommendations.

3. Network Density:
   - Interpretation of density {density:.4f} and its impact on threat propagation and resilience.
   - Comparison to ideal security and performance ranges.

4. Community Structure:
   - Significance of {len(communities)} communities.
   - Security implications and inter-community measures.

5. Topological Vulnerabilities:
   - Identification of weak points, potential attack vectors, and lateral movement risk.

6. Resilience and Redundancy:
   - Assessment of network resilience, redundancy, and recommendations for improvement.

7. Segmentation:
   - Evaluation of current segmentation and optimization suggestions.
   - Potential for zero trust architecture implementation.

8. Traffic Flow:
   - Impact of topology on traffic patterns, bottlenecks, and monitoring recommendations.

9. Scalability:
   - Network's scalability and security challenges with growth.
   - Scalable security architecture recommendations.

10. Improvement Recommendations:
    - Prioritized actions to enhance security and redesign problematic areas.

11. Monitoring and Maintenance:
    - Key metrics, reassessment frequency, and automated tools for continuous analysis.

12. Compliance:
    - Evaluation against industry standards, compliance issues, and alignment recommendations.

Ensure actionable insights and consider both immediate and long-term improvements to network security."""
    return generate_orizon_analysis(prompt)

def analyze_cvss_distribution(avg_cvss, high_cvss_count, total_vulns):
    prompt = f"""Analyze the following CVSS score distribution:

- Average CVSS score: {avg_cvss:.2f}
- High-risk vulnerabilities (CVSS > 7.0): {high_cvss_count}
- Total vulnerabilities: {total_vulns}

Your analysis should include:

1. Overview:
   - Summary of the CVSS score distribution and initial severity assessment.

2. Average Score:
   - Interpretation of {avg_cvss:.2f} average score, industry comparison, and security implications.

3. High-Risk Vulnerabilities:
   - Analysis of {high_cvss_count} high-risk vulnerabilities, their percentage, and urgency.

4. Score Breakdown:
   - Distribution across ranges, pattern identification, and analysis of extremes.

5. Temporal/Environmental Factors:
   - Impact of these metrics on base CVSS scores and risk assessment recommendations.

6. Security Posture Impact:
   - Organizational risk assessment, consequences of the current distribution, and industry comparison.

7. Remediation Prioritization:
   - Strategies for addressing vulnerabilities based on CVSS scores and continuous management.

8. Resource Allocation:
   - Allocation of security resources and effort estimation by severity levels.

9. Recommendations:
   - Actions to improve score distribution, reduce high-risk vulnerabilities, and enhance scoring processes.

10. Compliance and Reporting:
    - Implications for regulatory compliance and reporting to stakeholders.

11. Trend Analysis:
    - Historical trends (if available) and predictions for future distributions.

12. Key Performance Indicators:
    - Metrics for tracking improvements, suggested targets, and reassessment frequency.

Ensure the analysis is thorough, actionable, and considers both tactical and strategic improvements based on CVSS scores."""
    return generate_orizon_analysis(prompt)

def analyze_vulnerability_age(avg_age, old_vulnerabilities_count, total_vulns):
    prompt = f"""Analyze the following vulnerability age distribution:

- Average age: {avg_age:.1f} days
- Vulnerabilities older than 90 days: {old_vulnerabilities_count}
- Total vulnerabilities: {total_vulns}

Your analysis should include:

1. Overview:
   - Summary of the age distribution and initial assessment of management efficiency.

2. Average Age:
   - Interpretation of {avg_age:.1f} days, industry comparison, and security implications.

3. Persistent Vulnerabilities:
   - Analysis of {old_vulnerabilities_count} vulnerabilities older than 90 days, their percentage, and persistence reasons.

4. Age Breakdown:
   - Distribution across age ranges, pattern identification, and analysis of extremes.

5. Risk Accumulation:
   - Assessment of cumulative risk due to vulnerability age and potential consequences.

6. Remediation Velocity:
   - Analysis of remediation speed, severity level comparison, and process bottlenecks.

7. Security Posture Impact:
   - Evaluation of risk exposure, compliance implications, and threat potential due to persistence.

8. Remediation Strategy:
   - Approach for addressing vulnerabilities by age and severity, and reducing average age.

9. Resource Allocation:
   - Resource suggestions based on age distribution and effort estimation by age groups.

10. Recommendations:
    - Actions to improve lifecycle management, prevent aging, and enhance remediation processes.

11. Continuous Improvement:
    - Ongoing management strategies, prevention of new vulnerabilities, and team collaboration.

12. Key Performance Indicators:
    - Metrics for tracking age management, suggested benchmarks, and reassessment frequency.

13. Tools and Automation:
    - Tool recommendations, automation suggestions, and CI/CD integration (if applicable).

Ensure the analysis is thorough, actionable, and considers both tactical and strategic improvements to vulnerability lifecycle management."""
    return generate_orizon_analysis(prompt)

def analyze_vulnerability_types(most_common_type, frequency, top_10_types):
    prompt = f"""Analyze the following vulnerability type distribution:

- Most common type: '{most_common_type}' (Frequency: {frequency})
- Top 10 types: {', '.join(top_10_types)}

Your analysis should include:

1. Overview:
   - Summary of type distribution and initial security challenge assessment.

2. Most Common Type:
   - Description of '{most_common_type}', causes, attack vectors, impact, and industry prevalence.

3. Top 10 Types:
   - Brief description of each, distribution analysis, and pattern identification.

4. Root Cause Analysis:
   - Exploration of systemic issues and links to specific technologies or practices.

5. Risk Assessment:
   - Evaluation of overall risk from the type distribution and interaction effects.

6. Industry Comparison:
   - Comparison to industry benchmarks and identification of unique patterns.

7. Remediation Strategies:
   - Approaches for addressing top types, prioritization framework, and prevention tools.

8. Security Posture:
   - Suggestions for improving security controls and mitigating multiple types.

9. Training and Awareness:
   - Proposals for staff training and developer education based on prevalent types.

10. Trend Analysis:
    - Analysis of type evolution over time and predictions for future landscapes.

11. Recommendations:
    - Actions to address critical types, reduce common vulnerabilities, and improve detection.

12. Continuous Monitoring:
    - Metrics for ongoing analysis, assessment frequency, and escalation thresholds.

13. Tool and Process Evaluation:
    - Assessment of current tools and recommendations for improvements.

Ensure the analysis is comprehensive, actionable, and considers both immediate responses and long-term improvements."""
    return generate_orizon_analysis(prompt)

def analyze_remediation_priority(high_priority_count, total_vulns):
    prompt = f"""Analyze the current remediation priority situation:

- High-priority vulnerabilities: {high_priority_count}
- Total vulnerabilities: {total_vulns}

Your analysis should include:

1. Overview:
   - Summary of remediation situation and urgency assessment.

2. High-Priority Vulnerabilities:
   - Examination of {high_priority_count} high-priority issues, their percentage, impact, and overall risk.

3. Remediation Challenges:
   - Identification of obstacles, resource requirements, and business impact considerations.

4. Prioritization Strategy:
   - Framework for prioritization, criteria beyond severity, and balancing high and low-priority fixes.

5. Risk-Based Approach:
   - Recommendations for a risk-based strategy, risk quantification, and stakeholder involvement.

6. Remediation Timeline:
   - Proposed timeline, full remediation estimation, and phased approach suggestions.

7. Resource Allocation:
   - Recommendations for resource allocation, training, and potential need for external assistance.

8. Continuous Monitoring:
   - Strategies for monitoring progress, reassessment of priorities, and adjusting strategies.

9. Recommendations:
    - Actionable steps for high-priority issues, process improvement, and lifecycle enhancement.

10. Metrics and KPIs:
    - Key indicators, targets, and metrics to track remediation effectiveness.

11. Communication Plan:
    - Reporting strategies, maintaining transparency, and educating the organization.

12. Long-term Measures:
    - Recommendations for reducing new vulnerabilities, improving secure practices, and enhancing security posture.

13. Compliance Considerations:
    - Analysis of alignment with compliance requirements and satisfying regulatory obligations.

14. Incident Response Integration:
    - Suggestions for integrating remediation with incident response and rapid threat response.

Ensure the analysis is thorough, actionable, and balances urgent remediation with sustainable, long-term management."""
    return generate_orizon_analysis(prompt)

def analyze_vulnerability_trend(current_avg, trend, historical_data):
    prompt = f"""Analyze the following vulnerability trend:

- 7-day moving average of new vulnerabilities: {current_avg:.2f}
- Observed trend: {trend}
- Historical data: {historical_data}

Your analysis should include:

1. Overview:
   - Summary of the current trend and initial significance assessment.

2. 7-Day Moving Average:
   - Interpretation of {current_avg:.2f} new vulnerabilities, comparison with previous periods, and anomaly identification.

3. Trend Assessment:
   - In-depth analysis of the {trend} trend, quantification, and identification of patterns or seasonality.

4. Historical Context:
   - Comparison with historical data, identification of long-term patterns, and analysis of influencing factors.

Ensure the analysis is data-driven, actionable, and considers both short-term responses and long-term adjustments based on observed trends."""
    
    return generate_orizon_analysis(prompt)

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
        pipe = load_llama_model()

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
            st.markdown(format_analysis_response(analyze_overview(total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns)))

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
                overview_analysis = analyze_overview(total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns)
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
                severity_analysis = analyze_severity_distribution(severity_counts)
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
                trend_analysis = analyze_timeline(recent_vulnerabilities, recent_critical_high)
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
            top_vuln_analysis = analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host)
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
            network_analysis = generate_network_analysis(top_central, density, communities)
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
                cvss_analysis = analyze_cvss_distribution(avg_cvss, len(high_cvss), total_vulns)
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
                age_analysis = analyze_vulnerability_age(avg_age, len(old_vulnerabilities), total_vulns)
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
            types_analysis = analyze_vulnerability_types(vuln_types.index[0], vuln_types.values[0], vuln_types.index.tolist())
        st.markdown(format_analysis_response(types_analysis))

        # Remediation Priority Matrix
        st.header("Remediation Priority Matrix")
        if all(col in filtered_vulnerabilities.columns for col in [severity_column, 'cvss_score', 'exploit_available']):
            fig_remediation = create_severity_impact_bubble(filtered_vulnerabilities, severity_column, 'cvss_score', host_column)
            if fig_remediation:
                st.plotly_chart(fig_remediation, use_container_width=True, config={'displayModeBar': False})
            
            high_priority = filtered_vulnerabilities[(filtered_vulnerabilities['cvss_score'] > 7) & (filtered_vulnerabilities['exploit_available'] == True)]
            with st.spinner("Analyzing remediation priorities..."):
                remediation_analysis = analyze_remediation_priority(len(high_priority), total_vulns)
            st.markdown(format_analysis_response(remediation_analysis))
        else:
            st.info("Not enough information available for remediation priority analysis.")

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
                        'types': fig_types
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
    start = time.time()
    main()
    end = time.time()

    # Calcolo del tempo impiegato
    elapsed_time = end - start

    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)

    print(f"Running time: {minutes:.2f}:{seconds:.2f}")