import os
import io
import zipfile
import json
import time
import subprocess
from collections import Counter
from datetime import datetime, timedelta
import pandas as pd
import pytz
import streamlit as st
import plotly.express as px
import plotly.io as pio
import networkx as nx
from io import BytesIO
from wordcloud import WordCloud
import torch
import cProfile

# Docx per la gestione di documenti Word
from docx import Document
from docx.shared import Inches

# Streamlit Authenticator per la gestione dell'autenticazione
from streamlit_authenticator import Authenticate
import yaml
from yaml.loader import SafeLoader

# my functions
from restart_utils import clear_pycache, restart_script
from GPU_utils import print_gpu_utilization, print_summary
from graph_utils import *  # all Michele utils

# Tentativo di importazione condizionale con gestione degli errori
try:
    from transformers import AutoTokenizer, pipeline
except ImportError:
    print("Errore durante l'importazione di 'AutoTokenizer'. Pulizia della cache e riavvio dello script...")
    clear_pycache()
    restart_script()

logo = Image.open("logo1.png")

# Definizione dei colori del branding kit
kelly_green = "#4AC300"
mariana_blue = "#002430"
burnt_red = "#E5625E"
dodger_blue = "#2191FB"
dawn_mist = "#DBE2E9"
simple_white = "#FFFFFF"

# Configurazione di Streamlit
st.set_page_config(page_title="Orizon Security", layout="wide", initial_sidebar_state="expanded")
with st.sidebar:
    st.image(logo)
st.config.set_option("theme.base", "light")
st.config.set_option("theme.primaryColor", kelly_green)
st.config.set_option("theme.backgroundColor", simple_white)
st.config.set_option("theme.secondaryBackgroundColor", dawn_mist)
st.config.set_option("theme.textColor", mariana_blue)
st.config.set_option("theme.font", 'sans serif')

# Configurazione dell'autenticazione Streamlit
with open('password.yaml') as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
    config['preauthorized']
)

# Configurazione di Plotly
template = pio.templates['ggplot2']
pio.templates.default = 'ggplot2'

template.layout.font.family = "Gill Sans, sans-serif"
template.layout.font.size = 12  # Ridotto da 300 a una dimensione più ragionevole
template.layout.font.color = mariana_blue
template.layout.title.font.size = 20
template.layout.xaxis.title.font.size = 16
template.layout.yaxis.title.font.size = 16
template.layout.paper_bgcolor = simple_white
template.layout.plot_bgcolor = dawn_mist  # Cambiato da rosso a un colore più neutro
template.layout.xaxis.gridcolor = simple_white
template.layout.xaxis.linecolor = mariana_blue
template.layout.xaxis.tickcolor = mariana_blue
template.layout.yaxis.gridcolor = simple_white
template.layout.yaxis.linecolor = mariana_blue
template.layout.yaxis.tickcolor = mariana_blue

# Definizione della palette di colori personalizzata
colors = [kelly_green, dodger_blue, burnt_red, mariana_blue]
template.layout.colorway = colors

pio.templates["Orizon_template"] = template
pio.templates.default = "Orizon_template"
_width = 800 
_height = 600

# Configurazione dell'ambiente CUDA
are_you_on_CUDA = False
run_LLM = True
if are_you_on_CUDA:
    os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'

# Selezione del modello LLM
model_id = "Qwen/Qwen2-1.5B-Instruct"
auth_token = "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"

# Pulizia della cache di Streamlit
clear = False
if clear:
    st.cache_resource.clear()

### Streamlit CSS dashboard setups ###
st.markdown("""
                <style>
                @import url('https://fonts.googleapis.com/css2?family=Gill+Sans&display=swap');

                body {
                    font-family: 'Gill Sans', sans-serif;
                    background-color: #FFFFFF;
                    color: #002430;
                }

                h1, h2, h3 {
                    color: #002430;
                    font-weight: 600;
                }

                .stAlert {
                    background-color: #DBE2E9;
                    color: #002430;
                    border: none;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }

                .stButton > button {
                    background-color: #2191FB;  /* Dodger Blue */
                    color: #FFFFFF;  /* Simple White */
                    border: none;
                    border-radius: 4px;
                    padding: 0.5rem 1rem;
                    font-weight: 600;
                }

                .stButton > button:hover {
                    background-color: #4AC300;  /* Kelly Green */
                    color: #FFFFFF;  /* Simple White */
                }

                .stProgress .st-bo {
                    background-color: #4AC300;
                }

                div[data-testid="stMetricValue"] {
                    font-size: 2rem;
                    font-weight: 600;
                    color: #002430;
                }

                div[data-testid="stMetricLabel"] {
                    font-size: 0.9rem;
                    font-weight: 400;
                    color: #002430;
                }

                .plot-container {
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                    background-color: #FFFFFF;
                    padding: 1rem;
                    margin-bottom: 1.5rem;
                }

                .stSelectbox, .stMultiSelect {
                    background-color: #FFFFFF;
                    color: #002430;
                    border-radius: 6px;
                    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
                }

                .sidebar .sidebar-content {
                    background-color: #FFFFFF;
                }

                .tooltip {
                    position: relative;
                    display: inline-block;
                    border-bottom: 1px dotted #002430;
                }

                .tooltip .tooltiptext {
                    visibility: hidden;
                    width: 200px;
                    background-color: #002430;
                    color: #FFFFFF;
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
                    background-color: #FFFFFF;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    padding: 1rem;
                    text-align: center;
                }

                .kpi-value {
                    font-size: 2rem;
                    font-weight: 600;
                    color: #4AC300;
                }

                .kpi-label {
                    font-size: 0.9rem;
                    color: #002430;
                }

                .section-nav {
                    position: sticky;
                    top: 0;
                    background-color: #FFFFFF;
                    z-index: 1000;
                    padding: 1rem 0;
                    margin-bottom: 1rem;
                    border-bottom: 1px solid #002430;
                }

                .section-nav a {
                    color: #002430;
                    text-decoration: none;
                    margin-right: 1rem;
                    padding: 0.5rem 1rem;
                    border-radius: 4px;
                    transition: background-color 0.2s ease;
                }

                .section-nav a:hover {
                    background-color: #2191FB;
                    color: #FFFFFF;
                }
                </style>
    """, unsafe_allow_html=True)

### Utility functions ###
@st.cache_resource
def load_LLM(model_id = model_id, auth_token = auth_token):

    if not torch.cuda.is_available():
        print("CUDA GPU not available!")
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

        return chat_pipeline
    
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

@st.cache_data
def calculate_risk_score(vulnerabilities, severity_column):
    # Dizionario che associa a ciascun livello di severità un peso specifico
    severity_weights = {'critical': 10, 'high': 8, 'medium': 6, 'low': 4, 'info': 2}
    
    # Calcolo del peso totale, sommando i pesi delle severità per ciascuna vulnerabilità
    # Se la severità non è riconosciuta, si assegna un peso di 0
    total_weight = sum(severity_weights.get(str(v).lower(), 0) for v in vulnerabilities[severity_column])
    
    # Calcolo del peso massimo possibile: numero di vulnerabilità * 10 (peso massimo di una singola vulnerabilità)
    max_weight = len(vulnerabilities) * 10
    
    # Calcolo del punteggio di rischio come percentuale del peso totale rispetto al peso massimo
    # Se max_weight è maggiore di 0, si calcola la percentuale; altrimenti, il punteggio è 0 (indica assenza di vulnerabilità o errore)
    return int((total_weight / max_weight) * 100) if max_weight > 0 else 0


@st.cache_data
def generate_orizon_analysis(prompt, _pipeline, max_new_tokens=256):

    try:
        messages = [{'role': 'system', 'content': 'You are a Cybersecurity expert, i need your help'},
            {'role': 'user', 'content': prompt}]
        response = _pipeline(messages, max_new_tokens=1000)[0]['generated_text']
        response_text = response[-1]['content'] 
        if are_you_on_CUDA:
            print_gpu_utilization()

        return response_text
    
    except Exception as e:
        st.error(f"Error generating analysis: {str(e)}")
        return "Analysis generation failed. Please try again."
    
### Prompt eng ### 

@st.cache_data
def analyze_overview(total, risk_score, critical, high, medium, low, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_severity_distribution(severity_counts, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_timeline(recent_vulnerabilities, recent_critical_high, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def generate_network_analysis(top_central, density, communities, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_cvss_distribution(avg_cvss, high_cvss_count, total_vulns, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_vulnerability_age(avg_age, old_vulnerabilities_count, total_vulns, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_vulnerability_types(most_common_type, frequency, top_10_types, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_remediation_priority(high_priority_count, total_vulns, _pipe):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_vulnerability_trend(current_avg, trend, historical_data, _pipe):
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
    
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def create_severity_impact_bubble(vulnerabilities, severity_column, cvss_column, host_column):
    if all(col in vulnerabilities.columns for col in [severity_column, cvss_column, host_column]):
        vulnerability_counts = vulnerabilities.groupby([severity_column, host_column]).size().reset_index(name='count')
        avg_cvss = vulnerabilities.groupby([severity_column, host_column])[cvss_column].mean().reset_index(name='avg_cvss')
        bubble_data = pd.merge(vulnerability_counts, avg_cvss, on=[severity_column, host_column])
        
        fig = px.scatter(bubble_data, 
                         width=_width,
                         height=_height,
                         x='count', 
                         y='avg_cvss', 
                         size='count', 
                         color=severity_column,
                         hover_name=host_column,
                         labels={'count': 'Number of Vulnerabilities', 'avg_cvss': 'Average CVSS Score'},
                         title="Severity, Impact, and Prevalence Correlation")
        return fig
    else:
        return None

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
    
    st.sidebar.title("Orizon Security Dashboard")

    if st.sidebar.button("Restart App"):
        subprocess.run(['python', 'run_streamlit_port8501.py'])
        print('Dashboard is now restarted!')
    
    uploaded_file = st.sidebar.file_uploader("Upload Vulnerability JSON", type="json", key="vuln_upload")
    
    if uploaded_file:
        with st.spinner("Processing vulnerability data..."):
            vulnerabilities = load_data(uploaded_file)
        if vulnerabilities is not None and not vulnerabilities.empty:
            st.sidebar.success("JSON file loaded successfully!")
            
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
        st.markdown("Welcome to our private Security Dashboard, here you can see the analysis of the JSON file.")

        pipe = None
        # Load model
        if run_LLM:
            pipe = load_LLM()

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

        # Security Posture Overview
        st.header("Security Posture Overview", anchor="security-posture-overview")
        col1, col2 = st.columns([3, 2])
        with col1:

            if risk_score > 40 and risk_score < 60:
                gauge_color = dodger_blue
            elif risk_score > 60:
                gauge_color = burnt_red
            else:
                gauge_color = kelly_green
            
            fig_risk_score = go.Figure(
                go.Indicator(
                mode = "gauge+number",
                value = risk_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Score", 'font': {'size': 20}},
                gauge = {
                    'bar': {'color': gauge_color},
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': mariana_blue}}),
                 layout=go.Layout(width=_width, height=_height, font={'color': mariana_blue}))
            
            st.plotly_chart(fig_risk_score, use_container_width=True, config={'displayModeBar': False})
        
        with col2:
            st.subheader("Orizon Engine Analysis")
            overview_analysis = ''
            with st.spinner("Generating overview analysis..."):
                overview_analysis = ''
                if run_LLM:
                    overview_analysis = analyze_overview(total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns, _pipe = pipe)
            st.markdown(overview_analysis)

        # Severity Distribution
        st.header("Vulnerability Severity Distribution", anchor="vulnerability-severity-distribution")
        col1, col2 = st.columns([2, 1])
        with col1:
            severity_counts = filtered_vulnerabilities[severity_column].value_counts()
            fig_severity = px.pie(
                                    values=severity_counts.values, 
                                   names=severity_counts.index, 
                                   color=severity_counts.index,
                                    title="Vulnerability Severity Distribution",
                                    width=_width, height=_height
                                )
            fig_severity.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_severity, use_container_width=True, config={'displayModeBar': False})

        with col2:
            st.subheader("Orizon Engine Analysis")
            severity_analysis = ''
            with st.spinner("Generating severity analysis..."):
                severity_analysis = ''
                if run_LLM:
                    severity_analysis = analyze_severity_distribution(severity_counts, _pipe= pipe)
            st.markdown(severity_analysis)


        # Vulnerability Timeline
        st.header("Geolocation of company servers", anchor="Geolocation of company servers")
        ### dopo aver visualizzato l'header di streamlit lo script si blocca e sembra come se fosse dentro un loop che dura molto tempo
        
        col1, col2 = st.columns([2, 1])
        with col1:
            # Michele

            # profiler
            profiler = cProfile.Profile()
            profiler.enable()

            file_contents = uploaded_file.read()
            df = load_data_geo(file_contents)

            # Define severity weights
            severity_weights = {
                'unknown': 1,
                'info': 2,
                'low': 4,
                'medium': 6,
                'high':8,
                'critical': 10
            }

            # Apply weights to severity column
            df['severity_weight'] = df['severity'].map(severity_weights)

            # Calculate the danger score by summing the severity weights per server (host)
            danger_score_per_server = df.groupby('host')['severity_weight'].sum().reset_index()

            # Add the IP addresses to the danger_score_per_server dataframe
            danger_score_per_server['ip'] = danger_score_per_server['host'].apply(resolve_hostname)

            progress_bar = st.progress(0)
            status_text = st.empty()
            summary = st.empty()

            # Geolocate IPs to get location information (country, city)
            ip_list = danger_score_per_server['ip'].to_list()
            geo_results = []

            for index, ip in enumerate(ip_list):
                progress = (index + 1) / len(ip_list)
                progress_bar.progress(progress)
                status_text.text(f'Numbers of scanned hosts: {index + 1}/{len(ip_list)}')
                d = geolocate_ip(ip, 'f2cfc8c5c8c358')
                geo_results.append(d)
            
            geolocation_data = pd.DataFrame(geo_results)
            #geolocation_data = danger_score_per_server['ip'].apply(lambda ip: pd.Series(geolocate_ip(ip, 'f2cfc8c5c8c358')))
            geolocation_data.columns = ['latitude', 'longitude', 'country', 'city']
            danger_score_per_server = pd.concat([danger_score_per_server, geolocation_data], axis=1)

            # Aggregate risk scores by IP using the danger_score_per_server data
            risk_by_ip = danger_score_per_server.groupby(['ip', 'country', 'city', 'latitude', 'longitude'])['severity_weight'].sum().reset_index()

            # Normalize risk scores to be between 0 and 100
            min_score = risk_by_ip['severity_weight'].min()
            max_score = risk_by_ip['severity_weight'].max()

            risk_by_ip['normalized_risk_score'] = ((risk_by_ip['severity_weight'] - min_score) / (max_score - min_score)) * 100

            # Create and display the Plotly map
            geo_map = create_plotly_map(risk_by_ip)
            st.plotly_chart(geo_map, use_container_width=True, config={'displayModeBar': False})

            # Display the data in the table
            st.subheader("Risk Scores by IP")

            # Select columns to display, including location information
            selected_columns = ['ip', 'country', 'city', 'severity_weight', 'normalized_risk_score']

            # Pagination
            items_per_page = st.slider("Items per page", min_value=10, max_value=100, value=20, step=10)
            total_pages = len(risk_by_ip) // items_per_page + (1 if len(risk_by_ip) % items_per_page > 0 else 0)
            current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1)

            start_idx = (current_page - 1) * items_per_page
            end_idx = start_idx + items_per_page

            # Display the selected page of the table
            st.dataframe(risk_by_ip[selected_columns].iloc[start_idx:end_idx], height=400, use_container_width=True)

            # Show the pagination information
            st.write(f"Showing {start_idx+1} to {min(end_idx, len(risk_by_ip))} of {len(risk_by_ip)} entries")

            profiler.disable()
            profiler.print_stats(sort='cumulative')
        


        # Top 10 Vulnerabilities
        st.header("Top 10 Critical Vulnerabilities", anchor="top-10-critical-vulnerabilities")
        top_10 = filtered_vulnerabilities.sort_values(severity_column, ascending=False).head(10)
        fig_top_10 = go.Figure(data=[go.Table(
            header=dict(values=['Host', 'Severity', 'Vulnerability', 'Description'],
                        align='left',
                        font=dict(color='white', size=12)),
            cells=dict(values=[top_10[host_column], top_10[severity_column], top_10['template_name'], top_10[description_column]],
                       fill_color='rgba(0,0,0,0)',
                       align='left'))
        ])
        st.plotly_chart(fig_top_10, use_container_width=True, config={'displayModeBar': False})
        st.subheader("Orizon Engine Analysis")
        common_types = top_10['template_name'].value_counts()
        most_common_type = common_types.index[0]
        hosts_affected = top_10[host_column].nunique()
        most_affected_host = top_10[host_column].value_counts().index[0]
        top_vuln_analysis = ''
        with st.spinner("Analyzing top vulnerabilities..."):
            top_vuln_analysis = ''
            if run_LLM:
                top_vuln_analysis = analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host, _pipe = pipe)
        st.markdown(top_vuln_analysis)

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
        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5), hoverinfo='none', mode='lines')
        node_x = [pos[node][0] for node in G.nodes()]
        node_y = [pos[node][1] for node in G.nodes()]
        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers', hoverinfo='text',
                                marker=dict(showscale=True, size=10, 
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
                                         title="Network Topology Visualization", width=_width, height=_height))
        st.plotly_chart(fig_network, use_container_width=True, config={'displayModeBar': False})
        st.subheader("Orizon Engine Analysis")
        centrality = nx.degree_centrality(G)
        top_central = sorted(centrality, key=centrality.get, reverse=True)[:5]
        density = nx.density(G)
        communities = list(nx.community.greedy_modularity_communities(G))
        with st.spinner("Analyzing network topology..."):
            if run_LLM:
                network_analysis = generate_network_analysis(top_central, density, communities, _pipe=pipe)
                st.markdown(network_analysis)

        # Additional Cybersecurity Insights
        st.header("Additional Cybersecurity Insights", anchor="additional-cybersecurity-insights")
        
        # CVSS Score Distribution (if available)
        if 'cvss_score' in filtered_vulnerabilities.columns:
            st.subheader("CVSS Score Distribution")
            fig_cvss = px.histogram(
                filtered_vulnerabilities,
                width=_width,
                height=_height, 
                x='cvss_score', 
                nbins=20, 
                title="Distribution of CVSS Scores",
                labels={'cvss_score': 'CVSS Score', 'count': 'Number of Vulnerabilities'}
            )
            fig_cvss.update_layout(bargap=0.1)
            st.plotly_chart(fig_cvss, use_container_width=True, config={'displayModeBar': False})
            
            avg_cvss = filtered_vulnerabilities['cvss_score'].mean()
            high_cvss = filtered_vulnerabilities[filtered_vulnerabilities['cvss_score'] > 7]
            cvss_analysis = ''
            with st.spinner("Analyzing CVSS distribution..."):
                cvss_analysis = ''
                if run_LLM:
                    cvss_analysis = analyze_cvss_distribution(avg_cvss, len(high_cvss), total_vulns, _pipe = pipe)
            st.markdown(cvss_analysis)

        if created_at_column:
            # Michele
            st.subheader("Screenshots")
            st.write("We are taking screenshots...")

            scelta = 'No'
            if st.button('Click here to interrupt the process'):
                scelta = 'Yes'

            if scelta == 'No':

                screenshots = []
                errors = []
                progress_bar = st.progress(0)
                status_text = st.empty()
                summary = st.empty()

                df = load_data_screen(file_contents)

                # Filter the dataframe
                filtered_df = df[~df['severity'].isin(['info'])]

                # Get unique hosts
                unique_hosts = filtered_df['host'].unique()

                # setup Selenium WebDriver
                driver = setup_driver()
                max_width, max_height = 1920, 1080

                # Iterate over each unique host and take a screenshot
                for index, host in enumerate(unique_hosts):
                    
                    progress = (index + 1) / len(unique_hosts)
                    progress_bar.progress(progress)
                    status_text.text(f'Numbers of scanned sites: {index + 1}/{len(unique_hosts)}')

                    host, image, error_type = take_screenshot(driver, host, max_width, max_height)
                    if host and image:
                        screenshots.append((host, image))
                    else:
                        errors.append((host, error_type))
                    
                    summary.text(f"Validated Screenshots: {len(screenshots)}, Errors: {len(errors)}")
                
                # Mostra riepilogo degli errori
                if errors:
                    st.subheader("Errors recap")
                    for host, error_type in errors:
                        st.error(f'Error for \"{host}\": {error_type}')

                driver.quit()
                st.success("Process successfully completed")

                # esistono delle screenshot
                if screenshots:
                    st.subheader("Screenshot gallery")
                    cols = st.columns(3)
                    for i, (host, image) in enumerate(screenshots):
                        with cols[i % 3]:
                            st.image(image, caption=host, use_column_width=True)

                    # Creiamo un file zip in memoria
                    zip_buffer = io.BytesIO()
                    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                        for host, image in screenshots:
                            # Convertiamo l'immagine in PNG
                            img_byte_arr = io.BytesIO()
                            image.save(img_byte_arr, format='PNG')
                            img_byte_arr = img_byte_arr.getvalue()
                            
                            # Aggiungiamo l'immagine al file zip
                            zip_file.writestr(f"image_{host}.png", img_byte_arr)

                    # Resettiamo il puntatore del buffer
                    zip_buffer.seek(0)

                    # Utilizziamo st.download_button per creare un pulsante di download
                    st.download_button(
                        label="Download images",
                        data=zip_buffer,
                        file_name="screenshots.zip",
                        mime="application/zip"
                    )


                # Display the screenshots using Streamlit's st.image
                #for host, image in screenshots:
                #    st.image(image, caption=f'Screenshot of {host}', use_column_width=True)

        # Vulnerability Types Analysis
        st.subheader("Top Vulnerability Types")
        vuln_types = filtered_vulnerabilities['template_name'].value_counts().head(10)
        fig_types = px.bar(
            width=_width,
            height=_height,
            x=vuln_types.index, 
            y=vuln_types.values, 
            title="Top 10 Vulnerability Types",
            labels={'x': 'Vulnerability Type', 'y': 'Count'}
        )
        st.plotly_chart(fig_types, use_container_width=True, config={'displayModeBar': False})
        
        types_analysis = ''
        with st.spinner("Analyzing vulnerability types..."):
            types_analysis = ''
            if run_LLM:
                types_analysis = analyze_vulnerability_types(vuln_types.index[0], vuln_types.values[0], vuln_types.index.tolist(), _pipe = pipe)
        st.markdown(types_analysis)

        # Remediation Priority Matrix
        st.header("Remediation Priority Matrix")
        if all(col in filtered_vulnerabilities.columns for col in [severity_column, 'cvss_score', 'exploit_available']):
            fig_remediation = create_severity_impact_bubble(filtered_vulnerabilities, severity_column, 'cvss_score', host_column)
            if fig_remediation:
                st.plotly_chart(fig_remediation, use_container_width=True, config={'displayModeBar': False})
            
            high_priority = filtered_vulnerabilities[(filtered_vulnerabilities['cvss_score'] > 7) & (filtered_vulnerabilities['exploit_available'] == True)]
            with st.spinner("Analyzing remediation priorities..."):
                remediation_analysis = ''
                if run_LLM:
                    remediation_analysis = analyze_remediation_priority(len(high_priority), total_vulns, _pipe = pipe)
            st.markdown(remediation_analysis)
        else:
            st.info("Not enough information available for remediation priority analysis.")

        st.header('WorldCloud analysis')
        df = load_data_word(file_contents)
        all_tags = df['template_name']
        tag_counts = Counter(all_tags)

        # Creazione di una colormap personalizzata
        from matplotlib.colors import LinearSegmentedColormap

        colors = [kelly_green, dodger_blue, burnt_red, mariana_blue]
        n_bins = len(colors)
        cmap_name = 'brand_colors'
        cm = LinearSegmentedColormap.from_list(cmap_name, colors, N=n_bins)

        # Creazione del WordCloud
        wordcloud_ = WordCloud(width=_width, height=_height, 
                            background_color='white', 
                            max_font_size=300, 
                            scale=3, 
                            relative_scaling=0.5, 
                            collocations=False, 
                            colormap=cm).generate_from_frequencies(tag_counts)

        img = wordcloud_.to_image()
        st.image(img, use_column_width=True)

        # Export Options
        st.header("Export Dashboard")
        col1, col2 = st.columns(2)
        with col1:
            export_format = st.selectbox("Choose export format:", ["Word", "CSV", "JSON"], key="export_format")
        with col2:
            if st.button("Generate Report", key="generate_report"):
                with st.spinner(f"Generating {export_format} report..."):
                    analyses = {
                        'overview': overview_analysis,
                        'severity': severity_analysis,
                        'top_vulnerabilities': top_vuln_analysis,
                        'types': types_analysis
                    }
                    if 'cvss_score' in filtered_vulnerabilities.columns:
                        analyses['cvss'] = cvss_analysis
                    if 'remediation_analysis' in locals():
                        analyses['remediation'] = remediation_analysis
                    
                    figures = {
                        'risk_score': fig_risk_score,
                        'severity': fig_severity,
                        'network': fig_network,
                        'types': fig_types
                    }
                    if 'cvss_score' in filtered_vulnerabilities.columns:
                        figures['cvss'] = fig_cvss
                    if 'fig_remediation' in locals():
                        figures['remediation'] = fig_remediation
                    
                    if export_format == "Word":
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

    # login
    name, authentication_status, username = authenticator.login(key='Login', location='main')

    if authentication_status == False:
        st.error('Username/password is incorrect')
    elif authentication_status == None:
        st.warning('Please enter your username and password')
    elif authentication_status:
        # true login
        authenticator.logout('Logout', 'main')
        st.write(f'Welcome *{name}*')
        start = time.time()
        main()
        end = time.time()

        # Calcolo del tempo impiegato
        elapsed_time = end - start

        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)

        print(f"Running time: {minutes:.2f}:{seconds:.2f}")