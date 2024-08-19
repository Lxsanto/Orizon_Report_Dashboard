import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import networkx as nx
from datetime import datetime, timedelta
import pytz
from collections import Counter
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO

# Set page config
st.set_page_config(page_title="Orizon Security", layout="wide", page_icon="🛡️")

# Custom CSS for an ultra-modern UI
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    .stApp {
        background-color: #f8fafc;
    }
    
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    h1, h2, h3 {
        color: #1e293b;
        font-weight: 700;
    }
    
    .stAlert {
        background-color: #ffffff;
        border: none;
        border-radius: 10px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    
    .stButton>button {
        border-radius: 8px;
        background-color: #3b82f6;
        color: white;
        font-weight: 600;
        padding: 0.5rem 1rem;
        border: none;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        background-color: #2563eb;
        box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.5);
    }
    
    .stProgress .st-bo {
        background-color: #3b82f6;
    }
    
    div[data-testid="stMetricValue"] {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1e293b;
    }
    
    div[data-testid="stMetricLabel"] {
        font-size: 1rem;
        font-weight: 600;
        color: #64748b;
    }
    
    .plot-container {
        border-radius: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        background-color: white;
        padding: 1rem;
        margin-bottom: 1.5rem;
    }
    
    .stSelectbox, .stMultiSelect {
        background-color: white;
        border-radius: 8px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    }
    
    .sidebar .sidebar-content {
        background-color: #f1f5f9;
    }
    </style>
    """, unsafe_allow_html=True)

# Load Llama 3.1 model and tokenizer
@st.cache_resource
def load_llama_model():
    with st.spinner("Initializing Orizon Engine..."):
        try:
            model_id = "meta-llama/Meta-Llama-3.1-8B"
            auth_token = "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"  
            tokenizer = AutoTokenizer.from_pretrained(model_id, token=auth_token)
            model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16, device_map="auto", token=auth_token)
            return tokenizer, model
        except Exception as e:
            st.error(f"Failed to load Orizon Engine: {str(e)}")
            return None, None

# Utility functions
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
def generate_orizon_analysis(_tokenizer, _model, prompt, max_length=500):
    try:
        inputs = _tokenizer(prompt, return_tensors="pt").to(_model.device)
        outputs = _model.generate(**inputs, max_new_tokens=max_length, temperature=0.7)
        return _tokenizer.decode(outputs[0], skip_special_tokens=True)
    except Exception as e:
        st.error(f"Error generating analysis: {str(e)}")
        return "Analysis generation failed. Please try again."

# Analysis functions
def analyze_overview(_tokenizer, _model, total, risk_score, critical, high, medium, low):
    prompt = f"Provide a brief security analysis based on: {total} total vulnerabilities, risk score {risk_score}/100, {critical} critical, {high} high, {medium} medium, and {low} low severity vulnerabilities. Include key findings and recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_severity_distribution(_tokenizer, _model, severity_counts):
    prompt = f"Analyze this severity distribution: {severity_counts.to_dict()}. Provide key insights and basic recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_timeline(_tokenizer, _model, recent_vulnerabilities, recent_critical_high):
    prompt = f"Analyze the trend of {len(recent_vulnerabilities)} new vulnerabilities in the last 30 days, including {recent_critical_high} critical or high severity. Provide brief insights and basic recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_top_vulnerabilities(_tokenizer, _model, most_common_type, common_types, hosts_affected, most_affected_host):
    prompt = f"Analyze top vulnerabilities: Most common type '{most_common_type}' (Frequency: {common_types.iloc[0]}), affecting {hosts_affected} hosts. Most vulnerable host: {most_affected_host}. Provide key insights and basic recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def generate_network_analysis(_tokenizer, _model, top_central, density, communities):
    prompt = f"Analyze network with {len(top_central)} central nodes, density {density:.2f}, and {len(communities)} communities. Provide basic insights and recommendations for network security."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_cvss_distribution(_tokenizer, _model, avg_cvss, high_cvss_count):
    prompt = f"Analyze CVSS scores: Average {avg_cvss:.2f}, {high_cvss_count} high-risk vulnerabilities. Provide brief insights and basic recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_vulnerability_age(_tokenizer, _model, avg_age, old_vulnerabilities_count):
    prompt = f"Analyze vulnerability age: Average {avg_age:.1f} days, {old_vulnerabilities_count} older than 90 days. Provide brief insights and basic recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_vulnerability_types(_tokenizer, _model, most_common_type, frequency, top_10_types):
    prompt = f"Analyze vulnerability types: Most common is '{most_common_type}' (Frequency: {frequency}). Top 10 types: {', '.join(top_10_types)}. Provide brief insights and basic recommendations."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_remediation_priority(_tokenizer, _model, high_priority_count):
    prompt = f"Analyze remediation priorities: {high_priority_count} high-priority vulnerabilities. Provide brief insights and basic recommendations for addressing these vulnerabilities."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def analyze_vulnerability_trend(_tokenizer, _model, current_avg, trend):
    prompt = f"Analyze vulnerability trend: Current 7-day average is {current_avg:.2f}, trend is {trend}. Provide brief insights and basic recommendations based on this trend."
    return generate_orizon_analysis(_tokenizer, _model, prompt)

def generate_pdf_report(filtered_vulnerabilities, analyses, figures):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    # Modifica gli stili esistenti invece di aggiungerne di nuovi
    styles['Title'].fontSize = 24
    styles['Title'].spaceAfter = 12
    styles['Heading1'].fontSize = 18
    styles['Heading1'].spaceAfter = 6
    styles['BodyText'].fontSize = 12
    styles['BodyText'].spaceAfter = 6

    # Title
    elements.append(Paragraph("Orizon Security Dashboard Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # Overview
    elements.append(Paragraph("Security Posture Overview", styles['Heading1']))
    elements.append(Paragraph(analyses['overview'], styles['BodyText']))
    elements.append(Spacer(1, 12))

    # Add Risk Score Gauge
    img_buffer = BytesIO()
    figures['risk_score'].write_image(img_buffer, format="png")
    img = Image(img_buffer, width=6*inch, height=3*inch)
    elements.append(img)
    elements.append(Spacer(1, 12))

    # Severity Distribution
    elements.append(Paragraph("Vulnerability Severity Distribution", styles['Heading1']))
    elements.append(Paragraph(analyses['severity'], styles['BodyText']))
    img_buffer = BytesIO()
    figures['severity'].write_image(img_buffer, format="png")
    img = Image(img_buffer, width=6*inch, height=3*inch)
    elements.append(img)
    elements.append(Spacer(1, 12))

    # Timeline
    elements.append(Paragraph("Vulnerability Discovery Timeline", styles['Heading1']))
    elements.append(Paragraph(analyses['timeline'], styles['BodyText']))
    img_buffer = BytesIO()
    figures['timeline'].write_image(img_buffer, format="png")
    img = Image(img_buffer, width=6*inch, height=3*inch)
    elements.append(img)
    elements.append(Spacer(1, 12))

    # Top 10 Vulnerabilities
    elements.append(Paragraph("Top 10 Critical Vulnerabilities", styles['Heading1']))
    elements.append(Paragraph(analyses['top_vulnerabilities'], styles['BodyText']))
    
    # Network Topology
    elements.append(Paragraph("Network Topology Analysis", styles['Heading1']))
    elements.append(Paragraph(analyses['network'], styles['BodyText']))
    img_buffer = BytesIO()
    figures['network'].write_image(img_buffer, format="png")
    img = Image(img_buffer, width=6*inch, height=3*inch)
    elements.append(img)
    elements.append(Spacer(1, 12))

    # Additional Insights
    elements.append(Paragraph("Additional Cybersecurity Insights", styles['Heading1']))
    
    if 'cvss' in analyses:
        elements.append(Paragraph("CVSS Score Distribution", styles['Heading1']))
        elements.append(Paragraph(analyses['cvss'], styles['BodyText']))
        img_buffer = BytesIO()
        figures['cvss'].write_image(img_buffer, format="png")
        img = Image(img_buffer, width=6*inch, height=3*inch)
        elements.append(img)
        elements.append(Spacer(1, 12))

    if 'age' in analyses:
        elements.append(Paragraph("Vulnerability Age Analysis", styles['Heading1']))
        elements.append(Paragraph(analyses['age'], styles['BodyText']))
        img_buffer = BytesIO()
        figures['age'].write_image(img_buffer, format="png")
        img = Image(img_buffer, width=6*inch, height=3*inch)
        elements.append(img)
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("Top Vulnerability Types", styles['Heading1']))
    elements.append(Paragraph(analyses['types'], styles['BodyText']))
    img_buffer = BytesIO()
    figures['types'].write_image(img_buffer, format="png")
    img = Image(img_buffer, width=6*inch, height=3*inch)
    elements.append(img)
    elements.append(Spacer(1, 12))

    if 'remediation' in analyses:
        elements.append(Paragraph("Remediation Priority Matrix", styles['Heading1']))
        elements.append(Paragraph(analyses['remediation'], styles['BodyText']))
        img_buffer = BytesIO()
        figures['remediation'].write_image(img_buffer, format="png")
        img = Image(img_buffer, width=6*inch, height=3*inch)
        elements.append(img)
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("Vulnerability Trend Forecasting", styles['Heading1']))
    elements.append(Paragraph(analyses['trend'], styles['BodyText']))
    img_buffer = BytesIO()
    figures['trend'].write_image(img_buffer, format="png")
    img = Image(img_buffer, width=6*inch, height=3*inch)
    elements.append(img)
    elements.append(Spacer(1, 12))

    doc.build(elements)
    buffer.seek(0)
    return buffer

def main():
    st.title("Orizon Security Dashboard")
    st.markdown("Powered by advanced AI for comprehensive cybersecurity analysis")

    # Load model
    tokenizer, model = load_llama_model()
    if tokenizer is None or model is None:
        st.error("Failed to initialize Orizon Engine. Please refresh the page and try again.")
        return

    # Sidebar for file upload and global filters
    with st.sidebar:
        st.header("Dashboard Controls")
        uploaded_file = st.file_uploader("Upload Vulnerability JSON", type="json", key="vuln_upload")
        
        if uploaded_file:
            with st.spinner("Processing vulnerability data..."):
                vulnerabilities = load_data(uploaded_file)
            if vulnerabilities is not None and not vulnerabilities.empty:
                st.success("File processed successfully!")
                
                # Ensure 'created_at' is in datetime format
                if 'created_at' in vulnerabilities.columns:
                    vulnerabilities['created_at'] = pd.to_datetime(vulnerabilities['created_at'], errors='coerce')
                    
                    # Remove rows with invalid dates
                    vulnerabilities = vulnerabilities.dropna(subset=['created_at'])
                    
                    if not vulnerabilities.empty:
                        # Global filters
                        st.subheader("Global Filters")
                        min_date = vulnerabilities['created_at'].min().date()
                        max_date = vulnerabilities['created_at'].max().date()
                        date_range = st.date_input(
                            "Date Range",
                            value=(min_date, max_date),
                            min_value=min_date,
                            max_value=max_date,
                            key="date_filter"
                        )
                        severity_filter = st.multiselect(
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
                        
                        st.info(f"Showing {len(filtered_vulnerabilities)} out of {len(vulnerabilities)} vulnerabilities")
                    else:
                        st.error("No valid data after date conversion. Please check your data format.")
                        return
                else:
                    st.error("The 'created_at' column is missing from the data. Please check your JSON file.")
                    return
            else:
                st.error("Error loading data. Please check your JSON file.")
                return
    
    if uploaded_file and 'filtered_vulnerabilities' in locals() and not filtered_vulnerabilities.empty:

        # Automatic column detection
        severity_column = 'severity' if 'severity' in filtered_vulnerabilities.columns else None
        description_column = 'description' if 'description' in filtered_vulnerabilities.columns else None
        created_at_column = 'created_at' if 'created_at' in filtered_vulnerabilities.columns else None
        host_column = 'host' if 'host' in filtered_vulnerabilities.columns else None

        # Overview Section
        st.header("Security Posture Overview")
        col1, col2 = st.columns([3, 2])
        with col1:
            total_vulns = len(filtered_vulnerabilities)
            risk_score = calculate_risk_score(filtered_vulnerabilities, severity_column)
            critical_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'critical'])
            high_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'high'])
            medium_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'medium'])
            low_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'low'])
            
            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            with metric_col1:
                st.metric("Total Vulnerabilities", total_vulns)
            with metric_col2:
                st.metric("Risk Score", f"{risk_score}/100", delta=f"{100-risk_score} points to improve")
            with metric_col3:
                st.metric("Critical Vulnerabilities", critical_vulns, delta=-critical_vulns, delta_color="inverse")
            with metric_col4:
                st.metric("High Vulnerabilities", high_vulns, delta=-high_vulns, delta_color="inverse")
            
            fig_risk_score = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Score"},
                gauge = {
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#3b82f6"},
                    'steps' : [
                        {'range': [0, 50], 'color': "#ef4444"},
                        {'range': [50, 75], 'color': "#f59e0b"},
                        {'range': [75, 100], 'color': "#10b981"}],
                    'threshold': {
                        'line': {'color': "#ef4444", 'width': 4},
                        'thickness': 0.75,
                        'value': risk_score}}))
            fig_risk_score.update_layout(height=300)
            st.plotly_chart(fig_risk_score, use_container_width=True, config={'displayModeBar': False})
        
        with col2:
            st.subheader("Orizon Engine Analysis")
            with st.spinner("Generating overview analysis..."):
                overview_analysis = analyze_overview(tokenizer, model, total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns)
            st.markdown(overview_analysis)

        # Severity Distribution
        st.header("Vulnerability Severity Distribution")
        col1, col2 = st.columns([2, 1])
        with col1:
            severity_counts = filtered_vulnerabilities[severity_column].value_counts()
            fig_severity = px.pie(values=severity_counts.values, names=severity_counts.index, 
                         title="Vulnerability Severity Distribution",
                         color=severity_counts.index,
                         color_discrete_map={'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b', 'low': '#22c55e', 'info': '#3b82f6'})
            fig_severity.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_severity, use_container_width=True, config={'displayModeBar': False})
        with col2:
            st.subheader("Orizon Engine Analysis")
            with st.spinner("Generating severity analysis..."):
                severity_analysis = analyze_severity_distribution(tokenizer, model, severity_counts)
            st.markdown(severity_analysis)

        # Vulnerability Timeline
        st.header("Vulnerability Discovery Timeline")
        col1, col2 = st.columns([2, 1])
        with col1:
            timeline_data = filtered_vulnerabilities.groupby([created_at_column, severity_column]).size().unstack(fill_value=0)
            fig_timeline = px.area(timeline_data, x=timeline_data.index, y=timeline_data.columns, 
                          title="Vulnerability Discovery Over Time",
                          labels={'value': 'Number of Vulnerabilities', created_at_column: 'Date'},
                          color_discrete_map={'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b', 'low': '#22c55e', 'info': '#3b82f6'})
            fig_timeline.update_layout(legend_title_text='Severity')
            st.plotly_chart(fig_timeline, use_container_width=True, config={'displayModeBar': False})
        with col2:
            st.subheader("Orizon Engine Analysis")
            recent_vulnerabilities = filtered_vulnerabilities[filtered_vulnerabilities[created_at_column] > (datetime.now(pytz.utc) - timedelta(days=30))]
            recent_critical_high = len(recent_vulnerabilities[recent_vulnerabilities[severity_column].str.lower().isin(['critical', 'high'])])
            with st.spinner("Generating trend analysis..."):
                trend_analysis = analyze_timeline(tokenizer, model, recent_vulnerabilities, recent_critical_high)
            st.markdown(trend_analysis)

        # Top 10 Vulnerabilities
        st.header("Top 10 Critical Vulnerabilities")
        top_10 = filtered_vulnerabilities.sort_values(severity_column, ascending=False).head(10)
        fig_top_10 = go.Figure(data=[go.Table(
            header=dict(values=['Host', 'Severity', 'Vulnerability', 'Description'],
                        fill_color='#3b82f6',
                        align='left',
                        font=dict(color='white', size=12)),
            cells=dict(values=[top_10[host_column], top_10[severity_column], top_10['template_name'], top_10[description_column]],
                       fill_color='#f1f5f9',
                       align='left'))
        ])
        fig_top_10.update_layout(margin=dict(l=0, r=0, t=0, b=0))
        st.plotly_chart(fig_top_10, use_container_width=True, config={'displayModeBar': False})
        st.subheader("Orizon Engine Analysis")
        common_types = top_10['template_name'].value_counts()
        most_common_type = common_types.index[0]
        hosts_affected = top_10[host_column].nunique()
        most_affected_host = top_10[host_column].value_counts().index[0]
        with st.spinner("Analyzing top vulnerabilities..."):
            top_vuln_analysis = analyze_top_vulnerabilities(tokenizer, model, most_common_type, common_types, hosts_affected, most_affected_host)
        st.markdown(top_vuln_analysis)

        # Network Topology View
        st.header("Network Topology Analysis")
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
        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#94a3b8'), hoverinfo='none', mode='lines')
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
                                         margin=dict(b=20,l=5,r=5,t=40),
                                         title="Network Topology Visualization"))
        st.plotly_chart(fig_network, use_container_width=True, config={'displayModeBar': False})
        st.subheader("Orizon Engine Analysis")
        centrality = nx.degree_centrality(G)
        top_central = sorted(centrality, key=centrality.get, reverse=True)[:5]
        density = nx.density(G)
        communities = list(nx.community.greedy_modularity_communities(G))
        with st.spinner("Analyzing network topology..."):
            network_analysis = generate_network_analysis(tokenizer, model, top_central, density, communities)
        st.markdown(network_analysis)

        # Additional Cybersecurity Insights
        st.header("Additional Cybersecurity Insights")
        
        # CVSS Score Distribution (if available)
        if 'cvss_score' in filtered_vulnerabilities.columns:
            st.subheader("CVSS Score Distribution")
            fig_cvss = px.histogram(filtered_vulnerabilities, x='cvss_score', nbins=20, 
                               title="Distribution of CVSS Scores",
                               labels={'cvss_score': 'CVSS Score', 'count': 'Number of Vulnerabilities'},
                               color_discrete_sequence=['#3b82f6'])
            fig_cvss.update_layout(bargap=0.1)
            st.plotly_chart(fig_cvss, use_container_width=True, config={'displayModeBar': False})
            
            avg_cvss = filtered_vulnerabilities['cvss_score'].mean()
            high_cvss = filtered_vulnerabilities[filtered_vulnerabilities['cvss_score'] > 7]
            with st.spinner("Analyzing CVSS distribution..."):
                cvss_analysis = analyze_cvss_distribution(tokenizer, model, avg_cvss, len(high_cvss))
            st.markdown(cvss_analysis)

        # Vulnerability Age Analysis
        if created_at_column:
            st.subheader("Vulnerability Age Analysis")
            filtered_vulnerabilities['age'] = (datetime.now(pytz.utc) - filtered_vulnerabilities[created_at_column]).dt.days
            fig_age = px.box(filtered_vulnerabilities, y='age', 
                         title="Distribution of Vulnerability Age",
                         labels={'age': 'Age (days)'},
                         color_discrete_sequence=['#3b82f6'])
            st.plotly_chart(fig_age, use_container_width=True, config={'displayModeBar': False})
            
            avg_age = filtered_vulnerabilities['age'].mean()
            old_vulnerabilities = filtered_vulnerabilities[filtered_vulnerabilities['age'] > 90]
            with st.spinner("Analyzing vulnerability age..."):
                age_analysis = analyze_vulnerability_age(tokenizer, model, avg_age, len(old_vulnerabilities))
            st.markdown(age_analysis)

        # Vulnerability Types Analysis
        st.subheader("Top Vulnerability Types")
        vuln_types = filtered_vulnerabilities['template_name'].value_counts().head(10)
        fig_types = px.bar(x=vuln_types.index, y=vuln_types.values, 
                     title="Top 10 Vulnerability Types",
                     labels={'x': 'Vulnerability Type', 'y': 'Count'},
                     color_discrete_sequence=['#3b82f6'])
        st.plotly_chart(fig_types, use_container_width=True, config={'displayModeBar': False})
        
        with st.spinner("Analyzing vulnerability types..."):
            types_analysis = analyze_vulnerability_types(tokenizer, model, vuln_types.index[0], vuln_types.values[0], vuln_types.index.tolist())
        st.markdown(types_analysis)

        # Remediation Priority Matrix
        st.header("Remediation Priority Matrix")
        if all(col in filtered_vulnerabilities.columns for col in [severity_column, 'cvss_score', 'exploit_available']):
            fig_remediation = px.scatter(filtered_vulnerabilities, 
                             x='cvss_score', 
                             y=severity_column, 
                             color='exploit_available',
                             size='cvss_score',
                             hover_data=[host_column, 'template_name'],
                             title="Remediation Priority Matrix",
                             color_discrete_map={True: '#ef4444', False: '#3b82f6'})
            st.plotly_chart(fig_remediation, use_container_width=True, config={'displayModeBar': False})
            
            high_priority = filtered_vulnerabilities[(filtered_vulnerabilities['cvss_score'] > 7) & (filtered_vulnerabilities['exploit_available'] == True)]
            
            with st.spinner("Analyzing remediation priorities..."):
                remediation_analysis = analyze_remediation_priority(tokenizer, model, len(high_priority))
            st.markdown(remediation_analysis)
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
            fig_trend.add_trace(go.Scatter(x=vulnerabilities_per_day.index, y=vulnerabilities_per_day['count'], mode='lines', name='Actual', line=dict(color='#3b82f6')))
            fig_trend.add_trace(go.Scatter(x=vulnerabilities_per_day.index, y=vulnerabilities_per_day['SMA'], mode='lines', name='7-day Moving Average', line=dict(color='#10b981')))
            fig_trend.add_trace(go.Scatter(x=forecast_dates, y=forecast_values, mode='lines', name='Forecast', line=dict(color='#f59e0b', dash='dash')))
            fig_trend.update_layout(title='Vulnerability Trend and 30-day Forecast', xaxis_title='Date', yaxis_title='Number of Vulnerabilities')
            st.plotly_chart(fig_trend, use_container_width=True, config={'displayModeBar': False})

            current_avg = vulnerabilities_per_day['SMA'].iloc[-1]
            trend = 'Increasing' if vulnerabilities_per_day['SMA'].iloc[-1] > vulnerabilities_per_day['SMA'].iloc[-8] else 'Decreasing or Stable'
            with st.spinner("Analyzing vulnerability trend..."):
                trend_analysis = analyze_vulnerability_trend(tokenizer, model, current_avg, trend)
            st.markdown(trend_analysis)

        # Export Options
        st.header("Export Dashboard")
        col1, col2 = st.columns(2)
        with col1:
            export_format = st.selectbox("Choose export format:", ["PDF", "CSV", "JSON"], key="export_format")
        with col2:
            if st.button("Generate Report", key="generate_report"):
                with st.spinner(f"Generating {export_format} report..."):
                    if export_format == "PDF":
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
                        
                        pdf_buffer = generate_pdf_report(filtered_vulnerabilities, analyses, figures)
                        st.download_button(
                            label="Download PDF Report",
                            data=pdf_buffer,
                            file_name="orizon_security_report.pdf",
                            mime="application/pdf",
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
        selected_columns = st.multiselect(
            "Select columns to display",
            options=filtered_vulnerabilities.columns,
            default=[host_column, severity_column, 'template_name', description_column],
            key="column_selector"
        )
        st.dataframe(filtered_vulnerabilities[selected_columns], height=400, use_container_width=True)

    else:
        st.info("Please upload a JSON file in the sidebar to begin the analysis.")

if __name__ == "__main__":
    main()