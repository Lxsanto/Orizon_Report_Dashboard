import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import networkx as nx
from datetime import datetime, timedelta
import pytz
from collections import Counter

# Set page config
st.set_page_config(page_title="Orizon Dashboard", layout="wide")

# Utility functions
@st.cache_data
def load_data(file):
    if file is not None:
        data = json.loads(file.getvalue().decode('utf-8'))
        if isinstance(data, dict):
            return pd.DataFrame(data)
        elif isinstance(data, list):
            return pd.DataFrame(data)
        else:
            st.error("Unrecognized data format. Please upload a valid JSON file.")
            return None
    return None

def calculate_risk_score(vulnerabilities, severity_column):
    severity_weights = {'critical': 10, 'high': 8, 'medium': 5, 'low': 2, 'info': 1}
    total_weight = sum(severity_weights.get(str(v).lower(), 0) for v in vulnerabilities[severity_column])
    max_weight = len(vulnerabilities) * 10
    return 100 - int((total_weight / max_weight) * 100) if max_weight > 0 else 100

def analyze_overview(vulnerabilities, severity_column):
    total = len(vulnerabilities)
    critical = len(vulnerabilities[vulnerabilities[severity_column].str.lower() == 'critical'])
    high = len(vulnerabilities[vulnerabilities[severity_column].str.lower() == 'high'])
    risk_score = calculate_risk_score(vulnerabilities, severity_column)
    
    analysis = f"Security Posture Summary:\n\n"
    analysis += f"• Total vulnerabilities: {total}\n"
    analysis += f"• Risk score: {risk_score}/100\n"
    analysis += f"• Critical vulnerabilities: {critical}\n"
    analysis += f"• High severity vulnerabilities: {high}\n\n"
    
    if risk_score > 80:
        analysis += "Overall assessment: GOOD\n"
        analysis += "The current security posture is robust, but vigilance is required. Recommendations:\n"
        analysis += "1. Implement continuous monitoring for new threats.\n"
        analysis += "2. Conduct regular penetration testing to identify potential weaknesses.\n"
        analysis += "3. Focus on addressing any remaining critical and high vulnerabilities."
    elif risk_score > 60:
        analysis += "Overall assessment: NEEDS IMPROVEMENT\n"
        analysis += "The security posture requires attention. Urgent recommendations:\n"
        analysis += "1. Prioritize patching critical and high severity vulnerabilities immediately.\n"
        analysis += "2. Conduct a thorough review of security policies and procedures.\n"
        analysis += "3. Implement additional security controls to mitigate risks."
    else:
        analysis += "Overall assessment: CRITICAL\n"
        analysis += "The security posture is at high risk. Immediate actions required:\n"
        analysis += "1. Initiate incident response procedures to contain potential breaches.\n"
        analysis += "2. Engage in rapid vulnerability remediation, focusing on critical and high severity issues.\n"
        analysis += "3. Conduct an emergency security audit and consider engaging external cybersecurity experts."
    
    return analysis

def analyze_severity_distribution(vulnerabilities, severity_column):
    severity_counts = vulnerabilities[severity_column].value_counts()
    total = len(vulnerabilities)
    
    analysis = "Severity Distribution Analysis:\n\n"
    for severity, count in severity_counts.items():
        percentage = (count / total) * 100
        analysis += f"• {severity.capitalize()}: {count} ({percentage:.1f}%)\n"
    
    analysis += "\nKey Insights:\n"
    most_common = severity_counts.index[0]
    analysis += f"1. The most prevalent severity level is '{most_common}'.\n"
    
    if most_common.lower() in ['critical', 'high']:
        analysis += "2. High concentration of severe vulnerabilities indicates a critical security situation.\n"
        analysis += "3. Immediate action is necessary to address these high-risk issues.\n"
        analysis += "4. Consider implementing emergency patches and conducting an urgent security review."
    elif most_common.lower() == 'medium':
        analysis += "2. A significant number of medium-severity issues require attention.\n"
        analysis += "3. While not immediately critical, these vulnerabilities could be exploited if left unaddressed.\n"
        analysis += "4. Develop a prioritized remediation plan to tackle these issues systematically."
    else:
        analysis += "2. The majority of issues are lower severity, which is relatively positive.\n"
        analysis += "3. However, these should still be addressed as part of ongoing security maintenance.\n"
        analysis += "4. Implement a regular patching schedule to prevent accumulation of minor vulnerabilities."
    
    return analysis

def analyze_timeline(vulnerabilities, created_at_column, severity_column):
    vulnerabilities[created_at_column] = pd.to_datetime(vulnerabilities[created_at_column], utc=True)
    recent_vulnerabilities = vulnerabilities[vulnerabilities[created_at_column] > (datetime.now(pytz.utc) - timedelta(days=30))]
    recent_critical_high = len(recent_vulnerabilities[recent_vulnerabilities[severity_column].str.lower().isin(['critical', 'high'])])
    
    analysis = "Vulnerability Discovery Trend Analysis:\n\n"
    analysis += f"• In the last 30 days, {len(recent_vulnerabilities)} new vulnerabilities were discovered.\n"
    analysis += f"• {recent_critical_high} of these are critical or high severity.\n\n"
    
    if recent_critical_high > 0:
        analysis += "Key Concerns:\n"
        analysis += "1. The presence of recent high-severity vulnerabilities indicates active security threats.\n"
        analysis += "2. These new critical/high vulnerabilities require immediate attention and rapid response.\n"
        analysis += "3. Consider initiating an incident response procedure to investigate potential exploits.\n"
    else:
        analysis += "Positive Indicators:\n"
        analysis += "1. No recent critical or high severity vulnerabilities discovered is a good sign.\n"
        analysis += "2. This suggests that current security measures may be effective in preventing severe issues.\n"
        analysis += "3. Continue monitoring and addressing lower severity vulnerabilities proactively.\n"
    
    vulnerability_rate = len(recent_vulnerabilities) / 30  # vulnerabilities per day
    if vulnerability_rate > len(vulnerabilities) / (365 * 2):  # comparing to average over last 2 years
        analysis += "\nTrend Alert:\n"
        analysis += "• There's a significant increase in vulnerability discovery rate recently.\n"
        analysis += "• This could indicate:\n"
        analysis += "  - Increased attacker activity or new attack vectors\n"
        analysis += "  - Recent changes in the system that introduced vulnerabilities\n"
        analysis += "  - Improved detection capabilities uncovering previously hidden issues\n"
        analysis += "• Recommendation: Conduct a thorough security review and consider increasing monitoring efforts.\n"
    else:
        analysis += "\nStable Trend:\n"
        analysis += "• The rate of new vulnerability discovery is stable or decreasing.\n"
        analysis += "• This suggests that current security measures and practices are generally effective.\n"
        analysis += "• Recommendation: Maintain the current security posture while continuing to monitor for new threats.\n"
    
    return analysis

def analyze_top_vulnerabilities(top_vulnerabilities):
    analysis = f"Top {len(top_vulnerabilities)} Vulnerabilities Analysis:\n\n"
    
    common_types = top_vulnerabilities['template_name'].value_counts()
    most_common_type = common_types.index[0]
    analysis += f"1. Most Common Vulnerability Type:\n"
    analysis += f"   • '{most_common_type}' (Frequency: {common_types[0]})\n"
    analysis += f"   • This vulnerability type may indicate a systemic issue in the infrastructure.\n"
    analysis += f"   • Recommendation: Conduct a focused audit on systems susceptible to this vulnerability type.\n\n"
    
    hosts_affected = top_vulnerabilities['host'].nunique()
    most_affected_host = top_vulnerabilities['host'].value_counts().index[0]
    analysis += f"2. Host Impact:\n"
    analysis += f"   • Total hosts affected: {hosts_affected}\n"
    analysis += f"   • Most vulnerable host: {most_affected_host}\n"
    analysis += f"   • Recommendation: Prioritize remediation efforts on the most affected hosts, particularly {most_affected_host}.\n\n"
    
    if 'critical' in top_vulnerabilities['severity'].str.lower().values:
        critical_count = len(top_vulnerabilities[top_vulnerabilities['severity'].str.lower() == 'critical'])
        analysis += f"3. Critical Vulnerabilities:\n"
        analysis += f"   • {critical_count} critical vulnerabilities identified\n"
        analysis += f"   • These pose immediate and severe risk to the system\n"
        analysis += f"   • Recommendation: Initiate emergency patching for all critical vulnerabilities.\n\n"
    
    # Additional analysis on exploitation risk
    if 'cvss_score' in top_vulnerabilities.columns:
        high_cvss = top_vulnerabilities[top_vulnerabilities['cvss_score'] > 7]
        analysis += f"4. Exploitation Risk:\n"
        analysis += f"   • {len(high_cvss)} vulnerabilities have a CVSS score > 7.0\n"
        analysis += f"   • These are at high risk of exploitation\n"
        analysis += f"   • Recommendation: Implement additional security controls and consider isolating affected systems.\n\n"
    
    analysis += "5. Action Plan:\n"
    analysis += "   • Immediately address all critical and high severity vulnerabilities\n"
    analysis += "   • Conduct a root cause analysis on the most common vulnerability types\n"
    analysis += "   • Implement security hardening measures on the most affected hosts\n"
    analysis += "   • Develop a comprehensive patch management strategy to prevent recurring issues\n"
    
    return analysis

def generate_network_analysis(G):
    analysis = "Network Topology Analysis:\n\n"
    
    # Identify central nodes
    centrality = nx.degree_centrality(G)
    top_central = sorted(centrality, key=centrality.get, reverse=True)[:5]
    
    analysis += "1. Key Nodes:\n"
    for node in top_central:
        analysis += f"   • {node}: High connectivity, potential critical point in the network\n"
    analysis += "   Recommendation: Enhance security measures on these key nodes to prevent widespread impact.\n\n"
    
    # Analyze network density
    density = nx.density(G)
    analysis += f"2. Network Density: {density:.2f}\n"
    if density > 0.5:
        analysis += "   • The network is highly interconnected\n"
        analysis += "   • This could lead to rapid propagation of attacks\n"
        analysis += "   Recommendation: Implement network segmentation to reduce the risk of lateral movement.\n\n"
    else:
        analysis += "   • The network has a moderate to low level of interconnection\n"
        analysis += "   • This may naturally limit the spread of potential attacks\n"
        analysis += "   Recommendation: Review isolation policies to ensure critical assets are adequately protected.\n\n"
    
    # Identify potential bottlenecks
    cut_vertices = list(nx.articulation_points(G))
    if cut_vertices:
        analysis += "3. Potential Bottlenecks:\n"
        for vertex in cut_vertices[:3]:  # List top 3 to keep it concise
            analysis += f"   • {vertex}: Critical junction in the network\n"
        analysis += "   Recommendation: Implement redundancy for these nodes to improve network resilience.\n\n"
    
    # Community detection
    communities = list(nx.community.greedy_modularity_communities(G))
    analysis += f"4. Network Communities:\n"
    analysis += f"   • Detected {len(communities)} distinct communities in the network\n"
    if len(communities) > 1:
        analysis += "   • This suggests some natural segmentation exists\n"
        analysis += "   Recommendation: Align security policies with these natural boundaries and consider formalizing them.\n"
    else:
        analysis += "   • The network appears to be a single, tightly-knit community\n"
        analysis += "   Recommendation: Consider implementing artificial segmentation to improve security isolation.\n"
    
    return analysis

def main():
    st.title("Enhanced Cybersecurity Assessment Dashboard")

    # Sidebar for file upload and global filters
    with st.sidebar:
        st.header("Dashboard Controls")
        uploaded_file = st.file_uploader("Upload Vulnerability JSON", type="json", key="vuln_upload")
        
        if uploaded_file:
            vulnerabilities = load_data(uploaded_file)
            if vulnerabilities is not None and not vulnerabilities.empty:
                st.success("File uploaded successfully!")
                
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
            
            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            with metric_col1:
                st.metric("Total Vulnerabilities", total_vulns)
            with metric_col2:
                st.metric("Risk Score", f"{risk_score}/100", delta=f"{100-risk_score} points to improve")
            with metric_col3:
                st.metric("Critical Vulnerabilities", critical_vulns, delta=-critical_vulns, delta_color="inverse")
            with metric_col4:
                st.metric("High Vulnerabilities", high_vulns, delta=-high_vulns, delta_color="inverse")
            
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Score"},
                gauge = {
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "darkblue"},
                    'steps' : [
                        {'range': [0, 50], 'color': "red"},
                        {'range': [50, 75], 'color': "yellow"},
                        {'range': [75, 100], 'color': "green"}],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': risk_score}}))
            st.plotly_chart(fig)
        
        with col2:
            st.subheader("AI-Powered Security Analysis")
            st.markdown(analyze_overview(filtered_vulnerabilities, severity_column))

        # Severity Distribution
        st.header("Vulnerability Severity Distribution")
        col1, col2 = st.columns([2, 1])
        with col1:
            severity_counts = filtered_vulnerabilities[severity_column].value_counts()
            fig = px.pie(values=severity_counts.values, names=severity_counts.index, 
                         title="Vulnerability Severity Distribution",
                         color=severity_counts.index,
                         color_discrete_map={'critical': 'red', 'high': 'orange', 'medium': 'yellow', 'low': 'green', 'info': 'blue'})
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig)
        with col2:
            st.subheader("AI-Powered Severity Analysis")
            st.markdown(analyze_severity_distribution(filtered_vulnerabilities, severity_column))

        # Vulnerability Timeline
        st.header("Vulnerability Discovery Timeline")
        col1, col2 = st.columns([2, 1])
        with col1:
            timeline_data = filtered_vulnerabilities.groupby([created_at_column, severity_column]).size().unstack(fill_value=0)
            fig = px.area(timeline_data, x=timeline_data.index, y=timeline_data.columns, 
                          title="Vulnerability Discovery Over Time",
                          labels={'value': 'Number of Vulnerabilities', created_at_column: 'Date'},
                          color_discrete_map={'critical': 'red', 'high': 'orange', 'medium': 'yellow', 'low': 'green', 'info': 'blue'})
            fig.update_layout(legend_title_text='Severity')
            st.plotly_chart(fig)
        with col2:
            st.subheader("AI-Powered Trend Analysis")
            st.markdown(analyze_timeline(filtered_vulnerabilities, created_at_column, severity_column))

        # Top 10 Vulnerabilities
        st.header("Top 10 Critical Vulnerabilities")
        top_10 = filtered_vulnerabilities.sort_values(severity_column, ascending=False).head(10)
        fig = go.Figure(data=[go.Table(
            header=dict(values=['Host', 'Severity', 'Vulnerability', 'Description'],
                        fill_color='paleturquoise',
                        align='left'),
            cells=dict(values=[top_10[host_column], top_10[severity_column], top_10['template_name'], top_10[description_column]],
                       fill_color='lavender',
                       align='left'))
        ])
        fig.update_layout(title_text="Top 10 Critical Vulnerabilities")
        st.plotly_chart(fig)
        st.subheader("AI-Powered Vulnerability Analysis")
        st.markdown(analyze_top_vulnerabilities(top_10))

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
        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines')
        node_x = [pos[node][0] for node in G.nodes()]
        node_y = [pos[node][1] for node in G.nodes()]
        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers', hoverinfo='text',
                                marker=dict(showscale=True, colorscale='YlOrRd', size=10, 
                                            color=[], colorbar=dict(thickness=15, title='Node Connections'),
                                            line_width=2))
        node_adjacencies = []
        node_text = []
        for node, adjacencies in enumerate(G.adjacency()):
            node_adjacencies.append(len(adjacencies[1]))
            node_text.append(f'{adjacencies[0]} - # of connections: {len(adjacencies[1])}')
        node_trace.marker.color = node_adjacencies
        node_trace.text = node_text
        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(showlegend=False, hovermode='closest',
                                         margin=dict(b=20,l=5,r=5,t=40),
                                         title="Network Topology Visualization"))
        st.plotly_chart(fig)
        st.subheader("AI-Powered Network Analysis")
        st.markdown(generate_network_analysis(G))

        # Additional Cybersecurity Insights
        st.header("Additional Cybersecurity Insights")
        
        # CVSS Score Distribution (if available)
        if 'cvss_score' in filtered_vulnerabilities.columns:
            st.subheader("CVSS Score Distribution")
            fig = px.histogram(filtered_vulnerabilities, x='cvss_score', nbins=20, 
                               title="Distribution of CVSS Scores",
                               labels={'cvss_score': 'CVSS Score', 'count': 'Number of Vulnerabilities'})
            fig.update_layout(bargap=0.1)
            st.plotly_chart(fig)
            
            avg_cvss = filtered_vulnerabilities['cvss_score'].mean()
            high_cvss = filtered_vulnerabilities[filtered_vulnerabilities['cvss_score'] > 7]
            st.markdown(f"""
            **AI Analysis of CVSS Scores:**
            - Average CVSS Score: {avg_cvss:.2f}
            - Number of high-risk vulnerabilities (CVSS > 7.0): {len(high_cvss)}
            - Recommendation: Focus on vulnerabilities with high CVSS scores, as they pose the most significant risk.
            """)

        # Vulnerability Age Analysis
        if created_at_column:
            filtered_vulnerabilities['age'] = (datetime.now(pytz.utc) - filtered_vulnerabilities[created_at_column]).dt.days
            st.subheader("Vulnerability Age Analysis")
            fig = px.box(filtered_vulnerabilities, y='age', 
                         title="Distribution of Vulnerability Age",
                         labels={'age': 'Age (days)'})
            st.plotly_chart(fig)
            
            avg_age = filtered_vulnerabilities['age'].mean()
            old_vulnerabilities = filtered_vulnerabilities[filtered_vulnerabilities['age'] > 90]
            st.markdown(f"""
            **AI Analysis of Vulnerability Age:**
            - Average age of vulnerabilities: {avg_age:.1f} days
            - Number of vulnerabilities older than 90 days: {len(old_vulnerabilities)}
            - Recommendation: Prioritize addressing older vulnerabilities, especially those that have remained unresolved for extended periods.
            """)

        # Vulnerability Types Analysis
        st.subheader("Top Vulnerability Types")
        vuln_types = filtered_vulnerabilities['template_name'].value_counts().head(10)
        fig = px.bar(x=vuln_types.index, y=vuln_types.values, 
                     title="Top 10 Vulnerability Types",
                     labels={'x': 'Vulnerability Type', 'y': 'Count'})
        st.plotly_chart(fig)
        
        most_common_type = vuln_types.index[0]
        st.markdown(f"""
        **AI Analysis of Vulnerability Types:**
        - Most common vulnerability type: {most_common_type}
        - This vulnerability type appears {vuln_types.values[0]} times
        - Recommendation: Conduct a focused review on systems affected by '{most_common_type}' to identify and address common weaknesses.
        """)

        # Remediation Priority Matrix
        st.header("Remediation Priority Matrix")
        if all(col in filtered_vulnerabilities.columns for col in [severity_column, 'cvss_score', 'exploit_available']):
            fig = px.scatter(filtered_vulnerabilities, 
                             x='cvss_score', 
                             y=severity_column, 
                             color='exploit_available',
                             size='cvss_score',
                             hover_data=[host_column, 'template_name'],
                             title="Remediation Priority Matrix")
            st.plotly_chart(fig)
            
            high_priority = filtered_vulnerabilities[(filtered_vulnerabilities['cvss_score'] > 7) & (filtered_vulnerabilities['exploit_available'] == True)]
            st.markdown(f"""
            **AI Analysis of Remediation Priorities:**
            - {len(high_priority)} vulnerabilities are high priority (CVSS > 7 and exploit available)
            - These should be addressed immediately to minimize risk
            - Recommendation: Create a task force to address these high-priority vulnerabilities within the next 48 hours
            """)
        else:
            st.write("Not enough information available for remediation priority analysis.")

        # Final Recommendations
        st.header("AI-Generated Final Recommendations")
        st.markdown(f"""
        Based on the comprehensive analysis of your cybersecurity posture, here are the key recommendations:

        1. **Immediate Action Required:** 
           - Address the {len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'critical'])} critical vulnerabilities immediately.
           - Patch or mitigate the {len(high_priority) if 'high_priority' in locals() else 'high-priority'} vulnerabilities with known exploits and high CVSS scores.

        2. **Short-term Priorities:**
           - Implement a rapid patching cycle for high and medium severity vulnerabilities.
           - Conduct a thorough review of network segmentation based on the topology analysis.
           - Enhance monitoring for the most vulnerable hosts identified in the analysis.

        3. **Long-term Strategies:**
           - Develop a comprehensive plan to improve the overall risk score, aiming for a target of 85+.
           - Establish a regular vulnerability assessment and penetration testing schedule.
           - Invest in security awareness training for all staff to reduce human-factor risks.
           - Regularly update and test the incident response plan based on the latest threat landscape.

        4. **Continuous Improvement:**
           - Monitor the monthly vulnerability trend and adjust security measures accordingly.
           - Regularly reassess compliance status and address any gaps in meeting security standards.
           - Implement a feedback loop to continuously refine and improve the vulnerability management process.

        Remember, cybersecurity is an ongoing process. Regular reviews and updates to your security strategy are essential to maintain a robust security posture in the face of evolving threats.
        """)

        # Export Options
        st.header("Export Dashboard")
        col1, col2 = st.columns(2)
        with col1:
            export_format = st.selectbox("Choose export format:", ["PDF", "CSV", "JSON"], key="export_format")
        with col2:
            if st.button("Generate Report", key="generate_report"):
                if export_format == "PDF":
                    st.success("PDF report generation initiated. (Note: This is a placeholder. Actual PDF generation would need to be implemented.)")
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
        st.dataframe(filtered_vulnerabilities[selected_columns], height=400)

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

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=vulnerabilities_per_day.index, y=vulnerabilities_per_day['count'], mode='lines', name='Actual'))
            fig.add_trace(go.Scatter(x=vulnerabilities_per_day.index, y=vulnerabilities_per_day['SMA'], mode='lines', name='7-day Moving Average'))
            fig.add_trace(go.Scatter(x=forecast_dates, y=forecast_values, mode='lines', name='Forecast', line=dict(dash='dash')))
            fig.update_layout(title='Vulnerability Trend and 30-day Forecast', xaxis_title='Date', yaxis_title='Number of Vulnerabilities')
            st.plotly_chart(fig)

            st.markdown("""
            **AI Analysis of Vulnerability Trend Forecast:**
            - The forecast is based on a 7-day moving average of historical data.
            - This simple model assumes that recent trends will continue in the near future.
            - Use this forecast as a general guideline, but be aware that actual numbers may vary due to unforeseen factors.
            - Recommendation: Regularly update this forecast with new data and adjust your security measures accordingly.
            """)

        # Comparative Analysis
        st.header("Comparative Analysis")
        if st.checkbox("Compare with previous period", key="compare_checkbox"):
            current_period = filtered_vulnerabilities
            previous_period_start = current_period[created_at_column].min() - (current_period[created_at_column].max() - current_period[created_at_column].min())
            previous_period = vulnerabilities[(vulnerabilities[created_at_column] >= previous_period_start) & (vulnerabilities[created_at_column] < current_period[created_at_column].min())]

            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Current Period")
                st.metric("Total Vulnerabilities", len(current_period))
                st.metric("Critical Vulnerabilities", len(current_period[current_period[severity_column].str.lower() == 'critical']))
                st.metric("Risk Score", calculate_risk_score(current_period, severity_column))

            with col2:
                st.subheader("Previous Period")
                st.metric("Total Vulnerabilities", len(previous_period))
                st.metric("Critical Vulnerabilities", len(previous_period[previous_period[severity_column].str.lower() == 'critical']))
                st.metric("Risk Score", calculate_risk_score(previous_period, severity_column))

            st.markdown("""
            **AI Analysis of Period Comparison:**
            - Compare the metrics between the current and previous periods to identify trends.
            - A significant increase in vulnerabilities or critical issues may indicate new security challenges.
            - An improved risk score suggests that your security measures are having a positive impact.
            - Recommendation: Investigate any notable changes between periods and adjust your security strategy accordingly.
            """)

        # Security Posture Improvement Suggestions
        st.header("Security Posture Improvement Suggestions")
        improvement_areas = [
            "Vulnerability Management",
            "Network Security",
            "Access Control",
            "Data Protection",
            "Incident Response",
            "Security Awareness Training"
        ]
        selected_area = st.selectbox("Select an area for improvement suggestions:", improvement_areas, key="improvement_area")

        if selected_area == "Vulnerability Management":
            st.markdown("""
            1. Implement a continuous vulnerability scanning process.
            2. Prioritize patching based on vulnerability severity and exploit availability.
            3. Establish a clear patch management policy and stick to defined SLAs.
            4. Regularly audit and update your asset inventory.
            5. Implement virtual patching where immediate patching is not possible.
            """)
        elif selected_area == "Network Security":
            st.markdown("""
            1. Implement network segmentation to limit the spread of potential breaches.
            2. Regularly review and update firewall rules.
            3. Implement Intrusion Detection and Prevention Systems (IDS/IPS).
            4. Use VPNs for secure remote access.
            5. Implement strong encryption for data in transit.
            """)
        # Add more elif blocks for other improvement areas...

        st.markdown(f"""
        **AI-Generated Advice for {selected_area}:**
        These suggestions are based on industry best practices and the specific vulnerabilities identified in your environment. Implementing these measures can significantly improve your security posture in the area of {selected_area.lower()}.
        """)

    else:
        st.write("Please upload a JSON file to begin the analysis.")

if __name__ == "__main__":
    main()
