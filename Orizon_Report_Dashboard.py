import os
import io
import zipfile
import time
from collections import Counter
from datetime import datetime, timedelta
import pandas as pd
import streamlit as st
import torch
import re
import cProfile
import pstats
from icecream import ic
from dotenv import load_dotenv

# Carica le variabili dal file .env
load_dotenv()

# Accedi alla variabile di ambiente
hugging_token = os.getenv('huggin_face')
ip_token = os.getenv('ip_info')

# Streamlit Authenticator per la gestione dell'autenticazione
from streamlit_authenticator import Authenticate
import yaml
from yaml.loader import SafeLoader

# my functions
from restart_utils import clear_pycache, restart_script
from GPU_utils import print_gpu_utilization, print_summary
from generic_utils import *
from prompts_utils import *
from docx_utils import * 
from export_utils import *
from graphic_utils import *

# Tentativo di importazione condizionale con gestione degli errori
try:
    from transformers import AutoTokenizer, pipeline
except ImportError:
    print("Errore durante l'importazione di 'AutoTokenizer'. Pulizia della cache e riavvio dello script...")
    clear_pycache()
    restart_script()

logo = Image.open("logo1.png")

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

# Configurazione dell'ambiente CUDA
are_you_on_CUDA = False
run_LLM = False
if are_you_on_CUDA:
    os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'

# Selezione del modello LLM
model_id = "meta-llama/Llama-3.2-3B-Instruct"
#model_id = "microsoft/Phi-3.5-mini-instruct"

# Pulizia della cache di Streamlit
clear = False
if clear:
    st.cache_resource.clear()

ports = ['20', '21', '22', '23', '25', '53', '110', '135', '139', '143', '445', '3389']


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
def load_LLM(model_id = model_id, auth_token = hugging_token):

    if not torch.cuda.is_available():
        print("CUDA GPU not available!")
    else:
        print("CUDA is available. Backend and pinned memory configurations are applied.")
        print_gpu_utilization()

    
    try:
        model_kwargs = {'load_in_8bit':True
        }
        _tokenizer = AutoTokenizer.from_pretrained(model_id, 
                                                   use_fast= True)
        chat_pipeline = pipeline("text-generation", 
                                 torch_dtype='auto',
                             model=model_id,
                             token=auth_token,
                             tokenizer=_tokenizer,
                             device_map="auto",
                             #model_kwargs=model_kwargs
                             )
        
        print(f'Pipeline loaded on {chat_pipeline.device}')

        return chat_pipeline
    
    except Exception as e:
        st.error(f"Error loading the model: {str(e)}")

def calculate_risk_score(vulnerabilities, severity_column):
    # Definisce i pesi per ogni livello di severità.
    # I pesi riflettono l'impatto relativo di ciascuna severità sulla valutazione complessiva del rischio.
    # 'critical' ha un peso di 1000, il più alto, mentre 'info' ha un peso di 1, il più basso.
    severity_weights = {'critical': 1000, 'high': 600, 'medium': 400, 'low': 100, 'info': 1}
    
    # Inizializza un dizionario per contare le occorrenze di ciascun livello di severità.
    # Ogni chiave (livello di severità) è inizializzata a 0.
    severity_counts = {severity: 0 for severity in severity_weights}
    
    # Conta il numero di vulnerabilità per ciascun livello di severità.
    # Converte ogni valore di severità in minuscolo per gestire eventuali differenze di formato.
    for v in vulnerabilities[severity_column]:
        severity = str(v).lower()
        # Incrementa il conteggio solo se la severità è presente nel dizionario.
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Calcola il punteggio ponderato sommando il prodotto tra il peso di ciascuna severità
    # e il numero di vulnerabilità corrispondenti.
    weighted_score = sum(severity_weights[severity] * count for severity, count in severity_counts.items())
    
    # Calcola il numero totale di vulnerabilità sommandone i conteggi.
    total_vulnerabilities = sum(severity_counts.values())
    
    # Se non ci sono vulnerabilità, restituisce un punteggio di rischio pari a 0.
    if total_vulnerabilities == 0:
        return 0
    
    # Calcola il punteggio di rischio basato principalmente sul punteggio ponderato,
    # normalizzando il punteggio sulla base del numero totale di vulnerabilità e raddoppiandolo per dare maggiore peso.
    risk_score = (weighted_score / total_vulnerabilities) * 2
    
    # Se sono presenti vulnerabilità di livello 'medium', si assicura che abbiano un impatto significativo sul punteggio.
    # Il punteggio viene aumentato a un minimo di 40 più 5 punti per ogni vulnerabilità 'medium' aggiuntiva.
    if severity_counts['medium'] > 0:
        risk_score = max(risk_score, 40 + (severity_counts['medium'] - 1) * 5)
    
    # Limita il punteggio massimo a 100 per evitare che superi un valore massimo predefinito.
    risk_score = min(risk_score, 100)
    
    # Restituisce il punteggio di rischio come intero, per una rappresentazione più pulita.
    return int(risk_score)

def calculate_risk_score1(severity_counts):
    """
    Calcola il punteggio di rischio basato sul numero di vulnerabilità di ciascun tipo.
    
    Args:
        severity_counts (dict): Dizionario contenente il numero di vulnerabilità per ciascun livello di severità.
    
    Returns:
        int: Punteggio di rischio calcolato.
    """
    
    # Estrai i valori dal dizionario per una gestione più chiara.
    info = severity_counts.get('info', 0)
    low = severity_counts.get('low', 0)
    medium = severity_counts.get('medium', 0)
    high = severity_counts.get('high', 0)
    critical = severity_counts.get('critical', 0)

    # Calcola il numero totale di vulnerabilità significative.
    total_vuln = medium + high + critical
    total_low = info + low

    # Caso 1: Nessuna vulnerabilità rilevante.
    if total_vuln == 0:
        # Caso 1a: Nessuna vulnerabilità info o low, quindi rischio zero.
        if total_low == 0:
            return 0
        # Caso 1b: Solo vulnerabilità info, restituisce un rischio di 30.
        if info > 0 and low == 0:
            return 30
        # Caso 1c: Solo vulnerabilità low, con un numero maggiore di 5, restituisce un rischio di 45.
        if low > 5:
            return 45
        # Caso 1d: Solo vulnerabilità low o info, meno di 5, restituisce un rischio di 40.
        return 40

    # Caso 2: Presenza di vulnerabilità significative (medium, high, critical).
    # Iniziamo con un valore base per il rischio in base al numero di vulnerabilità.
    risk = 0

    # Definisci un valore base per il rischio in base al numero di vulnerabilità.
    if total_vuln == 1:
        risk = 40
    elif total_vuln == 2:
        risk = 50
    elif total_vuln == 3:
        risk = 55
    elif total_vuln == 4:
        risk = 65
    elif total_vuln == 5:
        risk = 70
    elif total_vuln == 6:
        risk = 80
    else:
        risk = 100  # Per più di 6 vulnerabilità significative, restituisce il rischio massimo.

    # Aggiusta il rischio
    if low > 0:
        risk += 5
    if high > 0:
        risk += 8
    if critical > 0:
        risk += 10
    
    # Limita il punteggio massimo a 100.
    risk = min(risk, 100)

    return risk

@st.cache_data
def process_and_filter_vulnerabilities(uploaded_file):
    vulnerabilities = load_data(uploaded_file)

    # replace unknow tih critical
    if 'severity' in vulnerabilities.columns:
        vulnerabilities['severity'] = vulnerabilities['severity'].replace('unknown', 'critical')

    if vulnerabilities is not None and not vulnerabilities.empty:
        st.sidebar.success("JSON file loaded successfully!")
        
        if 'created_at' in vulnerabilities.columns:
            vulnerabilities['created_at'] = pd.to_datetime(vulnerabilities['created_at'], errors='coerce')
            vulnerabilities = vulnerabilities.dropna(subset=['created_at'])
            return vulnerabilities
        else:
            st.error("The 'created_at' column is missing from the data. Please check your JSON file.")
            return None
    else:
        st.error("Failed to load data or the file is empty.")
        return None

def Geolocation_of_servers(file_contents, api_key):
    # Load and preprocess data
    df = load_data_geo(file_contents)
    
    severity_weights = {
        'unknown': 1, 'info': 2, 'low': 4, 'medium': 6, 'high': 8, 'critical': 10
    }
    
    df['severity_weight'] = df['severity'].map(severity_weights)
    danger_score_per_server = df.groupby('host')['severity_weight'].sum().reset_index()
    host_names = danger_score_per_server['host']

    st.write('The geolocation process duration depends on DNS settings... Please wait')
    progress_bar = st.progress(0)
    status_text = st.empty()
    summary = st.empty()

    geo_results = []
    ips = []
    for id, host in enumerate(host_names):
        progress = (id + 1) / len(host_names)
        progress_bar.progress(progress)
        status_text.text(f'Numbers of scanned hosts: {id + 1}/{len(host_names)}')
        ip = resolve_hostname(host)
        ips.append(ip)
        d = geolocate_ip(ip, api_key)
        geo_results.append(d)


    danger_score_per_server['ip'] = ips
    
    geolocation_data = pd.DataFrame(geo_results, columns=['latitude', 'longitude', 'country', 'city'])
    
    # Combine data and aggregate risk scores
    risk_by_ip = pd.concat([danger_score_per_server, geolocation_data], axis=1)
    risk_by_ip = risk_by_ip.groupby(['ip', 'country', 'city', 'latitude', 'longitude'])['severity_weight'].sum().reset_index()
    
    # Normalize risk scores
    max_score = risk_by_ip['severity_weight'].max()
    risk_by_ip['normalized_risk_score'] = (risk_by_ip['severity_weight'] / max_score) * 100
    risk_by_ip.loc[risk_by_ip['severity_weight'] == max_score, 'normalized_risk_score'] = 100

    geo_map = create_plotly_map(risk_by_ip)
    geo_map_1 = create_country_bubble_plot(risk_by_ip)

    # Group hosts by IP
    hosts_by_ip = danger_score_per_server.groupby('ip')['host'].agg(list).reset_index()
    hosts_by_ip.columns = ['ip', 'associated_hosts']

    # Merge the hosts information with the risk_by_ip dataframe
    risk_by_ip = risk_by_ip.merge(hosts_by_ip, on='ip', how='left')
    
    return geo_map, geo_map_1, risk_by_ip

def main():

    # directory = "latex_template"

    # Lista dei file da verificare ed eliminare se esistono
    # files_to_check = [
    #     "orizon-recon-report-main.aux",
    #     "orizon-recon-report-main.bcf",
    #     "orizon-recon-report-main.log",
    #     "orizon-recon-report-main.out",
    #     "orizon-recon-report-main.pdf",
    #     "orizon-recon-report-main.run.xml",
    #     "orizon-recon-report-main.tex",
    #     "orizon-recon-report-main.toc"
    # ]

    # for file_name in files_to_check:
    #     file_path = os.path.join(directory, file_name)
    #     if os.path.exists(file_path):
    #         print(f"Eliminando il file: {file_name}")
    #         #os.remove(file_path)
    #     else:
    #         print(f"File non trovato: {file_name}")

    # Cartelle da eliminare
    folders = ['ports_scanning', 'txts']

    for folder in folders:
        if os.path.exists(folder):
            #print(f"Cartella '{folder}' trovata, verrà eliminata.")
            shutil.rmtree(folder)
        else:
            #print(f"Cartella '{folder}' non trovata, passo oltre.")
            pass
    
    # cartelle da creare 
    folders = ['txts', 'txts/screenshots', 'txts/pngs', 'txts/ports_scanning', 'txts/dfs']

    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            #print(f"Cartella '{folder}' creata")
        else:
            #print(f"Cartella '{folder}' trovata, passo oltre.")
            pass

    st.sidebar.title("Orizon Security Dashboard")
    
    language = st.selectbox('select language here',
                            ('English', 'Italian', 'Spanish'))
    st.write('You selected:', language)
    
    if language == 'Italian':
        language = 'it'
        vuln_defs = vuln_defs_ita
    if language == 'English':
        language = 'en'
        vuln_defs = vuln_defs_eng
    if language == 'Spanish':
        language = 'es'
        vuln_defs = vuln_defs_esp
    
    uploaded_file = st.sidebar.file_uploader("Upload Vulnerability JSON", type="json", key="vuln_upload")

    name_client = st.text_input("Enter here the name of the Client", None)
    st.write("The current Client name is", name_client)

    if uploaded_file:
        file_contents = uploaded_file.read()
    
    if uploaded_file and name_client:

        filtered_vulnerabilities = process_and_filter_vulnerabilities(uploaded_file)

        ic((filtered_vulnerabilities['severity'] == 'critical').sum())

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
            <a href="#top-10-critical-vulnerabilities">Top Vulnerabilities</a>
            <a href="#additional-cybersecurity-insights">Additional Insights</a>
        </div>
        """, unsafe_allow_html=True)

        # preambolo
        st.write(vuln_defs)

        # Executive Summary
        st.header("Executive Summary", anchor="executive-summary")
        total_vulns = len(filtered_vulnerabilities)

        severity_counts = {severity: 0 for severity in ['info', 'low', 'medium', 'high', 'critical']}

        for v in filtered_vulnerabilities['severity']:
            severity = str(v).lower()
            # Incrementa il conteggio solo se la severità è presente nel dizionario.
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        risk_score = calculate_risk_score1(severity_counts)
        critical_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'critical'])
        high_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'high'])
        medium_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'medium'])
        low_vulns = len(filtered_vulnerabilities[filtered_vulnerabilities[severity_column].str.lower() == 'low'])

        ic(critical_vulns)
        
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

            fig_risk_score = create_risk_score_gauge(risk_score)
            st.plotly_chart(fig_risk_score, use_container_width=True, config={'displayModeBar': False})
        
        with col2:
            overview_analysis = ''
            if run_LLM:
                if 'overview' not in st.session_state:
                    st.session_state['overview'] = analyze_overview(total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns, _pipe = pipe, language=language)

                if st.button(label='Regenerate chapter', help='Hit this button to regenerate the text from the LLM', key='oiu'):
                    analyze_overview.clear()
                    st.session_state['overview'] = analyze_overview(total_vulns, risk_score, critical_vulns, high_vulns, medium_vulns, low_vulns, _pipe = pipe, language=language, clear_cache=True)
                overview_analysis = st.session_state['overview']
                st.write(overview_analysis)

        # Severity Distribution
        st.header("Vulnerability Severity Distribution", anchor="vulnerability-severity-distribution")
        col1, col2 = st.columns([2, 1])
        with col1:
            severity_counts = filtered_vulnerabilities[severity_column].value_counts()
            fig_severity = pie(severity_counts)

            st.plotly_chart(fig_severity, use_container_width=True, config={'displayModeBar': False})

        with col2:
            severity_analysis = ''

            if run_LLM:
                if 'severity' not in st.session_state:
                    st.session_state['severity'] = analyze_severity_distribution(severity_counts, _pipe= pipe, language=language)

                if st.button(label='Regenerate chapter', help='Hit this button to regenerate the text from the LLM', key='uwgs'):
                    analyze_severity_distribution.clear()
                    st.session_state['severity'] = analyze_severity_distribution(severity_counts, _pipe= pipe, language=language, clear_cache=True)
                severity_analysis = st.session_state['severity']
                st.write(severity_analysis)


        # Top 10 Vulnerabilities
        st.header("Top 10 Critical Vulnerabilities", anchor="top-10-critical-vulnerabilities")
    
        def severity_to_num(severity):
            severity_order = {'Critical': 6, 'High': 5, 'Medium': 4, 'Low': 3, 'Info': 2, 'Unknown': 1}
            return severity_order.get(severity.capitalize(), 0)

        # Apply the custom sorting
        filtered_vulnerabilities['severity_num'] = filtered_vulnerabilities[severity_column].apply(severity_to_num)
        top_10 = filtered_vulnerabilities.sort_values(['severity_num', severity_column], ascending=[False, False]).head(10)
    
    
        # Apply the custom sorting
        filtered_vulnerabilities['severity_num'] = filtered_vulnerabilities[severity_column].apply(severity_to_num)
        sorted_vulnerabilities = filtered_vulnerabilities.sort_values(['severity_num', severity_column], ascending=[False, False])

        # Select the columns to display
        selected_columns = [host_column, severity_column, 'template_name', description_column, 'template_url', 'template_id']

        # Pagination
        severities_page = st.slider("Severities per page", min_value=10, max_value=100, value=20, step=10)
        total_pages = len(sorted_vulnerabilities) // severities_page + (1 if len(sorted_vulnerabilities) % severities_page > 0 else 0)
        current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, key=0)

        start_idx = (current_page - 1) * severities_page
        end_idx = start_idx + severities_page
        df_10vuln = sorted_vulnerabilities[selected_columns].iloc[start_idx:end_idx]

        # Display the selected page of the table
        st.dataframe(df_10vuln, height=400, use_container_width=True)

        # Show the pagination information
        st.write(f"Showing {start_idx+1} to {min(end_idx, len(sorted_vulnerabilities))} of {len(sorted_vulnerabilities)} entries")
        common_types = top_10['template_name'].value_counts()
        most_common_type = common_types.index[0]
        hosts_affected = top_10[host_column].nunique()
        most_affected_host = top_10[host_column].value_counts().index[0]

        top_vuln_analysis = ''
        if run_LLM:
            if 'top' not in st.session_state:
                st.session_state['top'] = analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host, _pipe = pipe, language=language)

            if st.button(label='Regenerate chapter', help='Hit this button to regenerate the text from the LLM', key='ywshg'):
                analyze_top_vulnerabilities.clear()
                st.session_state['top'] = analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host, _pipe = pipe, language=language, clear_cache=True)
            top_vuln_analysis = st.session_state['top']
            st.write(top_vuln_analysis)



        # Network Topology View
        # st.header("Network Topology Analysis", anchor="network-topology-analysis")
        # G = nx.Graph()
        # for _, row in filtered_vulnerabilities.iterrows():
        #     G.add_edge(row[host_column], row['template_name'])
        # pos = nx.spring_layout(G)
        # edge_x, edge_y = [], []
        # for edge in G.edges():
        #     x0, y0 = pos[edge[0]]
        #     x1, y1 = pos[edge[1]]
        #     edge_x.extend([x0, x1, None])
        #     edge_y.extend([y0, y1, None])
        # edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5), hoverinfo='none', mode='lines')
        # node_x = [pos[node][0] for node in G.nodes()]
        # node_y = [pos[node][1] for node in G.nodes()]
        # node_trace = go.Scatter(x=node_x, y=node_y, mode='markers', hoverinfo='text',
        #                         marker=dict(showscale=True, size=10, 
        #                                     color=[], colorbar=dict(thickness=15, title='Node Connections'),
        #                                     line_width=2))
        # node_adjacencies = []
        # node_text = []
        # for node, adjacencies in enumerate(G.adjacency()):
        #     node_adjacencies.append(len(adjacencies[1]))
        #     node_text.append(f'{adjacencies[0]} - # of connections: {len(adjacencies[1])}')
        # node_trace.marker.color = node_adjacencies
        # node_trace.text = node_text
        # fig_network = go.Figure(data=[edge_trace, node_trace],
        #                 layout=go.Layout(showlegend=False, hovermode='closest',
        #                                  title="Network Topology Visualization", width=_width, height=_height))
        # st.plotly_chart(fig_network, use_container_width=True, config={'displayModeBar': False})
        # centrality = nx.degree_centrality(G)
        # top_central = sorted(centrality, key=centrality.get, reverse=True)[:5]
        # density = nx.density(G)
        # communities = list(nx.community.greedy_modularity_communities(G))
        #    if run_LLM:
        #        network_analysis = generate_network_analysis(top_central, density, communities, _pipe=pipe, language=language)
        #        st.markdown(network_analysis)

        #Additional Cybersecurity Insights
        st.header("Additional Cybersecurity Insights", anchor="additional-cybersecurity-insights")

        # Vulnerability Types Analysis
        st.subheader("Top Vulnerability Types")
        vuln_types = filtered_vulnerabilities['template_name'].value_counts().head(10)
        
        fig_types = top10_vuln_hist(vuln_types)
        
        st.plotly_chart(fig_types, use_container_width=True, config={'displayModeBar': False})
        
        types_analysis = ''
        if run_LLM:
            if 'types' not in st.session_state:
                st.session_state['types'] = analyze_vulnerability_types(vuln_types.index[0], vuln_types.values[0], vuln_types.index.tolist(), _pipe = pipe, language=language)

            if st.button(label='Regenerate chapter', help='Hit this button to regenerate the text from the LLM', key='ushqtwkja'):
                analyze_vulnerability_types.clear()
                st.session_state['types'] = analyze_vulnerability_types(vuln_types.index[0], vuln_types.values[0], vuln_types.index.tolist(), _pipe = pipe, language=language, clear_cache=True)
            types_analysis = st.session_state['types']
            st.write(types_analysis)

        # # Remediation Priority Matrix
        # st.header("Remediation Priority Matrix")
        # if all(col in filtered_vulnerabilities.columns for col in [severity_column, 'cvss_score', 'exploit_available']):
        #     fig_remediation = create_severity_impact_bubble(filtered_vulnerabilities, severity_column, 'cvss_score', host_column)
        #     if fig_remediation:
        #         st.plotly_chart(fig_remediation, use_container_width=True, config={'displayModeBar': False})
            
        #     high_priority = filtered_vulnerabilities[(filtered_vulnerabilities['cvss_score'] > 7) & (filtered_vulnerabilities['exploit_available'] == True)]
        #         remediation_analysis = ''
        #         if run_LLM:
        #             remediation_analysis = analyze_remediation_priority(len(high_priority), total_vulns, _pipe = pipe, language=language)
        #     st.markdown(remediation_analysis)
        # else:
        #     st.info("Not enough information available for remediation priority analysis.")

        st.header('WorldCloud analysis')

        df = load_data_word(file_contents)
        all_tags = df['template_name']
        tag_counts = Counter(all_tags)
        
        cloud_img = worldcloud(tag_counts)

        st.image(cloud_img, use_column_width=True)

        # Interactive Vulnerability Explorer
        st.header("Interactive Vulnerability Explorer")
        
        # Add search functionality
        search_term = st.text_input("Search vulnerabilities", "")
        
        # Select columns to display
        selected_columns = st.multiselect(
            "Select columns to display",
            options=filtered_vulnerabilities.columns,
            default=[host_column, severity_column, 'template_name', 'template_url', description_column],
            key="column_selector"
        )
        
        # Filter vulnerabilities based on search term
        if search_term:
            filtered_data = filtered_vulnerabilities[filtered_vulnerabilities.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)]
        else:
            filtered_data = filtered_vulnerabilities
        
        # Display filtered data
        #st.dataframe(filtered_data[selected_columns], height=400, use_container_width=True)
        
        # Add pagination
        items_per_page = st.slider("Items per page", min_value=10, max_value=100, value=50, step=10)
        total_pages = len(filtered_data) // items_per_page + (1 if len(filtered_data) % items_per_page > 0 else 0)
        current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, key=1)
        
        start_idx = (current_page - 1) * items_per_page
        end_idx = start_idx + items_per_page
        df_interactive = filtered_data[selected_columns].iloc[start_idx:end_idx]
        st.dataframe(df_interactive, height=400, use_container_width=True)
        
        st.write(f"Showing {start_idx+1} to {min(end_idx, len(filtered_data))} of {len(filtered_data)} entries")

        # Geolocation of servers
        st.header("Geolocation of company servers", anchor="Geolocation of company servers")
        
        col1, col2 = st.columns([2, 1])
        with col1:

            geo_map, geo_map_1, risk_by_ip = Geolocation_of_servers(file_contents, api_key=ip_token)
            
            # Create and display the Plotly maps
            st.plotly_chart(geo_map, use_container_width=True, config={'displayModeBar': False})
            st.plotly_chart(geo_map_1, use_container_width=True, config={'displayModeBar': False})

            # Display the data in the table
            st.subheader("Risk Scores by IP")

            # Update the selected columns to include the new 'associated_hosts' column
            selected_columns = ['ip', 'associated_hosts', 'country', 'city', 'severity_weight', 'normalized_risk_score']

            # Pagination
            items_per_page = st.slider("Items per page", min_value=10, max_value=100, value=20, step=10)
            total_pages = len(risk_by_ip) // items_per_page + (1 if len(risk_by_ip) % items_per_page > 0 else 0)
            current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, key=2)

            start_idx = (current_page - 1) * items_per_page
            end_idx = start_idx + items_per_page
            df_risk = risk_by_ip[selected_columns].iloc[start_idx:end_idx]

            # Display the selected page of the table
            st.dataframe(df_risk, height=400, use_container_width=True)

            # Show the pagination information
            st.write(f"Showing {start_idx+1} to {min(end_idx, len(risk_by_ip))} of {len(risk_by_ip)} entries")

            countries = dict(risk_by_ip['country'].value_counts())
            cities = dict(risk_by_ip['city'].value_counts())

            # top5 risk
            risk_ = risk_by_ip.nlargest(5, 'normalized_risk_score')
            ip_top5 = risk_['ip'].to_list()
            countries_top5 = risk_['country'].to_list()
            cities_top5 = risk_['city'].to_list()
            hosts_top5 = risk_['associated_hosts'].to_list()
        
        with col2:
            geo_analysis = ''
            if run_LLM:
                if 'geo' not in st.session_state:
                    st.session_state['geo'] = analyze_geolocation(countries, cities, ip_top5, countries_top5, cities_top5, hosts_top5, _pipe = pipe, language=language)

                if st.button(label='Regenerate chapter', help='Hit this button to regenerate the text from the LLM', key='yuqirh'):
                    analyze_geolocation.clear()
                    st.session_state['geo'] = analyze_geolocation(countries, cities, ip_top5, countries_top5, cities_top5, hosts_top5, _pipe = pipe, language=language, clear_cache=True)
                geo_analysis = st.session_state['geo']
                st.write(geo_analysis)
        
        if not os.path.exists('txts/ports_scanning/bash'):
            os.makedirs('txts/ports_scanning/bash')
        
        LLM_comment = ''
        
        if created_at_column:
            # Michele
            st.header("Screenshots")

            df = load_data_screen(file_contents)

            # Filter the dataframe
            filtered_df = df[~df['severity'].isin(['info'])]

            

            if filtered_df.empty:
                # if we have only info we take the fistrs 5
                filtered_df = df[df['severity'] == 'info'].head(10)

            # Get unique hosts
            unique_hosts = filtered_df['host'].unique()

            urls_screenshot = []
            urls_ports = []
            for i in unique_hosts:
                # Rimuovi eventuali protocolli esistenti dall'host
                url = i.split('://')[-1]

                # Controlla se la porta è nella lista delle porte da escludere
                if ':' in url.split('/')[-1]:
                    port = url.split(':')[-1]
                    if port in ports:
                        urls_ports.append(url)
                    else:
                        urls_screenshot.append(url)
                else:
                    urls_screenshot.append(url)
            
            if 'sshots' not in st.session_state:
                st.session_state.sshots = True
            if 'sports' not in st.session_state:
                st.session_state.sports = True

            if st.button('Click here to interrupt the screenshot process', key='p0oqayh'):
                st.session_state.sshots = False

            if st.session_state.sshots:

                screenshots = []
                errors = []
                progress_bar = st.progress(0)
                status_text = st.empty()
                summary = st.empty()

                # setup Selenium WebDriver
                driver = setup_driver()
                max_width, max_height = 1920, 1080

                with st.spinner(text='Screenshots is in progress...'):
                    # Iterate over each unique host and take a screenshot
                    for index, host in enumerate(urls_screenshot):
                        
                        progress = (index + 1) / len(unique_hosts)
                        progress_bar.progress(progress)
                        status_text.text(f'Numbers of scanned sites: {index + 1}/{len(urls_screenshot)}')

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

                            sev_row = filtered_df[filtered_df['host'] == host].head(1)
                            severity = sev_row['severity'].values[0] if not sev_row.empty else "unknown"

                            # salve le immagini in locale nella cartella screenshot
                            image.save(f'txts/screenshots/{host}_{severity}.png', format='PNG')

                    # Resettiamo il puntatore del buffer
                    zip_buffer.seek(0)

                    # Utilizziamo st.download_button per creare un pulsante di download
                    st.download_button(
                        label="Download images",
                        data=zip_buffer,
                        file_name="screenshots.zip",
                        mime="application/zip"
                    )

            st.header("Ports scanning")

            if st.button('Click here to interrupt the ports scanning process', key='qaheu7sjn'):
                st.session_state.sports = False

            if st.session_state.sports:
                with st.spinner(text='Ports scanning is in progress...'):
                    results_port = []
                    if urls_ports:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        summary = st.empty()
                        for index, url in enumerate(urls_ports):
                            progress = (index + 1) / len(unique_hosts)
                            progress_bar.progress(progress)
                            status_text.text(f'Numbers of scanned ports: {index + 1}/{len(urls_ports)}')
                            res, res1 = scan_ip_port(url)
                            result = res + '\n\n' + res1
                            results_port.append(result)
                            st.subheader(url)
                            st.code(result, 'bash')

                        if run_LLM:
                            if 'bash' not in st.session_state:
                                st.session_state['bash'] = analyze_bash_results(urls_ports, results_port, _pipe = pipe, language=language)

                            if st.button(label='Regenerate chapter', help='Hit this button to regenerate the text from the LLM', key='quahy6s'):
                                analyze_bash_results.clear()
                                st.session_state['bash'] = analyze_bash_results(urls_ports, results_port, _pipe = pipe, language=language, clear_cache=True)
                            LLM_comment = st.session_state['bash']
                            st.write(LLM_comment)
                
                for terminal, host in zip(results_port, urls_ports):
                    with open(f'txts/ports_scanning/bash/{host}.txt', 'w') as file:
                        file.write(terminal)
                
                with open(f'txts/ports_scanning/LLM_comment.txt', 'w') as file:
                    file.write(LLM_comment)
        
        # Percorso della cartella principale
        base_dir = "txts"

        # Percorsi delle sottocartelle
        dfs_dir = os.path.join(base_dir, "dfs")
        pngs_dir = os.path.join(base_dir, "pngs")

        # Verifica se la cartella principale 'txts' esiste, altrimenti la crea
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
            #print(f"Cartella '{base_dir}' creata.")
        else:
            #print(f"Cartella '{base_dir}' già esistente.")
            pass

        # Verifica se la sottocartella 'dfs' esiste, altrimenti la crea
        if not os.path.exists(dfs_dir):
            os.makedirs(dfs_dir)
            #print(f"Cartella '{dfs_dir}' creata.")
        else:
            #print(f"Cartella '{dfs_dir}' già esistente.")
            pass

        # Verifica se la sottocartella 'pngs' esiste, altrimenti la crea
        if not os.path.exists(pngs_dir):
            os.makedirs(pngs_dir)
            #print(f"Cartella '{pngs_dir}' creata.")
        else:
            #print(f"Cartella '{pngs_dir}' già esistente.")
            pass

        vuln_defs += "\n\n"
        # trovare il primo titolo e due newline consecutivi
        pattern = r"(# .+\n)(\n)"

        overview_analysis = re.sub(pattern, r'\1\2' + vuln_defs, overview_analysis, count=1)
        
        texts_LLM = {#'Vulnerabilites definition': vuln_defs,
            'Security Posture Overview': overview_analysis,
                'Vulnerability Severity Distribution': severity_analysis,
                'Top 10 Critical Vulnerabilities': top_vuln_analysis,
                'Top 10 Vulnerability Types': types_analysis,
                'Geolocation of company servers': geo_analysis
                }
        
        for i, content in enumerate(texts_LLM.values()):
            with open(f"txts/{i}.txt", "w") as file:
                # Scrivi la stringa nel file
                file.write(content)

        figures = {'Security Posture Overview': [fig_risk_score],
                'Vulnerability Severity Distribution': [fig_severity],
                'Top 10 Vulnerability Types': [fig_types, cloud_img],
                'Geolocation of company servers': [geo_map, geo_map_1]
                }
        
        for i, fig in enumerate(figures.values()):
            for j, f in enumerate(fig, 1):
                save_figure(f, f'txts/pngs/{i}_{j}.png')

        dfs = {
                'Top 10 Critical Vulnerabilities': df_10vuln,
                'Vulnerability Explorer': df_interactive,
                'Geolocation of company servers': df_risk
                }

        for i, content in enumerate(dfs.values()):
            content.to_pickle(f"txts/dfs/{i}.pkl")
        
        def generate_files():
            input_directory = 'txts'  # select
            output_directory = 'latex_template'

            # elimina file tex esistente
            # TODO

            with st.spinner(text='Generation is in progress...'):
                tex_files = generate_tex_zip(input_directory, output_directory)
                pdf_file = generate_pdf(output_directory)
            
            return tex_files, pdf_file
        
        #messages = [{'role': 'user', 'content': 'Write a conclusion based on the previous analysis'}]
        #response = pipe(messages, max_new_tokens=100000000)[0]['generated_text']
        #response_text = response[-1]['content']
        #print(response_text)

        # Export Options
        st.header("Export Dashboard")

        # Genera il report solo se il bottone viene cliccato
        if st.button("Generate Report", key="generate_report"):
            tex_files, pdf_file = generate_files()
            st.session_state['tex_files'] = tex_files
            st.session_state['pdf_file'] = pdf_file
            st.session_state['files_generated'] = True

        # Mostra i pulsanti di download solo dopo la generazione dei file
        if st.session_state.get('files_generated', False):
            col1, col2 = st.columns(2)

            with col1:
                st.download_button(
                    label='Download .tex files ZIP',
                    data=st.session_state['tex_files'],
                    file_name=f'Orizon_Recon_{name_client}_texfiles.zip',
                    mime='application/zip'
                )
            with col2:
                st.download_button(
                    label='Download .pdf file',
                    data=st.session_state['pdf_file'],
                    file_name=f'Orizon_Recon_{name_client}.pdf',
                    mime='application/pdf'
                )

        def format_time(seconds):
            minutes, seconds = divmod(int(seconds), 60)
            if minutes > 0:
                return f"{minutes} min {seconds} sec"
            else:
                return f"{seconds} sec"

        if st.button("Generate technical csv", key='csv'):
            # Ottieni la lista degli ID
            id_list = filtered_vulnerabilities['template_id'].to_list()
            total_iterations = len(id_list)

            # Crea una barra di progresso
            progress_bar = st.progress(0)
            status_text = st.empty()

            series = []
            start_time = time.time()

            for i, id in enumerate(id_list):
                # Calcola il tempo trascorso
                elapsed_time = time.time() - start_time
                
                # Stima il tempo rimanente
                if i > 0:
                    avg_time_per_iteration = elapsed_time / i
                    estimated_time_remaining = avg_time_per_iteration * (total_iterations - i)
                else:
                    estimated_time_remaining = 0

                # Aggiorna la barra di progresso
                progress = (i + 1) / total_iterations
                progress_bar.progress(progress)
                
                # Formatta e aggiorna il testo di stato con la stima del tempo rimanente
                formatted_time = format_time(estimated_time_remaining)
                status_text.text(f'Parsing all vulnerabilities from MITRE database, estimated remaining time: {formatted_time}')
                
                # Esegui l'operazione
                serie = from_id_to_serie(id)
                series.append(serie)

            # Completa la barra di progresso
            progress_bar.progress(1.0)
            status_text.text('Elaborazione completata!')
                
            df_tot_vuln = pd.DataFrame(series)

            # Creiamo un buffer BytesIO
            buffer_csv = BytesIO()

            # Salviamo il DataFrame come CSV nel buffer
            df_tot_vuln.to_csv(buffer_csv, index=False, encoding='utf-8')

            # Riportiamo il cursore all'inizio del buffer
            buffer_csv.seek(0)

            st.download_button(
                label='Download technical annex in .CSV',
                data=buffer_csv,
                file_name=f'technical_{name_client}.csv',
                mime='application/csv'
            )



    else:
        st.info("Please upload a JSON file in the sidebar to begin the analysis.")

if __name__ == "__main__":
    # login
    # name, authentication_status, username = authenticator.login(key='Login', location='main')

    # if authentication_status == False:
    #     st.error('Username/password is incorrect')
    # elif authentication_status == None:
    #     st.warning('Please enter your username and password')
    # elif authentication_status:
    #     # true login
    #     authenticator.logout('Logout', 'main')
    #     st.write(f'Welcome *{name}*')
    #     start = time.time()
    #     main()
    #     end = time.time()

    #     # Calcolo del tempo impiegato
    #     elapsed_time = end - start

    #     minutes = int(elapsed_time // 60)
    #     seconds = int(elapsed_time % 60)

    #     print(f"Running time: {minutes:.2f}:{seconds:.2f}")

    main()