import pandas as pd
import json
import socket
import requests
import os
import time
from datetime import datetime
import plotly.graph_objects as go
from PIL import Image
import io
import numpy as np
import streamlit as st

# Selenium per l'automazione del browser
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import (NoSuchWindowException, TimeoutException, WebDriverException)
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# porte da escludere per le screenshots
ports = ['22', '23', '25', '53', '5900']

def setup_driver():
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--start-maximized')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--disable-notifications')
    
    # Aggiungi queste opzioni per ignorare gli errori dei certificati
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    
    # Imposta l'accettazione dei certificati non sicuri
    options.set_capability('acceptInsecureCerts', True)
    
    options.set_capability("pageLoadStrategy", "normal")
    
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    
    return driver

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

def load_data_geo(file):
    if file is not None:
        data = json.loads(file)
    return pd.DataFrame(data)

def load_data_screen(file):
    if file is not None:
        data = json.loads(file)
    return pd.DataFrame(data)

def load_data_word(file):
        if file is not None:
            data = json.loads(file)
        return pd.DataFrame(data)

def resolve_hostname(hostname):
    try:
        hostname = hostname.split(':')[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def geolocate_ip(ip, token):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={token}")
        data = response.json()
        if 'loc' in data:
            lat, lon = map(float, data['loc'].split(','))
            return lat, lon, data.get('country', ''), data.get('city', '')
        else:
            print(f"Failed to geolocate IP {ip}, Response: {data}")
            print(response.text)
            print()
            return None, None, None, None
    except requests.exceptions.RequestException as e:
        print(f"Error geolocating IP {ip}: {e}")
        return None, None, None, None

# Create the plotly map function
def create_plotly_map(risk_by_ip):
    # Group by location and get the maximum risk score for each location
    location_risk = risk_by_ip.groupby(['latitude', 'longitude', 'country', 'city'])['normalized_risk_score'].max().reset_index()

    latitudes = location_risk['latitude']
    longitudes = location_risk['longitude']
    texts = []
    sizes = []

    max_score = location_risk['normalized_risk_score'].max()
    min_score = location_risk['normalized_risk_score'].min()

    for index, row in location_risk.iterrows():
        country = row['country']
        city = row['city']
        score = row['normalized_risk_score']
        
        texts.append(f"Location: {city}, {country}<br>Max Risk Score: {score:.2f}")
        
        # Calculate the size based on the normalized risk score
        # Adjust the range (5, 30) to your preferred min and max sizes
        size = 5 + (score - min_score) / (max_score - min_score) * 25

        sizes.append(size)
    
    # Create the scattergeo plot with markers
    fig = go.Figure(go.Scattergeo(
        lon = longitudes,
        lat = latitudes,
        text = texts,
        mode = 'markers',
        marker = dict(
            size = sizes,
            color = 'rgba(229, 98, 94, 0.7)',  
            symbol = 'circle',
            line = dict(width=1, color='rgba(229, 98, 94, 0.7)')
        )
    ))

    # Update the layout of the map
    fig.update_layout(
        title = 'Geolocation of Company Servers (Aggregated by Location)',
        showlegend = False,
        geo = dict(
            scope = 'world',
            showland = True,
            landcolor = "rgb(230, 230, 230)",
            countrycolor = "rgb(204, 204, 204)",
            coastlinecolor = "rgb(204, 204, 204)",
            projection_type='natural earth',
        ),
        margin=dict(l=0, r=0, t=50, b=0),
        paper_bgcolor='white',
    )

    return fig

def create_country_bubble_plot(risk_by_ip):
    # Define color palette
    color_palette = {
        "kelly_green": "#4AC300",
        "mariana_blue": "#002430",
        "burnt_red": "#E5625E",
        "dodger_blue": "#2191FB",
        "dawn_mist": "#DBE2E9",
        "simple_white": "#FFFFFF",
        "sunglow": "#FFC857"
    }

    # Group by country and count IPs
    country_data = risk_by_ip.groupby('country').agg({
        'ip': 'count',
        'normalized_risk_score': 'mean'
    }).reset_index()

    # Calculate bubble sizes
    max_size = 150  # Maximum bubble size
    min_size = 20   # Minimum bubble size
    country_data['bubble_size'] = (country_data['ip'] - country_data['ip'].min()) / (country_data['ip'].max() - country_data['ip'].min()) * (max_size - min_size) + min_size

    # Improved bubble positioning
    def generate_positions(n, k=0.5):
        positions = []
        phi = (1 + 5**0.5) / 2  # Golden ratio
        for i in range(n):
            r = i**0.5 / n**0.5
            theta = 2 * np.pi * i / phi**2
            x = r * np.cos(theta)
            y = r * np.sin(theta)
            positions.append((k*x, k*y))
        return positions

    positions = generate_positions(len(country_data))
    x, y = zip(*positions)

    # Create custom colorscale
    colorscale = [
        [0, color_palette["dawn_mist"]],
        [0.25, color_palette["kelly_green"]],
        [0.5, color_palette["dodger_blue"]],
        [0.75, color_palette["sunglow"]],
        [1, color_palette["burnt_red"]]
    ]

    # Create bubbles
    bubbles = go.Scatter(
        x=x,
        y=y,
        mode='markers+text',
        text=country_data['country'],
        marker=dict(
            size=country_data['bubble_size'],
            color=country_data['normalized_risk_score'],
            colorscale=colorscale,
            line=dict(width=2, color=color_palette["simple_white"])
        ),
        textfont=dict(size=10, color=color_palette["mariana_blue"]),
        hoverinfo='text',
        hovertext=[f"{country}<br>IPs: {ip_count}<br>Avg Risk: {risk:.2f}" 
                   for country, ip_count, risk in zip(country_data['country'], country_data['ip'], country_data['normalized_risk_score'])],
        showlegend=False
    )

    # Create legend traces with correct colors
    legend_traces = []
    risk_levels = ["Very Low", "Low", "Medium", "High", "Very High"]
    for i, level in enumerate(risk_levels):
        color = colorscale[i][1]
        legend_traces.append(go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=12, color=color, symbol='circle'),
            name=f"{level} Risk",
            legendgroup=level,
            showlegend=True
        ))

    # Layout
    layout = go.Layout(
        title=dict(
            text='Country IP Distribution by Risk Level',
            font=dict(size=24, color=color_palette["mariana_blue"])
        ),
        showlegend=True,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 1]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 1]),
        hovermode='closest',
        paper_bgcolor=color_palette["simple_white"],
        plot_bgcolor=color_palette["simple_white"],
        legend=dict(
            itemsizing='constant',
            title=dict(text='Risk Levels', font=dict(size=16, color=color_palette["mariana_blue"])),
            font=dict(size=14),
            yanchor="top",
            y=0.99,
            xanchor="left",
            x=0.01,
            bgcolor='rgba(255,255,255,0.8)',
            bordercolor='rgba(0,0,0,0)',
            orientation='h'
        ),
        margin=dict(l=20, r=20, t=50, b=20)
    )

    # Create figure
    fig = go.Figure(data=[bubbles] + legend_traces, layout=layout)

    return fig


def check_url(driver, url):
    # Rimuovi eventuali protocolli esistenti
    url = url.split('://')[-1]
    
    if ':' in url.split('/')[-1]:  # Se c'è una porta specificata
        http_url = 'http://' + url
        https_url = 'https://' + url
    else:
        # Se non c'è una porta specificata, usiamo le porte standard
        http_url = 'http://' + url
        https_url = 'https://' + url

    try:
        driver.get(https_url)
        return https_url
    except WebDriverException:
        try:
            driver.get(http_url)
            return http_url
        except WebDriverException:
            return None

def handle_popups(driver):
    # Implementa qui la logica per gestire i popup comuni
    # Esempio:
    try:
        WebDriverWait(driver, 3).until(EC.element_to_be_clickable((By.ID, "cookie-accept"))).click()
    except:
        pass
    # Aggiungi altri gestori di popup se necessario

def is_image_blank(image):
    # Controlla se l'immagine è completamente bianca o quasi
    extrema = image.convert("L").getextrema()
    return extrema == (255, 255) or (extrema[1] - extrema[0]) < 10

@st.cache_data
def take_screenshot(_driver, host, max_width, max_height, max_retries=3):

    image, error_type = None, None

    _start_time = time.time()
    url = check_url(_driver, host)
    
    # controlla se url valido
    if not url:
        return host, image, "URL non valido"
    
    # Controlla se la porta è nella lista delle porte da escludere
    if ':' in host:
        port = host.split(':')[-1]
        if port in ports:
            return host, image, f'porta non supportata per servizi web: {port}'

    try:
        # Naviga alla pagina
        _driver.get(url)

        # Aspetta che il body sia presente
        WebDriverWait(_driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        
        # Aspetta che la pagina sia "pronta"
        WebDriverWait(_driver, 5).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        
        # Scorri la pagina per assicurarsi che tutto sia caricato
        _driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(0.5)  # Breve pausa dopo lo scroll
        _driver.execute_script("window.scrollTo(0, 0);")
        
        # Gestisci eventuali popup
        handle_popups(_driver)
        
        # Imposta la dimensione della finestra
        _driver.set_window_size(1920, 1080)
        
        # Aspetta ancora un momento prima di catturare lo screenshot
        time.sleep(0.5)
        
        # Cattura screenshot come byte stream
        screenshot_as_bytes = _driver.get_screenshot_as_png()
        image = Image.open(io.BytesIO(screenshot_as_bytes))

        # Verifica che l'immagine non sia completamente bianca
        if is_image_blank(image):
            print(f"Screenshot bianco rilevato per {host}")
            error_type = "Pagina bianca"

            # Debug: Salva lo screenshot bianco
            debug_dir = "debug_screenshots"
            os.makedirs(debug_dir, exist_ok=True)
            debug_filename = os.path.join(debug_dir, f"blank_{host.replace('://', '_')}_{int(time.time())}.png")
            image.save(debug_filename)
            
            # Debug: Ottieni informazioni aggiuntive sulla pagina
            page_title = _driver.title
            page_url = _driver.current_url
            
            print(f"Debug info per {host}:")
            print(f"  - URL finale: {page_url}")
            print(f"  - Titolo della pagina: {page_title}")
            print(f"  - Screenshot bianco salvato come: {debug_filename}")
        
        # Ridimensiona l'immagine mantenendo l'aspect ratio
        image.thumbnail((max_width, max_height))

        _end_time = time.time()
        execution_time = _end_time - _start_time
        #print(f"Tempo totale: {execution_time:.2f} secondi")
        
        return host, image, error_type
        
    # manage exceptions
    except TimeoutException:
        error_type = "Timeout"
    except WebDriverException as e:
        if "ERR_CONNECTION_REFUSED" in str(e):
            error_type = "Connessione rifiutata"
        elif "ERR_SSL_PROTOCOL_ERROR" in str(e):
            error_type = "Errore SSL"
        else:
            error_type = "Errore generico"

    # Cattura uno screenshot dell'errore se possibile
    try:
        error_screenshot = _driver.get_screenshot_as_png()
        image = Image.open(io.BytesIO(error_screenshot))
    except:
        pass

    _end_time = time.time()
    execution_time = _end_time - _start_time
    #print(f"Tempo totale: {execution_time:.2f} secondi")
    
    return host, image, error_type