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

def create_plotly_map(risk_by_ip):
    latitudes = []
    longitudes = []
    texts = []
    colors = []

    max_score = risk_by_ip['normalized_risk_score'].max()

    for index, row in risk_by_ip.iterrows():
        lat = row['latitude']
        lon = row['longitude']
        country = row['country']
        city = row['city']
        score = row['normalized_risk_score']
        
        latitudes.append(lat)
        longitudes.append(lon)
        texts.append(f"IP: {row['ip']}<br>Location: {city}, {country}<br>Risk Score: {score:.2f}")
            
        # Calculate the color intensity based on the normalized risk score
        color_intensity = int(255 * score / max_score)
        colors.append(f'rgb({color_intensity}, {255 - color_intensity}, 0)')
    
    # Create the scattergeo plot with markers
    fig = go.Figure(go.Scattergeo(
        lon = longitudes,
        lat = latitudes,
        text = texts,
        mode = 'markers',  # Only show text on hover
        marker = dict(
            size = 10,
            color = colors,  # Color based on risk score
            symbol = 'circle',
            line = dict(width=2, color='rgb(0, 0, 0)')  # Black outline for contrast
        )
    ))

    # Update the layout of the map
    fig.update_layout(
        title = 'Geolocation of Company Servers',
        showlegend = False,
        geo = dict(
            scope = 'world',
            showland = True,
            landcolor = "rgb(230, 230, 230)",  # Light gray for the land
            countrycolor = "rgb(204, 204, 204)",  # Light gray for country borders
            coastlinecolor = "rgb(204, 204, 204)",  # Light gray for coastlines
            projection_type='natural earth',  # Natural earth projection for a realistic look
        ),
        margin=dict(l=0, r=0, t=50, b=0),  # Adjust margins for a cleaner look
        paper_bgcolor='white',  # White background for the entire figure
    )

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

def take_screenshot(driver, host, max_width, max_height, max_retries=3):

    image, error_type = None, None

    _start_time = time.time()
    url = check_url(driver, host)
    
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
        driver.get(url)

        # Aspetta che il body sia presente
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        
        # Aspetta che la pagina sia "pronta"
        WebDriverWait(driver, 5).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        
        # Scorri la pagina per assicurarsi che tutto sia caricato
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(0.5)  # Breve pausa dopo lo scroll
        driver.execute_script("window.scrollTo(0, 0);")
        
        # Gestisci eventuali popup
        handle_popups(driver)
        
        # Imposta la dimensione della finestra
        driver.set_window_size(1920, 1080)
        
        # Aspetta ancora un momento prima di catturare lo screenshot
        time.sleep(0.5)
        
        # Cattura screenshot come byte stream
        screenshot_as_bytes = driver.get_screenshot_as_png()
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
            page_title = driver.title
            page_url = driver.current_url
            
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
        error_screenshot = driver.get_screenshot_as_png()
        image = Image.open(io.BytesIO(error_screenshot))
    except:
        pass

    _end_time = time.time()
    execution_time = _end_time - _start_time
    #print(f"Tempo totale: {execution_time:.2f} secondi")
    
    return host, image, error_type