import pandas as pd
import json
import socket
import requests
import plotly.graph_objects as go

from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
)


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

# Resolve hostnames to IPs
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
        ip = row['ip']
        score = row['normalized_risk_score']
        
        lat, lon, country, city = geolocate_ip(ip, '7509bea2d10454')
        if lat and lon:
            latitudes.append(lat)
            longitudes.append(lon)
            texts.append(f"IP: {ip}<br>Location: {city}, {country}<br>Risk Score: {score:.2f}")
            
            # Calculate the color intensity based on the normalized risk score
            color_intensity = int(255 * score / max_score)
            colors.append(f'rgb({color_intensity}, {255 - color_intensity}, 0)')
        else:
            print(f"Could not geolocate IP {ip}")
    
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

    # Add lines connecting the points (optional, depending on your data)
    for i in range(len(latitudes) - 1):
        for j in range(i + 1, len(latitudes)):
            fig.add_trace(go.Scattergeo(
                lon = [longitudes[i], longitudes[j]],
                lat = [latitudes[i], latitudes[j]],
                mode = 'lines',
                line = dict(width=1, color='rgb(0, 128, 255)'),  # Same color as the markers
                opacity=0.5  # Slight transparency for the lines
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

def check_url(driver, host):
    # Try with HTTPS first
    try:
        url = f'https://{host}'
        driver.get(url)
        WebDriverWait(driver, 40).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        return url
    except (TimeoutException, WebDriverException):
        pass  # Fall back to HTTP if HTTPS fails

    # Fall back to HTTP
    try:
        url = f'http://{host}'
        driver.get(url)
        WebDriverWait(driver, 40).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        return url
    except (TimeoutException, WebDriverException):
        return None  # Return None if both fail