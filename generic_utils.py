import pandas as pd
import json
import socket
from dns import resolver
import requests
import time
import plotly.graph_objects as go
from PIL import Image
import io
import numpy as np
import streamlit as st
import subprocess
import matplotlib.pyplot as plt
from wordcloud import WordCloud
from line_profiler import profile

# Selenium per l'automazione del browser
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import (TimeoutException, WebDriverException)
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

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

def _resolve_hostname(hostname):
    try:
        hostname = hostname.split(':')[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def save_figure(fig, index):
    try:
        if isinstance(fig, go.Figure):  # Caso Plotly
            filename = f"{index}"
            fig.write_image(filename)
            print(f"Plotly figure salvata come {filename}")
        
        elif isinstance(fig, plt.Figure):  # Caso Matplotlib
            filename = f"{index}"
            fig.savefig(filename, dpi=300)
            print(f"Matplotlib figure salvata come {filename}")
        
        elif isinstance(fig, WordCloud):  # Caso WordCloud
            filename = f"{index}"
            fig.to_file(filename)
            print(f"WordCloud salvata come {filename}")
        
        elif isinstance(fig, bytes):  # Caso byte stream (PNG)
            filename = f"{index}"
            with open(filename, "wb") as f:
                f.write(fig)
            print(f"Immagine byte salvata come {filename}")
        
        elif isinstance(fig, Image.Image):  # Caso PIL.Image.Image
            filename = f"{index}"
            fig.save(filename)
            print(f"Immagine PIL salvata come {filename}")
        
        else:  # Tipo non supportato
            print(f"Tipo di figura non supportato per l'elemento in posizione {index}: {type(fig)}")
    
    except Exception as e:
        print(f"Errore nel salvataggio della figura in posizione {index}: {e}, -- {type(fig)}")

@st.cache_data
def resolve_hostname(hostname):
    """
    Resolves the given hostname to its corresponding IP address using a DNS resolver.
    
    The function will attempt to resolve a hostname to its first available IP address
    by querying multiple DNS servers (NextDNS and Google DNS). If the hostname contains 
    a port, the port part is ignored. If the resolution fails, it returns None.
    
    Args:
        hostname (str): The hostname to resolve. Can contain a port, which will be ignored.
    
    Returns:
        str: The first resolved IP address for the hostname, or None if the resolution fails.
    """
    try:
        # If the hostname contains a port, split and use only the hostname part.
        hostname = hostname.split(':')[0]
        
        # Create a DNS resolver instance.
        res = resolver.Resolver()
        
        # Set custom DNS servers: NextDNS servers followed by Google DNS.
        res.nameservers = ['45.90.28.0', '45.90.30.0', '8.8.8.8']
        
        # Query the DNS resolver for the hostname.
        answers = res.resolve(hostname)
        
        # List to store the resolved IP addresses.
        indirizzi = []
        
        # Iterate through all DNS responses and extract IP addresses.
        for rdata in answers:
            indirizzi.append(rdata.address)
        
        # Return the first resolved IP address.
        return indirizzi[0]
    
    except:
        # Return None if there's any exception during the resolution process.
        return None

def run_command_connection(command='', timeout=120):
    """
    Executes a shell command and returns the output.
    
    This function runs a specified shell command with a given timeout. It captures the standard output (stdout)
    and standard error (stderr) of the command execution. If the command succeeds, it returns the output. If the
    command fails, it returns the error message. In case of a timeout, it returns a timeout message.
    
    Args:
        command (str): The shell command to execute. Default is an empty string.
        timeout (int): The time limit (in seconds) for the command to run before being terminated. Default is 120 seconds.
    
    Returns:
        str: The standard output if the command runs successfully, the error message if the command fails, 
        or a timeout message if the execution exceeds the specified timeout.
    """
    try:
        # Run the shell command using subprocess with a specified timeout
        # Capture both stdout and stderr, and set shell=True to run the command in the shell.
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        
        if result.returncode == 0:
            # If the command returns 0, it means the command was successful. Return the stdout as a string.
            return str(result.stdout)
        else:
            # If the command fails (non-zero return code), return the stderr message.
            return str(result.stderr)
    
    except subprocess.TimeoutExpired:
        # If the command exceeds the given timeout, return a timeout message.
        return "connection timed out."

@st.cache_data
def scan_ip_port(host=''):
    """
    Scans a specified IP address and port using various network services, based on the port number.
    Supported ports: ['20', '21', '22', '23', '25', '53', '110', '135', '139', '143', '445', '3389']
    
    This function resolves the hostname, determines the IP address and port, and runs specific 
    network commands based on the port being scanned.
    
    Before using this function, the following tools must be installed:
        - nmap
        - ftp
        - ssh
        - telnet
        - dig
        - netcat (nc)
        - smbclient
        - rdesktop
    
    Args:
        host (str): The target host in the form 'hostname:port'. The port is mandatory.
    
    Returns:
        tuple: 
            - nmap_res (str or None): The output of the nmap scan for the given IP and port.
            - res (str or None): The output of the command executed based on the detected port or a message if the port is unsupported.
    """
    # Initialize variables for storing results
    nmap_res = None
    res = None
    
    try:
        # Attempt to resolve the hostname into an IP address
        ip = resolve_hostname(host)
    except:
        # If hostname resolution fails, return None for both results
        return None, None
    
    # Extract the port number from the host string
    port = host.split(':')[-1]

    nmap = f'nmap -A -p {port} {ip}'  # nmap command for scanning the port (aggressive)
    ftp = f'ftp -a {ip} {port}'       # FTP connection attempt
    ssh = f'ssh -T root@{ip} -p {port}'  # SSH connection attempt
    telnet = f'telnet {ip} {port}'    # Telnet connection attempt
    dig = f'dig @{ip} google.com'     # DNS query using dig
    netcat = f'nc -v {ip} {port}'     # Netcat (nc) connection attempt
    smbclient = f'smbclient -L {ip} -p {port}'  # SMB connection attempt
    remote_desk = f'rdesktop {ip}:{port}'  # Remote desktop connection attempt

    # always run the nmap scan
    nmap_res = f"$ {nmap}\n\n"
    nmap_res += run_command_connection(nmap)
    if 'Note: Host seems down' in nmap_res:
        # retry
        nmap = f'nmap -Pn -A -p {port} {ip}'
        nmap_res = run_command_connection(nmap)

    # Execute different commands based on the port number
    if port in ['20', '21']:
        res = f"$ {ftp}\n\n"
        res += run_command_connection(ftp)
    elif port == '22':
        res = f"$ {ssh}\n\n"
        res += run_command_connection(ssh)
    elif port in ['23', '25', '110', '143']:
        res = f"$ {telnet}\n\n"
        res += run_command_connection(telnet)
    elif port == '53':
        res = f"$ {dig}\n\n"
        res += run_command_connection(dig)
    elif port == '135':
        res = f"$ {netcat}\n\n"
        res += run_command_connection(netcat)
    elif port in ['139', '445']:
        res = f"$ {smbclient}\n\n"
        res += run_command_connection(smbclient)
    elif port == '3389':
        res = f"$ {remote_desk}\n\n"
        res += run_command_connection(remote_desk)
    else:
        res = 'This port is not yet supported'
    
    # Return the results of the nmap scan and the specific service scan
    return nmap_res, res

@st.cache_data
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
def take_screenshot(_driver: webdriver, url, max_width, max_height, timeout=10):
    host = url

    _driver.set_page_load_timeout(timeout) # timeout load pagina
    _driver.set_script_timeout(timeout) # timeout script in a current browsing context

    image, error_type = None, None

    http_url = 'http://' + url
    https_url = 'https://' + url

    # Prova a caricare prima la versione HTTPS, poi HTTP in caso di fallimento
    try:
        _driver.get(https_url)
        url = https_url
    except TimeoutException:
        print("Timeout")
        return host, image, "Timeout raggiunto per HTTPS"
    except WebDriverException:
        try:
            _driver.get(http_url)
            url = http_url
        except TimeoutException:
            print("Timeout")
            return host, image, "Timeout raggiunto per HTTP"
        except WebDriverException:
            return host, image, "URL non valido"
    
    try:
        # Aspetta che il body sia presente
        WebDriverWait(_driver, timeout).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        
        # Aspetta che la pagina sia "pronta"
        WebDriverWait(_driver, timeout).until(
            lambda d: d.execute_script('return document.readyState') == 'complete'
        )
        
        # Scorri la pagina per assicurarsi che tutto sia caricato
        _driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(0.2)  # Breve pausa dopo lo scroll
        _driver.execute_script("window.scrollTo(0, 0);")
        
        # Gestisci eventuali popup
        handle_popups(_driver)
        
        # Imposta la dimensione della finestra
        _driver.set_window_size(1280, 720)
        
        # Aspetta ancora un momento prima di catturare lo screenshot
        time.sleep(0.2)
        
        # Cattura screenshot come byte stream
        screenshot_as_bytes = _driver.get_screenshot_as_png()
        image = Image.open(io.BytesIO(screenshot_as_bytes))
        
        # Ridimensiona l'immagine mantenendo l'aspect ratio
        image.thumbnail((max_width, max_height))
        
        return host, image, error_type
        
    except Exception as e:
        error_type = str(e)
    
    return host, image, error_type