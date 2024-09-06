import os
import subprocess
import streamlit as st

file = 'Orizon_Report_Dashboard.py'

python = '/home/utente/miniconda3/envs/orizon/bin/python'

os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"
os.environ["STREAMLIT_SERVER_PORT"] = "8501"
os.environ["STREAMLIT_SERVER_ADDRESS"] = "0.0.0.0"

# Costruisci il comando da eseguire
command = [python, "-m", "streamlit", "run", file]

subprocess.run(command)