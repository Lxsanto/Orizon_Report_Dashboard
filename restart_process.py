import subprocess

# Esegui lo script per terminare il processo corrente
subprocess.run(["python", "kill_process.py"])

# Esegui lo script per avviare il nuovo processo Streamlit
subprocess.run(["python", "start_streamlit.py"])
