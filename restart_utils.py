import subprocess
import sys
import streamlit as st
import os
import shutil


def restart_app():
    # Costruisci il comando per riavviare l'applicazione
    python_path = sys.executable  # Usa lo stesso interprete Python attualmente in uso
    streamlit_file = sys.argv[0]  # Usa il file Python attualmente in esecuzione

    # Avvia un nuovo processo per eseguire Streamlit
    subprocess.Popen([python_path, "-m", "streamlit", "run", streamlit_file])

    # Esci dall'applicazione corrente
    st.stop()

# Termina qualsiasi processo che sta usando la porta 8501
def kill_existing_process(port):
    try:
        # Usa lsof per trovare il PID del processo che sta usando la porta
        result = subprocess.check_output(["lsof", "-t", f"-i:{port}"])
        pid = int(result.strip())
        os.kill(pid, 9)  # Termina il processo con il segnale SIGKILL
        print(f"Terminato processo PID {pid} che utilizzava la porta {port}.")
    except subprocess.CalledProcessError:
        print(f"Nessun processo trovato sulla porta {port}.")

def clear_pycache():
    for root, dirs, files in os.walk('.', topdown=False):
        for name in dirs:
            if name == '__pycache__':
                shutil.rmtree(os.path.join(root, name))

def restart_script():
    os.execv(sys.executable, ['streamlit run'] + sys.argv)