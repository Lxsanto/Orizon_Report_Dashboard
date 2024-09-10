import subprocess
import os
import shutil


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
    """Riavvia lo script Streamlit corrente."""
    subprocess.run(['streamlit', 'run', 'Orizon_Report_Dashboard.py'])