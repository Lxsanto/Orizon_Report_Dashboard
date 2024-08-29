import os
import subprocess

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

# Termina il processo sulla porta 8501
kill_existing_process(8501)