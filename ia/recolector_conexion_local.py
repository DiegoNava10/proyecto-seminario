import subprocess
import time
import os
import sys

print("[INFO] Iniciando el protocolo de recolección de conexion local...")

# Obtenemos la ruta del directorio actual
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construimos rutas completas para evitar algun error de path
SENSOR_SCRIPT_PATH = os.path.join(script_dir, "..", "servidor", "sensor.py")
SENSOR_WORKING_DIR = os.path.join(script_dir, "..", "servidor")
OUTPUT_FILE_PATH = os.path.join(SENSOR_WORKING_DIR, "calibracion_local.csv")

# Configuración
DURACION_RECOLECCION_SEGUNDOS = 600 # 10 minutos

# Verificación
if not os.path.exists(SENSOR_SCRIPT_PATH):
    print(f"[ERROR] No se encontró el script del sensor en: {SENSOR_SCRIPT_PATH}")
    exit()

# Recolección
print(f"[AVISO] Se ejecutará el sensor en modo de calibración durante {DURACION_RECOLECCION_SEGUNDOS} segundos.")
print("        Por favor, usa tu computadora con normalidad (navega por internet, etc.).")
print("        No lances ningún ataque de prueba durante este periodo o el analisis se vera afectado.")

command = [sys.executable, SENSOR_SCRIPT_PATH, "--calibrar"]

try:
    # El sensor trabaja desde su propio directorio
    sensor_process = subprocess.Popen(command, cwd=SENSOR_WORKING_DIR)
    
    print("[INFO] Recolectando... (Esto tardará 10 minutos)")
    time.sleep(DURACION_RECOLECCION_SEGUNDOS)

finally:
    print("\n[INFO] Deteniendo el sensor...")
    sensor_process.terminate()
    sensor_process.wait()
    print("[INFO] Recolección de datos de conexion local completada.")
    
    if os.path.exists(OUTPUT_FILE_PATH):
        print(f"[SUCCESS] Los datos de tu red local han sido guardados en '{OUTPUT_FILE_PATH}'.")
    else:
        print("[ERROR] No se creó el archivo de calibración. Asegúrate de ejecutar este script correctamente.")
