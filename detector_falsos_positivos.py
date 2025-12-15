import time
import pandas as pd
import numpy as np
from joblib import load
import os
import sys
import subprocess 

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

from bd_mongoDB.conexion_db import (
    obtener_sospechosos_pendientes,
    mover_a_whitelist_confirmada,
    mover_a_final_blacklist_y_confirmar
)

INTERVALO_REVISION_SEGUNDOS = 30 #Cada cuanto tiempo revisa la bd
RUTA_IA = os.path.join(script_dir, "ia")

print("==================================================")
print("   INICIANDO IA 2   ")
print("==================================================")

#CARGA DEL MODELO ESPECIALISTA Random Forest
try:
    print("[INICIO] Cargando artefactos del modelo especialista...")
    modelo_especialista = load(os.path.join(RUTA_IA, "modelo_ids_moderno.joblib"))
    scaler_especialista = load(os.path.join(RUTA_IA, "scaler_moderno.joblib"))
    feature_names_especialista = load(os.path.join(RUTA_IA, "features_moderno.joblib"))
    print(f"[OK] Modelo especialista cargado. Espera {len(feature_names_especialista)} características.")
except FileNotFoundError as e:
    print(f"[ERROR FATAL] Faltan archivos del modelo especialista en '{RUTA_IA}'.")
    print("Asegúrate de haber ejecutado 'entrenar_modelo.py'.")
    exit()

#Set para llevar control de IPs ya bloqueadas en esta sesión y no spammear iptables
ips_bloqueadas_sesion = set()

def bloquear_ip_sistema(ip_address):
    """Ejecuta el comando NETSH de Windows para bloquear la IP entrante."""
    if ip_address in ips_bloqueadas_sesion:
        print(f"   [INFO] La IP {ip_address} ya estaba bloqueada en esta sesión.")
        return True
    
    nombre_regla = f"BLOQUEO_IDS_{ip_address}"
    comando = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={nombre_regla}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}"
    ]

    try:
        print(f"   [FIREWALL] Ejecutando bloqueo para {ip_address}...")
        # Ejecutamos el comando
        resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
        print(f"   [BANNED] ¡IP {ip_address} BLOQUEADA EXITOSAMENTE EN EL SISTEMA!")
        ips_bloqueadas_sesion.add(ip_address)
        return True
    except subprocess.CalledProcessError as e:
        print(f"   [ERROR FIREWALL] Falló el bloqueo de {ip_address}.")
        print(f"   Error output: {e.stdout}")
        return False
    except FileNotFoundError:
        print("   [ERROR FIREWALL] No se encontró el comando 'iptables'. ¿Estás en Linux?")
        return False

def iniciar_ciclo_revision():
    print(f"[INFO] Entrando en bucle de revisión (cada {INTERVALO_REVISION_SEGUNDOS}s)...")
    while True:
        try:
            sospechosos = obtener_sospechosos_pendientes()
            
            if not sospechosos:
                print(f"[ESPERA] No hay sospechosos pendientes en blacklist. Durmiendo...")
            else:
                print(f"\n[TRABAJO] Se encontraron {len(sospechosos)} casos para revisar.")
                
                for doc in sospechosos:
                    id_doc = doc["_id"]
                    ip = doc["ip_origen"]
                    vector = doc["vector_caracteristicas"]
                    print(f"   -> Analizando IP: {ip}...")

                    #Preprocesamiento para la Segunda IA
                    try:
                        vector_df = pd.DataFrame([vector], columns=feature_names_especialista)
                        vector_scaled = scaler_especialista.transform(vector_df)
                        
                        prediccion = modelo_especialista.predict(vector_scaled)[0]
                        resultado_final = "Benigno" if prediccion == 0 else "Ataque"
                        
                        print(f"      VEREDICTO SEGUNDA IA: {resultado_final.upper()}")

                        if resultado_final == "Benigno":
                            #Era un falso positivo de la primera IA
                            mover_a_whitelist_confirmada(id_doc, doc)
                        else:
                            #Ataque confirmado. Proceder al bloqueo.
                            bloqueado_ok = bloquear_ip_sistema(ip)
                            if bloqueado_ok:
                                mover_a_final_blacklist_y_confirmar(id_doc, doc)

                    except ValueError as ve:
                        print(f"   [ERROR DATA] El vector de la BD no coincide con el modelo especialista: {ve}")
                    except Exception as e:
                        print(f"   [ERROR PROCESO] Falló el análisis de este caso: {e}")

            time.sleep(INTERVALO_REVISION_SEGUNDOS)

        except KeyboardInterrupt:
            print("\n[SALIR] Deteniendo el analista.")
            break
        except Exception as e:
            print(f"[ERROR CRÍTICO] Error en el bucle principal: {e}")
            time.sleep(10)

if __name__ == "__main__":
    iniciar_ciclo_revision()