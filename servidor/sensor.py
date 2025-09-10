import time
import requests
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading
from joblib import load
import os
import sys # Importamos sys para leer los argumentos de la línea de comandos

# --- El modo ahora se controla por argumentos, no editando el archivo ---
MODO_CALIBRACION = "--calibrar" in sys.argv
# ---------------------------------------------------------------------

# --- Configuración ---
ANALYSIS_SERVER_URL = "http://127.0.0.1:5000/analizar_moderno"
FLOW_TIMEOUT = 60
CALIBRATION_FILE = "calibracion_local.csv"

# --- "Memoria" del Sensor ---
active_flows = {}

# --- Carga de la Lista de Características ---
try:
    FEATURE_NAMES = load("../ia/features_moderno.joblib")
    print(f"[INFO] Sensor iniciado. El 'contrato' de {len(FEATURE_NAMES)} características ha sido cargado.")
except FileNotFoundError:
    print("[ERROR] No se encontró 'features_moderno.joblib'. Ejecuta el script de entrenamiento primero.")
    exit()

def finalize_flow(flow_key, reason="timeout"):
    if flow_key not in active_flows: return
    flow = active_flows.pop(flow_key)

    # --- Cálculo de Características ---
    # (Esta lógica no cambia)
    flow['Flow Duration'] = max(1, (flow['last_seen'] - flow['start_time']) * 1_000_000)
    flow['Tot Fwd Pkts'] = len(flow['fwd_pkt_lengths'])
    flow['Tot Bwd Pkts'] = len(flow['bwd_pkt_lengths'])
    flow['TotLen Fwd Pkts'] = sum(flow['fwd_pkt_lengths'])
    flow['TotLen Bwd Pkts'] = sum(flow['bwd_pkt_lengths'])
    if flow['fwd_pkt_lengths']:
        flow['Fwd Pkt Len Max'] = float(max(flow['fwd_pkt_lengths']))
        flow['Fwd Pkt Len Min'] = float(min(flow['fwd_pkt_lengths']))
        flow['Fwd Pkt Len Mean'] = float(np.mean(flow['fwd_pkt_lengths']))
        flow['Fwd Pkt Len Std'] = float(np.std(flow['fwd_pkt_lengths']))
    all_times = sorted(flow['fwd_timestamps'] + flow['bwd_timestamps'])
    iat = np.diff(all_times)
    if len(iat) > 0:
        flow['Flow IAT Mean'] = float(np.mean(iat) * 1_000_000)
        flow['Flow IAT Std'] = float(np.std(iat) * 1_000_000)
        flow['Flow IAT Max'] = float(np.max(iat) * 1_000_000)
        flow['Flow IAT Min'] = float(np.min(iat) * 1_000_000)
    duration_sec = flow['Flow Duration'] / 1_000_000
    flow['Fwd Pkts/s'] = flow['Tot Fwd Pkts'] / duration_sec
    flow['Bwd Pkts/s'] = flow['Tot Bwd Pkts'] / duration_sec
    
    vector = [flow.get(feature.strip(), 0) for feature in FEATURE_NAMES]
    
    # --- Decisión de Modo ---
    if MODO_CALIBRACION:
        df_vector = pd.DataFrame([vector], columns=FEATURE_NAMES)
        header = not os.path.exists(CALIBRATION_FILE)
        df_vector.to_csv(CALIBRATION_FILE, mode='a', header=header, index=False)
        print(f"  -> Vector de tráfico local guardado para calibración...", end='\r')
    else:
        payload = {"ip": flow_key[0][0], "data": vector}
        print(f"FLUJO FINALIZADO ({reason}). Enviando vector de IP {flow_key[0][0]}...")
        try:
            response = requests.post(ANALYSIS_SERVER_URL, json=payload)
            if response.status_code == 200:
                result = response.json()
                if result.get('resultado') == 'Ataque':
                    print(f"  -> 🚨 ALERTA: POSIBLE ATAQUE DETECTADO DESDE {flow_key[0][0]} 🚨")
                else:
                    print(f"  -> Resultado: {result.get('resultado', 'error')}")
            else:
                print(f"  -> Error del servidor: {response.status_code}")
        except requests.exceptions.RequestException:
            pass

def process_packet(packet):
    # (Esta lógica no cambia)
    if not packet.haslayer(IP): return
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    proto = packet[IP].proto
    if packet.haslayer(TCP): src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP): src_port, dst_port = packet[UDP].sport, packet[UDP].dport
    else: src_port, dst_port = 0, 0
    flow_key = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port)))) + (proto,)
    if flow_key not in active_flows:
        active_flows[flow_key] = defaultdict(float, {
            'start_time': packet.time, 'fwd_pkt_lengths': [], 'bwd_pkt_lengths': [],
            'fwd_timestamps': [], 'bwd_timestamps': [], 'Dst Port': dst_port, 'Protocol': proto
        })
    flow = active_flows[flow_key]
    flow['last_seen'] = packet.time
    pkt_len = len(packet[IP])
    if src_ip == flow_key[0][0]:
        flow['fwd_pkt_lengths'].append(pkt_len)
        flow['fwd_timestamps'].append(packet.time)
    else:
        flow['bwd_pkt_lengths'].append(pkt_len)
        flow['bwd_timestamps'].append(packet.time)
    if packet.haslayer(TCP) and (packet[TCP].flags.F or packet[TCP].flags.R):
        finalize_flow(flow_key, reason="TCP FIN/RST")

def check_flow_timeouts():
    while True:
        time.sleep(10)
        current_time = time.time()
        for key, flow in list(active_flows.items()):
            if current_time - flow['last_seen'] > FLOW_TIMEOUT:
                finalize_flow(key, reason="timeout")

if __name__ == "__main__":
    if MODO_CALIBRACION:
        print("[AVISO] Sensor en MODO DE CALIBRACIÓN. Recolectando tráfico local benigno...")
        if os.path.exists(CALIBRATION_FILE):
            os.remove(CALIBRATION_FILE)
            print(f"[INFO] Archivo de calibración anterior '{CALIBRATION_FILE}' eliminado.")
    else:
        print("[INFO] Sensor en MODO DE DETECCIÓN. Monitoreando amenazas...")

    timeout_thread = threading.Thread(target=check_flow_timeouts, daemon=True)
    timeout_thread.start()
    sniff(prn=process_packet, store=0)

