import time
import requests
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading
from joblib import load
import os
import sys
import json
import base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Argumentos para calibracion desde terminal
MODO_CALIBRACION = "--calibrar" in sys.argv
# Configuración
ANALYSIS_SERVER_URL = "https://127.0.0.1:5000/analizar_moderno"
FLOW_TIMEOUT = 60
CALIBRATION_FILE = "calibracion_local.csv"


#Carga de llaves criptográficas
try:
    with open("aes_secret.key", "rb") as f:
        AES_KEY = f.read()
    with open("sensor_private.pem", "rb") as f:
        PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)
    print("[SEGURIDAD] Llaves criptográficas cargadas correctamente.")
except FileNotFoundError:
    if not MODO_CALIBRACION:
        print("[ERROR] Faltan las llaves (aes_secret.key o sensor_private.pem). Ejecuta generar_claves_seguridad.py")
        exit()

# Memoria del Sensor
active_flows = {}

# Carga de la Lista de Características
try:
    FEATURE_NAMES = load("../ia/features_moderno.joblib")
    print(f"[INFO] Sensor iniciado. El 'contrato' de {len(FEATURE_NAMES)} características ha sido cargado.")
except FileNotFoundError:
    print("[ERROR] No se encontró 'features_moderno.joblib'. Ejecuta el script de entrenamiento primero.")
    exit()

def encrypt_and_sign(payload_dict):
    """Cifra los datos con AES y firma el paquete con RSA"""
    #Convertir datos a bytes
    data_bytes = json.dumps(payload_dict).encode('utf-8')
    
    #Cifra con AES
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
    
    #Firmar el cifrado firma digital
    signature = PRIVATE_KEY.sign(
        ciphertext,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }

def finalize_flow(flow_key, reason="timeout"):
    if flow_key not in active_flows: return
    flow = active_flows.pop(flow_key)

    # Cálculo de Características
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
    
    #Logica de envio o guardado
    if MODO_CALIBRACION:
        df_vector = pd.DataFrame([vector], columns=FEATURE_NAMES)
        header = not os.path.exists(CALIBRATION_FILE)
        df_vector.to_csv(CALIBRATION_FILE, mode='a', header=header, index=False)
        print(f"  -> Vector de tráfico local guardado para calibración...", end='\r')
    else:
        payload = {"ip": flow_key[0][0], "data": vector}
        payload_secure = encrypt_and_sign(payload)
        print(f"FLUJO FINALIZADO ({reason}). Enviando vector cifrado de IP {flow_key[0][0]}...")
        try:
            response = requests.post(ANALYSIS_SERVER_URL, json=payload_secure, verify=False)
            if response.status_code == 200:
                result = response.json()
                if result.get('resultado') == 'Ataque':
                    print(f"  -> ALERTA: POSIBLE ATAQUE DETECTADO DESDE {flow_key[0][0]} ")
                else:
                    print(f"  -> Resultado: {result.get('resultado', 'error')}")
            else:
                print(f"  -> Error del servidor: {response.status_code}")
        except requests.exceptions.RequestException:
            pass

def process_packet(packet):
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
        print("[AVISO] Sensor en MODO DE CALIBRACIÓN. Recolectando tráfico local ...")
        if os.path.exists(CALIBRATION_FILE):
            os.remove(CALIBRATION_FILE)
            print(f"[INFO] Archivo de calibración anterior '{CALIBRATION_FILE}' eliminado.")
    else:
        print("[INFO] Sensor en MODO DE DETECCIÓN. Monitoreando amenazas...")

    timeout_thread = threading.Thread(target=check_flow_timeouts, daemon=True)
    timeout_thread.start()
    sniff(prn=process_packet, store=0)

