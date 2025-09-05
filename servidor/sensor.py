import time
import requests
import json
from scapy.all import sniff, TCP
from collections import defaultdict, deque

# --- Configuración ---
ANALYSIS_SERVER_URL = "http://127.0.0.1:5000/analizar"
TIME_WINDOW = 2.0
CONNECTION_TIMEOUT = 60.0
CLEANUP_INTERVAL = 10.0

# --- "MEMORIA" AVANZADA DEL SENSOR ---
# 1. Estado de conexiones TCP activas (memoria de trabajo)
connection_states = {}

# 2. Historial a corto plazo (últimos 2 segundos) para cada host de destino
host_history_short_term = defaultdict(deque)

# 3. Historial a largo plazo (últimas 100 conexiones) para cada host de destino
host_history_long_term = defaultdict(lambda: deque(maxlen=100))


def cleanup_short_term_history():
    """Limpia el historial de conexiones más antiguas que TIME_WINDOW."""
    current_time = time.time()
    for ip in list(host_history_short_term.keys()):
        while host_history_short_term[ip] and (current_time - host_history_short_term[ip][0]['timestamp']) > TIME_WINDOW:
            host_history_short_term[ip].popleft()
        if not host_history_short_term[ip]:
            del host_history_short_term[ip]

def cleanup_stale_connections():
    """Revisa y elimina conexiones que han superado el timeout."""
    current_time = time.time()
    stale_keys = [key for key, state in connection_states.items() if (current_time - state['start_time']) > CONNECTION_TIMEOUT]
    for key in stale_keys:
        state = connection_states[key]
        print(f"[TIMEOUT] Conexión {state['src_ip']}:{state['src_port']} ha superado el tiempo. Analizando...")
        state['flags'].add('TIMEOUT')
        assemble_and_send_vector(state)
        del connection_states[key]

def assemble_and_send_vector(conn):
    """Construye el vector completo de 40 características y lo envía."""
    current_time = time.time()
    
    # --- 1. Características Básicas ---
    duration = int(current_time - conn['start_time'])
    protocol_type = conn['protocol']
    service = get_service_name(conn['dst_port'])
    flag = get_flag_name(conn['flags'])
    src_bytes = conn.get('src_bytes', 0)
    dst_bytes = conn.get('dst_bytes', 0)
    land = "1" if conn['src_ip'] == conn['dst_ip'] else "0"

    # --- 2. Características de Tráfico (Ventana de 2 segundos) ---
    cleanup_short_term_history()
    dest_ip = conn['dst_ip']
    history_2s = host_history_short_term[dest_ip]
    count = len(history_2s)
    srv_count = sum(1 for h in history_2s if h['service'] == service)
    
    serror_count = sum(1 for h in history_2s if "R" in h['flags'])
    serror_rate = serror_count / count if count > 0 else 0.0
    srv_serror_rate = sum(1 for h in history_2s if h['service'] == service and "R" in h['flags']) / srv_count if srv_count > 0 else 0.0
    
    rerror_count = sum(1 for h in history_2s if "R" in h['flags']) # Simplificación
    rerror_rate = rerror_count / count if count > 0 else 0.0
    srv_rerror_rate = sum(1 for h in history_2s if h['service'] == service and "R" in h['flags']) / srv_count if srv_count > 0 else 0.0

    same_srv_rate = srv_count / count if count > 0 else 0.0
    diff_srv_rate = len(set(h['service'] for h in history_2s)) / count if count > 0 else 0.0
    
    # --- 3. Características de Tráfico (Ventana de 100 conexiones) ---
    history_100 = host_history_long_term[dest_ip]
    dst_host_count = len(history_100)
    dst_host_srv_count = sum(1 for h in history_100 if h['service'] == service)
    dst_host_same_srv_rate = dst_host_srv_count / dst_host_count if dst_host_count > 0 else 0.0
    
    unique_services_100 = set(h['service'] for h in history_100)
    dst_host_diff_srv_rate = len(unique_services_100) / dst_host_count if dst_host_count > 0 else 0.0

    src_ip = conn['src_ip']
    dst_host_same_src_port_rate = sum(1 for h in history_100 if h['src_ip'] == src_ip and h['src_port'] == conn['src_port']) / dst_host_count if dst_host_count > 0 else 0.0
    
    unique_hosts_100 = set(h['src_ip'] for h in history_100)
    dst_host_srv_diff_host_rate = len(unique_hosts_100) / dst_host_srv_count if dst_host_srv_count > 0 else 0.0

    dst_host_serror_rate = sum(1 for h in history_100 if "R" in h['flags']) / dst_host_count if dst_host_count > 0 else 0.0
    dst_host_srv_serror_rate = sum(1 for h in history_100 if h['service'] == service and "R" in h['flags']) / dst_host_srv_count if dst_host_srv_count > 0 else 0.0
    dst_host_rerror_rate = dst_host_serror_rate # Simplificación
    dst_host_srv_rerror_rate = dst_host_srv_serror_rate # Simplificación

    # --- Ensamblaje del Vector 100% Verídico (con limitaciones de DPI) ---
    vector = [
        str(duration), protocol_type, service, flag, str(src_bytes), str(dst_bytes),
        land, "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        str(count), str(srv_count), f"{serror_rate:.2f}", f"{srv_serror_rate:.2f}",
        f"{rerror_rate:.2f}", f"{srv_rerror_rate:.2f}", f"{same_srv_rate:.2f}", f"{diff_srv_rate:.2f}",
        "0.00", # srv_diff_host_rate (placeholder, requiere más estado)
        str(dst_host_count), str(dst_host_srv_count), f"{dst_host_same_srv_rate:.2f}",
        f"{dst_host_diff_srv_rate:.2f}", f"{dst_host_same_src_port_rate:.2f}",
        f"{dst_host_srv_diff_host_rate:.2f}", f"{dst_host_serror_rate:.2f}",
        f"{dst_host_srv_serror_rate:.2f}", f"{dst_host_rerror_rate:.2f}", f"{dst_host_srv_rerror_rate:.2f}"
    ]
    
    # --- Envío al Servidor de Análisis ---
    payload = {"ip": conn['src_ip'], "data": vector}
    print(f"CONEXIÓN FINALIZADA ({flag}). Enviando vector desde IP {payload['ip']}...")
    try:
        requests.post(ANALYSIS_SERVER_URL, json=payload)
    except requests.exceptions.RequestException:
        pass # Ignorar errores de conexión para no detener el sensor

def process_packet(packet):
    """Procesa cada paquete y actualiza las memorias de estado."""
    if not packet.haslayer(TCP): return

    src_ip, dst_ip = packet[0][1].src, packet[0][1].dst
    src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    flags = str(packet[TCP].flags)
    conn_key = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))

    if 'S' in flags and 'A' not in flags and conn_key not in connection_states:
        connection_states[conn_key] = {
            'start_time': time.time(), 'protocol': 'tcp', 'src_ip': src_ip, 
            'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port,
            'flags': set(flags), 'src_bytes': 0, 'dst_bytes': 0
        }
        return

    if conn_key in connection_states:
        conn = connection_states[conn_key]
        conn['flags'].update(flags)
        payload_len = len(packet[TCP].payload)
        if src_ip == conn['src_ip']:
            conn['src_bytes'] += payload_len
        else:
            conn['dst_bytes'] += payload_len
        
        if 'F' in flags or 'R' in flags:
            history_entry = {
                'timestamp': time.time(), 'service': get_service_name(conn['dst_port']),
                'flags': conn['flags'], 'src_ip': src_ip, 'src_port': src_port
            }
            host_history_short_term[conn['dst_ip']].append(history_entry)
            host_history_long_term[conn['dst_ip']].append(history_entry)
            
            assemble_and_send_vector(conn)
            del connection_states[conn_key]

# --- Funciones de Ayuda ---
def get_service_name(port):
    services = {80: "http", 443: "https", 21: "ftp", 22: "ssh", 25: "smtp"}
    return services.get(port, "other")

def get_flag_name(flags_set):
    if 'TIMEOUT' in flags_set: return "RSTO"
    if 'R' in flags_set: return "REJ"
    if 'S' in flags_set and 'F' in flags_set: return "SF"
    if 'S' in flags_set: return "S0"
    return "OTH"

# --- Bucle Principal del Sensor ---
if __name__ == "__main__":
    print("[INFO] Sensor Profesional iniciado. Monitoreando conexiones...")
    while True:
        try:
            sniff(prn=process_packet, store=0, filter="tcp", timeout=CLEANUP_INTERVAL)
            cleanup_stale_connections()
        except Exception as e:
            print(f"[ERROR] Error fatal en el bucle principal: {e}")
            time.sleep(5)

