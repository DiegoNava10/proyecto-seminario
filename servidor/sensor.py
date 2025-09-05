import time
import requests
import json
from scapy.all import sniff, TCP, UDP, ICMP
from collections import defaultdict, deque

# --- Configuración ---
ANALYSIS_SERVER_URL = "http://127.0.0.1:5000/analizar"
TIME_WINDOW = 2.0  # Ventana de tiempo para características de tráfico
# --- NUEVO: Configuración de Timeout ---
CONNECTION_TIMEOUT = 60.0 # Segundos antes de considerar una conexión "muerta"
CLEANUP_INTERVAL = 10.0   # Cada cuántos segundos revisamos si hay conexiones muertas

# --- "Memoria" del Sensor ---
connection_states = {}
host_history = defaultdict(deque)


def cleanup_history():
    """Limpia el historial de conexiones más antiguas que TIME_WINDOW."""
    current_time = time.time()
    for ip in list(host_history.keys()):
        while host_history[ip] and (current_time - host_history[ip][0][0]) > TIME_WINDOW:
            host_history[ip].popleft()
        if not host_history[ip]:
            del host_history[ip]

# --- NUEVO: Función para limpiar conexiones inactivas ---
def cleanup_stale_connections():
    """Revisa todas las conexiones activas y elimina las que han superado el timeout."""
    current_time = time.time()
    # Se itera sobre una copia para poder modificar el diccionario original
    stale_keys = []
    for key, state in connection_states.items():
        if (current_time - state['start_time']) > CONNECTION_TIMEOUT:
            print(f"[TIMEOUT] Conexión {state['src_ip']}:{state['src_port']} ha superado el tiempo de espera. Analizando...")
            # Se le asigna una flag especial para indicar que terminó por timeout
            state['flags'].add('TIMEOUT')
            assemble_and_send_vector(state)
            stale_keys.append(key)
    
    # Se eliminan las conexiones muertas de la memoria
    for key in stale_keys:
        if key in connection_states:
            del connection_states[key]


def assemble_and_send_vector(conn_details):
    """Construye y envía el vector completo de 40 características."""
    current_time = time.time()
    
    duration = int(current_time - conn_details['start_time'])
    protocol_type = conn_details['protocol']
    service = get_service_name(conn_details['dst_port'])
    # Se ajusta la flag para reflejar el estado final, incluido el timeout
    if 'TIMEOUT' in conn_details['flags']:
        flag = "RSTO" # Flag común para timeouts
    elif 'F' in conn_details['flags'] or 'R' in conn_details['flags']:
        flag = "SF"
    else:
        flag = "S0"
        
    src_bytes = conn_details.get('src_bytes', 0)
    dst_bytes = conn_details.get('dst_bytes', 0)

    cleanup_history()
    dest_ip = conn_details['dst_ip']
    history_for_host = host_history[dest_ip]

    count = len(history_for_host)
    srv_count = sum(1 for _, s, _ in history_for_host if s == service)
    serror_count = sum(1 for _, _, f in history_for_host if 'R' in f or 'TIMEOUT' in f)
    serror_rate = (serror_count / count) if count > 0 else 0.0
    srv_serror_rate = (sum(1 for _, s, f in history_for_host if s == service and ('R' in f or 'TIMEOUT' in f)) / srv_count) if srv_count > 0 else 0.0
    same_srv_rate = (srv_count / count) if count > 0 else 0.0

    vector = [
        str(duration), protocol_type, service, flag, str(src_bytes), str(dst_bytes),
        "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
        str(count), str(srv_count), f"{serror_rate:.2f}", f"{srv_serror_rate:.2f}",
        "0.00", "0.00", f"{same_srv_rate:.2f}", "0.00", "0.00",
        "255", "255", "1.00", "0.00", "1.00", "1.00", "0.00", "0.00", "0.00", "0.00"
    ]
    
    payload = {"ip": conn_details['src_ip'], "data": vector}
    print(f"CONEXIÓN FINALIZADA ({flag}). Enviando vector desde IP {payload['ip']}...")

    try:
        response = requests.post(ANALYSIS_SERVER_URL, json=payload)
        if response.status_code == 200:
            result = response.json()
            print(f"  -> Resultado: {result.get('resultado', 'error').upper()}")
            if result.get('resultado') == 'ataque':
                print("  🚨 ALERTA: POSIBLE ATAQUE DETECTADO 🚨")
        else:
            print(f"  -> Error al contactar el servidor: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  -> Error de conexión: {e}")


def process_packet(packet):
    """Procesa cada paquete y actualiza el estado de las conexiones."""
    if not packet.haslayer(TCP):
        return

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
        if src_ip == conn['src_ip']:
            conn['src_bytes'] += len(packet[TCP].payload)
        else:
            conn['dst_bytes'] += len(packet[TCP].payload)
        
        if 'F' in flags or 'R' in flags:
            host_history[conn['dst_ip']].append((time.time(), get_service_name(conn['dst_port']), conn['flags']))
            assemble_and_send_vector(conn)
            del connection_states[conn_key]

def get_service_name(port):
    """Mapea puertos a nombres de servicio conocidos."""
    services = {80: "http", 443: "https", 21: "ftp", 22: "ssh", 25: "smtp"}
    return services.get(port, "other")

# --- Bucle Principal del Sensor ---
if __name__ == "__main__":
    print("[INFO] Sensor Stateful con Timeout iniciado. Monitoreando conexiones...")
    while True:
        try:
            # Se captura tráfico por un intervalo corto
            sniff(prn=process_packet, store=0, filter="tcp", timeout=CLEANUP_INTERVAL)
            # Después de cada intervalo, se limpian las conexiones muertas
            cleanup_stale_connections()
        except Exception as e:
            print(f"[ERROR] Error en el bucle principal: {e}")
            time.sleep(5) # Se espera antes de reintentar en caso de error grave

