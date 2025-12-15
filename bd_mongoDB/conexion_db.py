import os
import pymongo
from pymongo.errors import ConnectionFailure
import datetime
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId

MONGO_URI = "mongodb+srv://octaviogutierrez:Joto1@clustercast.4eqghnt.mongodb.net/?appName=ClusterCAST"

# Inicia el cliente de MongoDB
try:
    client = pymongo.MongoClient(MONGO_URI,server_api=ServerApi('1'))   
    # Ping para conexion  
    client.admin.command('ping')
    print("[INFO] Conexión a MongoDB Atlas exitosa.")
    #Se define a donde nos conectamos
    db = client["CASTDB"]
    #servira para guardar los eventos analizados
    log_collection = db["log"]            
    whitelist_collection = db["whitelist"]
    blacklist_collection = db["blacklist"]
    final_blacklist_collection = db["final_blacklist"]
except ConnectionFailure as e:
    print(f"[ERROR] No se pudo conectar a MongoDB Atlas: {e}")
    client = None
except Exception as e:
    print(f"[ERROR] Error al inicializar MongoDB: {e}")
    client = None

def guardar_evento_analisis(ip_origen, resultado_prediccion, vector_datos):
    """
    Guarda el resultado de un análisis en la colección de alertas.
    guardamos cada evento analizado.
    """
    if db is None:
        print("[WARN] No hay conexión a la BD o las colecciones no existen. Omitiendo guardado.")
        return

    try:
        # Creamos el documento que se guardará
        documento_evento = {
            "ip_origen": ip_origen,
            "vector_caracteristicas": vector_datos,
            # Formato UTC
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "analizado_por_especialista": False
        }

        log_collection.insert_one(documento_evento.copy())

        if resultado_prediccion == "Benigno":
            whitelist_collection.insert_one(documento_evento)
            print(f"[DB] Evento de {ip_origen} (Benigno) guardado en WHITELIST.")
        else:
            blacklist_collection.insert_one(documento_evento)
            print(f"[DB] Evento de {ip_origen} (Ataque) guardado en BLACKLIST.")
    except Exception as e:
        print(f"[ERROR-DB] No se pudo guardar el evento en MongoDB: {e}")

def obtener_sospechosos_pendientes(limite=10):
    """Busca en blacklist los que aún no han sido revisados por el especialista."""
    if db is None: return []
    try:
        #Se busca documentos en blacklist que NO tengan el flag de revisado
        cursor = blacklist_collection.find({"analizado_por_especialista": False}).limit(limite)
        return list(cursor)
    except Exception as e:
        print(f"[ERROR-DB] Fallo al obtener sospechosos: {e}")
        return []
    
def mover_a_whitelist_confirmada(id_documento, documento_original):
    """Mueve de blacklist a whitelist (Falso Positivo corregido)."""
    if db is None: return False
    try:
        #Se prepara el documento para whitelist
        doc_to_move = documento_original.copy()
        doc_to_move["analizado_por_especialista"] = True
        doc_to_move["timestamp_revision"] = datetime.datetime.now(datetime.timezone.utc)
        if "_id" in doc_to_move: del doc_to_move["_id"]

        whitelist_collection.insert_one(doc_to_move)

        #Eliminamos de Blacklist usando su ID original
        blacklist_collection.delete_one({"_id": ObjectId(id_documento)})
        print(f"[DB] Corrección: {documento_original.get('ip_origen')} movido de Blacklist a Whitelist.")
        return True
    except Exception as e:
        print(f"[ERROR-DB] Fallo al mover a whitelist: {e}")
        return False
    
def mover_a_final_blacklist_y_confirmar(id_documento, documento_original):
    """Mueve de blacklist a final_blacklist (Ataque Confirmado)."""
    if db is None: return False
    try:
        doc_to_move = documento_original.copy()
        doc_to_move["analizado_por_especialista"] = True
        doc_to_move["timestamp_bloqueo"] = datetime.datetime.now(datetime.timezone.utc)
        doc_to_move["accion"] = "BLOQUEADO_IPTABLES"
        if "_id" in doc_to_move: del doc_to_move["_id"]

        #Insertamos en Final Blacklist
        final_blacklist_collection.insert_one(doc_to_move)

        #Eliminamos de Blacklist temporal
        blacklist_collection.delete_one({"_id": ObjectId(id_documento)})
        print(f"[DB] Confirmado: {documento_original.get('ip_origen')} movido a FINAL BLACKLIST.")
        return True
    except Exception as e:
        print(f"[ERROR-DB] Fallo al mover a final blacklist: {e}")
        return False