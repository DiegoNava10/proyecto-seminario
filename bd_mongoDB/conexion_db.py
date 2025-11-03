import os
import pymongo
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
import datetime
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

MONGO_URI = "mongodb+srv://octaviogutierrez:Joto1@clustercast.4eqghnt.mongodb.net/?appName=ClusterCAST"

# Inicia el cliente de MongoDB
try:
    client = pymongo.MongoClient(MONGO_URI,server_api=ServerApi('1'))   
    # Ping para conexion  
    client.admin.command('ping')
    print("[INFO] Conexión a MongoDB Atlas exitosa.")
except ConnectionFailure as e:
    print(f"[ERROR] No se pudo conectar a MongoDB Atlas: {e}")
    client = None
except Exception as e:
    print(f"[ERROR] Error al inicializar MongoDB: {e}")
    client = None

# Se define a donde nos conectamos
if client:
    db = client["CASTDB"]
    # servira para guardar los eventos analizados
    log_collection = db["log"]
    whitelist_collection = db["whitelist"]
    blacklist_collection = db["blacklist"]
else:
    log_collection = None
    whitelist_collection = None
    blacklist_collection = None

def guardar_evento_analisis(ip_origen, resultado_prediccion, vector_datos):
    """
    Guarda el resultado de un análisis en la colección de alertas.
    guardamos cada evento analizado.
    """
    if log_collection is None or whitelist_collection is None or blacklist_collection is None:
        print("[WARN] No hay conexión a la BD o las colecciones no existen. Omitiendo guardado.")
        return

    try:
        # Creamos el documento que se guardará
        documento_evento = {
            "ip_origen": ip_origen,
            "vector_caracteristicas": vector_datos,
            # Formato UTC
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
        }

        if resultado_prediccion == "Benigno":
            whitelist_collection.insert_one(documento_evento)
            print(f"[DB] Evento de {ip_origen} (Benigno) guardado en WHITELIST.")
        else:
            blacklist_collection.insert_one(documento_evento)
            print(f"[DB] Evento de {ip_origen} (Ataque) guardado en BLACKLIST.")
        
        # Se inserta a la coleccion
        log_collection.insert_one(documento_evento)
        
    except Exception as e:
        print(f"[ERROR-DB] No se pudo guardar el evento en MongoDB: {e}")