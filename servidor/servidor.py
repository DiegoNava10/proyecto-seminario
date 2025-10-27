from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from joblib import load
import traceback
import pandas as pd
from pymongo import MongoClient
import datetime
import os
import psycopg2

app = Flask(__name__)
CORS(app)

MONGO_URI = "mongodb+srv://EdgarMiranda:SiChuy123#@clustercast.4eqghnt.mongodb.net/?appName=ClusterCAST"
DB_NAME = "CASTDB"

try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    TTL_SECONDS = 1800 
    db.whitelist.create_index("timestamp", expireAfterSeconds=TTL_SECONDS)
    db.blacklist.create_index("timestamp", expireAfterSeconds=TTL_SECONDS)
    
    print(f"[INFO] Conectado exitosamente a MongoDB Atlas (DB: {DB_NAME}).")
    print(f"[INFO] Índices TTL configurados para borrado automático en {TTL_SECONDS}s.")

except Exception as e:
    print(f"[ERROR FATAL] No se pudo conectar a MongoDB Atlas: {e}")
    print("      Asegúrate de que tu IP esté en la Whitelist de Network Access y que la URI sea correcta.")
    exit()

# --- Carga de Artefactos de IA Especialista ---
print("[INFO] Cargando artefactos del modelo especialista...")
try:
    modelo = load("../ia/modelo_ids_moderno.joblib")
    scaler = load("../ia/scaler_moderno.joblib")
    feature_names = load("../ia/features_moderno.joblib")
    print(f"[INFO] Artefactos cargados. El modelo es un especialista en {len(feature_names)} características.")
except FileNotFoundError as e:
    print(f"[ERROR] No se pudo encontrar un archivo de modelo necesario: {e}")
    print("[ERROR] Asegúrate de haber ejecutado 'entrenar_modelo_definitivo.py' en la carpeta /ia.")
    exit()

@app.route("/analizar_moderno", methods=["POST"])
def analizar(): 
    try:
        contenido = request.get_json(force=True)
        if not contenido or "data" not in contenido or "ip" not in contenido:
            return jsonify({"error": "Faltan datos en la solicitud"}), 400
        
        vector_recibido = contenido["data"]
        ip = contenido.get("ip")
        
        # --- Verificación de Consistencia con el Contrato ---
        if len(vector_recibido) != len(feature_names):
            error_msg = f"Error de dimensión. El modelo espera {len(feature_names)} características, pero se recibieron {len(vector_recibido)}."
            print(f"[ERROR] {error_msg}")
            return jsonify({"error": error_msg}), 400

        # --- Preprocesamiento y Predicción ---
        # Creamos un DataFrame con los nombres de columna correctos para que el scaler funcione
        vector_df = pd.DataFrame([vector_recibido], columns=feature_names)
        vector_scaled = scaler.transform(vector_df)
        
        prediccion_numerica = modelo.predict(vector_scaled)[0]
        resultado = "Benigno" if prediccion_numerica == 0 else "Ataque"
        
        print(f"[RESULTADO] IP: {ip}, Predicción: {resultado.upper()}")

        try:
            # Creamos el documento que vamos a insertar
            documento = {
                "timestamp": datetime.datetime.utcnow(), # ¡Esencial para el borrado automático!
                "ip_origen": ip,
                "resultado": resultado,
                "vector_datos": vector_recibido # Guardamos el vector completo
            }

            # Decidimos a qué colección va
            if resultado == "Ataque":
                db.blacklist.insert_one(documento)
                print(f"  -> [BLACKLIST] IP {ip} registrada como amenaza.")
            else:
                db.whitelist.insert_one(documento)
                print(f"  -> [WHITELIST] IP {ip} registrada como benigna.")

        except Exception as db_error:
            print(f"[ERROR DB] No se pudo escribir en MongoDB: {db_error}")

        return jsonify({"resultado": resultado})
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    
#ruta Para crear usuarios
@app.route("/crear_usuario", methods=["POST"])
def crear_usuario():
    try:
        datos_usuario = request.get_json(force=True)
        # Aquí puedes agregar validación (ej. que exista email y password)
        if "email" not in datos_usuario or "nombre" not in datos_usuario:
            return jsonify({"error": "Faltan 'email' o 'nombre'"}), 400
        
        # Insertamos el nuevo usuario en la colección 'usuarios'
        db.usuarios.insert_one(datos_usuario)
        print(f"[INFO] Nuevo usuario creado: {datos_usuario['email']}")
        return jsonify({"status": "usuario creado", "email": datos_usuario['email']}), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("API de Detección de Intrusos (Modelo Especialista) corriendo en http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)

