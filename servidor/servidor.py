from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from joblib import load
import traceback
import psycopg2
import pandas as pd

app = Flask(__name__)
CORS(app)

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
            conn = psycopg2.connect(dbname="cia_db", user="admin", password="admin@123", host="localhost")
            cur = conn.cursor()
            # Creamos la tabla si no existe, con más detalles
            cur.execute("""
                CREATE TABLE IF NOT EXISTS resultados (
                    id SERIAL PRIMARY KEY, 
                    timestamp TIMESTAMPTZ DEFAULT NOW(), 
                    ip_origen TEXT, 
                    resultado TEXT, 
                    vector_datos TEXT
                );
            """)
            # Insertamos el nuevo registro
            cur.execute(
                "INSERT INTO resultados (ip_origen, resultado, vector_datos) VALUES (%s, %s, %s);", 
                (ip, resultado, str(datos))
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as db_error:
            print(f"[ERROR DB] No se pudo escribir en la base de datos: {db_error}")

        return jsonify({"resultado": resultado})
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("API de Detección de Intrusos (Modelo Especialista) corriendo en http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)

