from flask import Flask, request, jsonify
from flask_cors import CORS
from joblib import load
import traceback
import pandas as pd
import os

app = Flask(__name__)
CORS(app)

# --- Carga de Artefactos de Detección de Anomalías ---
print("[INFO] Cargando el Detector de Anomalías personalizado...")
try:
    # Carga el nuevo modelo de Isolation Forest
    modelo = load("../ia/anomaly_detector.joblib")
    # Carga la lista de características para asegurar la consistencia
    feature_names = load("../ia/features_moderno.joblib")
    print("[INFO] ¡Detector de Anomalías personalizado para tu red local cargado exitosamente!")
except FileNotFoundError as e:
    print(f"[ERROR] No se pudo encontrar un archivo de modelo: {e}")
    print("        Asegúrate de haber ejecutado 'recolectar_baseline.py' y 'entrenar_anomaly_detector.py'.")
    exit()

@app.route("/analizar_moderno", methods=["POST"])
def analizar(): 
    try:
        contenido = request.get_json(force=True)
        if not contenido or "data" not in contenido or "ip" not in contenido:
            return jsonify({"error": "Faltan datos en la solicitud"}), 400
        
        vector_recibido = contenido["data"]
        ip = contenido.get("ip")
        
        if len(vector_recibido) != len(feature_names):
            return jsonify({"error": "Error de dimensión."}), 400

        # Prepara el vector para la predicción
        vector_df = pd.DataFrame([vector_recibido], columns=feature_names)
        
        # El modelo de Isolation Forest devuelve:
        #  1 para tráfico normal (inlier)
        # -1 para anomalía (outlier/ataque)
        prediccion = modelo.predict(vector_df)[0]
        
        resultado = "Benigno" if prediccion == 1 else "Ataque"
        
        print(f"[RESULTADO] IP: {ip}, Predicción: {resultado.upper()}")
        return jsonify({"resultado": resultado})
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("API de Detección de Intrusos (Detector de Anomalías) corriendo en http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)

