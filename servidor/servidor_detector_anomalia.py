from flask import Flask, request, jsonify
from flask_cors import CORS
from joblib import load
import traceback
import pandas as pd
import os
import sys
import json
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

script_dir = os.path.dirname(__file__)
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

from bd_mongoDB.conexion_db import guardar_evento_analisis

app = Flask(__name__)
CORS(app)

# Carga de Artefactos de Detección de Anomalías
print("[INFO] Cargando el Detector de Anomalías personalizado...")
try:
    # Carga el modelo de Isolation Forest 
    modelo = load("../ia/anomaly_detector.joblib")
    # Carga la lista de características
    feature_names = load("../ia/features_moderno.joblib")
    print("[INFO] ¡Detector de Anomalías personalizado para tu red local cargado exitosamente!")
except FileNotFoundError as e:
    print(f"[ERROR] No se pudo encontrar un archivo de modelo: {e}")
    print("        Asegúrate de haber ejecutado 'recolectar_conexion_local.py' y 'entrenar_anomaly_detector.py'.")
    exit()

try:
    with open("aes_secret.key", "rb") as f:
        AES_KEY = f.read()
    with open("sensor_public.pem", "rb") as f:
        SENSOR_PUBLIC_KEY = serialization.load_pem_public_key(f.read())
    print("[SEGURIDAD] Llaves criptográficas del sensor cargadas correctamente.")
except FileNotFoundError:
    print("[ERROR] Faltan las llaves (aes_secret.key o sensor_public.pem). Ejecuta generar_claves_seguridad.py")
    exit()

@app.route("/analizar_moderno", methods=["POST"])
def analizar(): 
    try:
        paquete_seguro = request.get_json(force=True)

        #Decodificar de Base64
        nonce = base64.b64decode(paquete_seguro['nonce'])
        ciphertext = base64.b64decode(paquete_seguro['ciphertext'])
        signature = base64.b64decode(paquete_seguro['signature'])

        try:
            SENSOR_PUBLIC_KEY.verify(
                signature,
                ciphertext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("[ALERTA SEGURIDAD] Firma digital inválida. Posible intento de suplantación.")
            return jsonify({"error": "Firma Rechazada"}), 403
        
        #Descifrar datos
        aesgcm = AESGCM(AES_KEY)
        data_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        contenido_original = json.loads(data_bytes.decode('utf-8'))

        vector_recibido = contenido_original["data"]
        ip = contenido_original.get("ip")

        if vector_recibido is None or ip is None:
            return jsonify({"error": "Faltan datos en la solicitud"}), 400
        
        if len(vector_recibido) != len(feature_names):
            return jsonify({"error": "Error de dimensión."}), 400

        # Se prepara para la prediccion
        vector_df = pd.DataFrame([vector_recibido], columns=feature_names)
        
        # Devuelve 1 tráfico normal, -1 anomalía
        prediccion = modelo.predict(vector_df)[0]
        
        resultado = "Benigno" if prediccion == 1 else "Ataque"
        
        print(f"[RESULTADO] IP: {ip}, Predicción: {resultado.upper()}")
        
        try:
            guardar_evento_analisis(ip, resultado, vector_recibido)
        except Exception as e:
            print(f"[ERROR] Fallo en la lógica de guardado de BD: {e}")
        
        return jsonify({"resultado": resultado})
    
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("API de Detección de Intrusos corriendo en http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')