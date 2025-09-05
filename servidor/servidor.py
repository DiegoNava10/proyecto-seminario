from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from joblib import load
import psycopg2
import pickle
import traceback

app = Flask(__name__)
CORS(app)

# --- Carga de Artefactos de IA ---
print("[INFO] Cargando modelo, codificadores y escalador...")
try:
    modelo = load("../ia/modelo_ids.joblib")
    with open("../ia/encoders.pkl", "rb") as f:
        encoders = pickle.load(f)
    scaler = load("../ia/scaler.joblib")
    print("[INFO] Artefactos cargados correctamente. Servidor listo.")
except FileNotFoundError as e:
    print(f"[ERROR] No se pudo encontrar un archivo de modelo necesario: {e}")
    print("[ERROR] Asegúrate de haber ejecutado 'entrenar_modelo.py' con la última versión del código.")
    exit()

@app.route("/analizar", methods=["POST"])
def analizar(): 
    try:
        contenido = request.get_json(force=True)
        if not contenido or "data" not in contenido or "ip" not in contenido:
            return jsonify({"error": "Faltan datos en la solicitud"}), 400
        
        datos = contenido["data"]
        ip = contenido.get("ip")
        
        # Verificación de que el vector tenga la longitud correcta (40)
        if len(datos) != 40:
            error_msg = f"Error de dimensión. Se esperaban 40 características, pero se recibieron {len(datos)}."
            print(f"[ERROR] {error_msg}")
            return jsonify({"error": error_msg}), 400

        print(f"[DEBUG] Vector recibido de {ip} con {len(datos)} características.")
        
        vector_numerico = []
        indices_categoricos = encoders.keys()

        for i, val in enumerate(datos):
            # Se comprueba si el índice 'i' de la característica es categórico
            if i in indices_categoricos:
                try:
                    # Se usa el encoder correspondiente al índice para transformar el valor de texto a número
                    valor_transformado = encoders[i].transform([str(val)])[0]
                    vector_numerico.append(valor_transformado)
                except Exception:
                    # Si el valor es desconocido (ej. un nuevo tipo de servicio)
                    print(f"[WARNING] Valor desconocido '{val}' para columna categórica {i}. Usando 0 por defecto.")
                    vector_numerico.append(0) 
            else:
                # Si no es categórico, es numérico y se convierte a float
                vector_numerico.append(float(val))

        # Se escala el vector ya completamente numérico
        vector_final = scaler.transform([np.array(vector_numerico)])
        # Se realiza la predicción
        prediccion_numerica = modelo.predict(vector_final)[0]
        resultado = "normal" if prediccion_numerica == 0 else "ataque"
        
        print(f"[RESULTADO] IP: {ip}, Predicción: {resultado.upper()}")

        # Opcional: Guardar en la base de datos
        # conn = psycopg2.connect(dbname="cia_db", user="admin", password="admin@admin123", host="localhost")
        # cur = conn.cursor()
        # cur.execute("CREATE TABLE IF NOT EXISTS resultados (id SERIAL PRIMARY KEY, timestamp TIMESTAMPTZ DEFAULT NOW(), ip TEXT, resultado TEXT, vector TEXT);")
        # cur.execute("INSERT INTO resultados (ip, resultado, vector) VALUES (%s, %s, %s);", (ip, resultado, str(datos)))
        # conn.commit()
        # cur.close()
        # conn.close()

        return jsonify({"resultado": resultado})
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("API de Detección de Intrusos corriendo en http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)
