from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from joblib import load
import pickle
import traceback
import psycopg2

app = Flask(__name__)
CORS(app)

print("[INFO] Cargando modelo, codificadores y escalador...")
try:
    modelo = load("../ia/modelo_ids.joblib")
    with open("../ia/encoders.pkl", "rb") as f:
        encoders = pickle.load(f)
    scaler = load("../ia/scaler.joblib")
    print("[INFO] Artefactos cargados correctamente. Servidor listo.")
except FileNotFoundError as e:
    print(f"[ERROR] No se pudo encontrar un archivo de modelo necesario: {e}")
    print("[ERROR] Asegúrate de haber ejecutado la última versión de 'entrenar_modelo.py'.")
    exit()

@app.route("/analizar", methods=["POST"])
def analizar(): 
    try:
        contenido = request.get_json(force=True)
        if not contenido or "data" not in contenido or "ip" not in contenido:
            return jsonify({"error": "Faltan datos en la solicitud"}), 400
        
        datos = contenido["data"]
        ip = contenido.get("ip")
        
        if len(datos) != 40:
            error_msg = f"Error de dimensión. Se esperaban 40 características, pero se recibieron {len(datos)}."
            print(f"[ERROR] {error_msg}")
            return jsonify({"error": error_msg}), 400

        vector_numerico = []
        for i, val in enumerate(datos):
            if i in encoders:
                encoder = encoders[i]
                # Comprueba si el valor es conocido por el codificador
                if str(val) in encoder.classes_:
                    valor_transformado = encoder.transform([str(val)])[0]
                    vector_numerico.append(valor_transformado)
                else:
                    # Si la clase es desconocida (ej. 'https'), la mapea a 'other'
                    print(f"[INFO] Valor desconocido '{val}' para columna {i}. Mapeando a 'other'.")
                    try:
                        # Intenta transformar 'other', que es una categoría común
                        valor_transformado = encoder.transform(['other'])[0]
                        vector_numerico.append(valor_transformado)
                    except ValueError:
                        # Si 'other' tampoco existe, usa 0 como último recurso
                        vector_numerico.append(0)
            else:
                # Si no es una columna categórica, la convierte a float
                vector_numerico.append(float(val))

        vector_final = scaler.transform([np.array(vector_numerico)])
        prediccion_numerica = modelo.predict(vector_final)[0]
        resultado = "normal" if prediccion_numerica == 0 else "ataque"
        
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
    print("API de Detección de Intrusos corriendo en http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)