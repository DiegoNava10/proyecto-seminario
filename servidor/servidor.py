from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from joblib import load
import psycopg2

app = Flask(__name__)
CORS(app)
modelo = load("../ia/modelo_ids.joblib")

@app.route("/analizar", methods=["POST"])
def analizar(): 
    try:

        contenido = request.get_json(force=True)
        if not contenido or "data" not in contenido or "ip" not in contenido:
            return jsonify({"error": "Faltan datos en la solicitud"}), 400
        datos = contenido["data"]
        ip = request.json.get("ip")
        
        print(f"[DEBUG] Vector recibido: {datos}")
        print(f"[DEBUG] Longitud del vector: {len(datos)}")

        resultado = "normal" if modelo.predict([np.array(datos)])[0] == 0 else "ataque"

        conn = psycopg2.connect(dbname="cia_db", user="admin", password="admin@123", host="localhost")
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS resultados (ip TEXT, resultado TEXT);")
        cur.execute("INSERT INTO resultados (ip, resultado) VALUES (%s, %s);", (ip, resultado))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"resultado": resultado})
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__=="__main__":
    print("API corriendo http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port =5000)
