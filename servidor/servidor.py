from flask import Flask, request, jsonify
import numpy as np
from joblib import load
import logging
import os

app = Flask(__name__)
modelo = load("../ia/modelo_ids.joblib")

logging.basicConfig(filename="registro.log", level=logging.INFO)

@app.route("/analizar", methods=["POST"])
def analizar(): 
    contenido = request.json
    vector = np.array(contenido["data"]).reshape(1, -1)
    ip = contenido.get("ip", "0.0.0.0")

    pred = modelo.predict(vector)[0]
    resultado = "normal" if pred == 0 else "ataque"
    logging.info(f"[{ip}] -> {resultado}")

   if resultado == "ataque":
       os.system(f"iptables -A INPUT -s {ip} -j DROP")

    return jsonify({"resultado": resultado})

if __name__=="__main__":
    print(
