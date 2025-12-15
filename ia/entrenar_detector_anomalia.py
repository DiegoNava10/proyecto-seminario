import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump, load
import os

print("[INFO] Iniciando el entrenamiento del Detector de Anomalías personalizado...")

# Rutas
BASELINE_DATA_PATH = "../servidor/calibracion_local.csv"
MODEL_OUTPUT_PATH = "anomaly_detector.joblib"
FEATURES_PATH = "features_moderno.joblib"

# Verificación
if not os.path.exists(BASELINE_DATA_PATH):
    print(f"[ERROR] No se encontró el archivo de conexion local en '{BASELINE_DATA_PATH}'.")
    print("        Asegúrate de haber ejecutado 'recolectar_conexion_local.py' primero.")
    exit()
if not os.path.exists(FEATURES_PATH):
    print(f"[ERROR] No se encontró el archivo de características '{FEATURES_PATH}'.")
    exit()

# Entrenamiento
print("[INFO] Cargando datos de conexion local de tu red...")
df_baseline = pd.read_csv(BASELINE_DATA_PATH)
features = load(FEATURES_PATH)

# Nos aseguramos de que los datos de entrenamiento usen las mismas columnas que el sensor
# y que no contengan la columna 'Label' si accidentalmente se coló.
features_without_label = [f for f in features if f.lower() != 'label']
X_train = df_baseline[features_without_label]

print(f"[INFO] Entrenando el modelo de Isolation Forest con {len(X_train)} registros de tu tráfico normal...")

# Isolation Forest es un modelo para la detección de anomalías
# contamination='auto' permite que el modelo decida el umbral de anomalía
modelo = IsolationForest(n_estimators=100, contamination='auto', random_state=42, n_jobs=-1)
modelo.fit(X_train)

print("[INFO] Entrenamiento completado.")

# Guardado de Artefactos
dump(modelo, MODEL_OUTPUT_PATH)
# Guardamos la lista de características que si usó el modelo
dump(features_without_label, "features_anomaly_detector.joblib")

print(f"[SUCCESS] El Detector de Anomalías personalizado ha sido guardado en '{MODEL_OUTPUT_PATH}'.")
print("           El servidor ahora está listo para usar este nuevo modelo.")

