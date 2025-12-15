import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from joblib import dump
import matplotlib.pyplot as plt
import seaborn as sns
import gc
import os

print("[INFO] Iniciando el protocolo de entrenamiento (Modo Especialista Definitivo)...")

# Rutas
PROCESSED_DATA_PATH = "data_processed/"
TRAIN_FILE = os.path.join(PROCESSED_DATA_PATH, "dataset_entrenamiento.csv")
TEST_FILE = os.path.join(PROCESSED_DATA_PATH, "dataset_prueba.csv")

# Características que el modelo podrá utilizar
FEATURES_WE_CAN_COMPUTE = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Label'
]
print(f"[INFO] El modelo se entrenará como un especialista en {len(FEATURES_WE_CAN_COMPUTE)-1} características clave.")

try:
    print(f"[INFO] Cargando y filtrando el dataset de entrenamiento...")
    # Leemos solo las columnas que nos interesan para ahorrar memoria
    df_train = pd.read_csv(TRAIN_FILE, usecols=lambda column: column in FEATURES_WE_CAN_COMPUTE, low_memory=False)
    
    print(f"[INFO] Cargando y filtrando el dataset de prueba...")
    df_test = pd.read_csv(TEST_FILE, usecols=lambda column: column in FEATURES_WE_CAN_COMPUTE, low_memory=False)

    # Consolidamos en un solo DataFrame
    df = pd.concat([df_train, df_test], ignore_index=True)
    del df_train, df_test
    gc.collect()

except Exception as e:
    print(f"\n[ERROR] Ocurrió un error al cargar los datasets: {e}")
    print("        Asegúrate de haber ejecutado 'preparar_dataset.py' primero.")
    exit()

# Preprocesamiento
print("[INFO] Realizando preprocesamiento...")
df.rename(columns={'Label': 'Label_text'}, inplace=True, errors='ignore')
df['Label'] = df['Label_text'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
df = df.drop(['Label_text'], axis=1, errors='ignore')

X = df.drop('Label', axis=1)
y = df['Label']
feature_names = X.columns.tolist()
del df
gc.collect()

# División y Escalado
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Entrenamiento
print(f"\n[INFO] Entrenando el modelo especialista con {X_train.shape[0]} registros...")
modelo = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1, max_depth=30, min_samples_leaf=5)
modelo.fit(X_train, y_train)

# Evaluación
print("\n[INFO] Evaluando el modelo especialista...")
y_pred = modelo.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\n--- Calidad del Modelo Especialista ---")
print(f"Porcentaje de Acertividad: {accuracy * 100:.2f}%")
print("\n--- Reporte de Clasificación Detallado ---")
print(classification_report(y_test, y_pred, target_names=['Benigno', 'Ataque']))

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='viridis')
plt.title('Matriz de Confusión (Modelo Especialista)')
plt.xlabel('Predicción')
plt.ylabel('Realidad')
plt.show()

# Guardado de Artefactos
print("\n[INFO] Guardando artefactos del modelo especialista...")
dump(modelo, "modelo_ids_moderno.joblib")
dump(scaler, "scaler_moderno.joblib")
dump(feature_names, "features_moderno.joblib")

print("\n[SUCCESS] Proceso completado. Tu IA especialista está lista.")