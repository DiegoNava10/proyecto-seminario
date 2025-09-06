import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump
import pickle
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

print("[INFO] Cargando y preparando el dataset...")

col_names = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
             "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
             "root_shell","su_attempted","num_root","num_file_creations","num_shells",
             "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
             "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
             "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
             "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
             "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
             "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
             "label","difficulty"]

data = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt", 
                   header=None, names=col_names)

# --- ### SOLUCIÓN: DICCIONARIO DE ATAQUES INTEGRADO ### ---
# En lugar de descargar el archivo, definimos el mapeo directamente aquí.
# Esto hace que nuestro script sea robusto y autosuficiente.
print("[INFO] Usando diccionario de ataques integrado.")
attack_map = {
    'back': 'dos', 'buffer_overflow': 'u2r', 'ftp_write': 'r2l', 'guess_passwd': 'r2l',
    'imap': 'r2l', 'ipsweep': 'probe', 'land': 'dos', 'loadmodule': 'u2r',
    'multihop': 'r2l', 'neptune': 'dos', 'nmap': 'probe', 'perl': 'u2r', 'phf': 'r2l',
    'pod': 'dos', 'portsweep': 'probe', 'rootkit': 'u2r', 'satan': 'probe',
    'smurf': 'dos', 'spy': 'r2l', 'teardrop': 'dos', 'warezclient': 'r2l', 'warezmaster': 'r2l'
}
# -----------------------------------------------------------

data['attack_type'] = data['label'].apply(lambda r: attack_map.get(r, 'normal'))
data = data.drop(['difficulty', 'num_outbound_cmds'], axis=1)

print("[INFO] Realizando alineación quirúrgica para ataques de sondeo...")
data.loc[data['attack_type'] == 'probe', 'service'] = 'other'

servicios_comunes = ['http', 'smtp', 'ftp', 'ftp_data', 'ssh', 'private', 'domain_u', 'other']
data['service'] = data['service'].apply(lambda x: x if x in servicios_comunes else 'other')
data = data.drop('attack_type', axis=1)

y = data['label'].apply(lambda x: 0 if x == 'normal' else 1)
X = data.drop('label', axis=1)

label_encoders = {}
for i, col in enumerate(X.columns):
    if X[col].dtype == 'object':
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        label_encoders[i] = le

X_train_df, X_test_df, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
X_train = X_train_df.to_numpy()
X_test = X_test_df.to_numpy()

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("[INFO] Entrenando el modelo RandomForest con datos quirúrgicamente alineados...")
modelo = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
modelo.fit(X_train, y_train)

print("\n[INFO] Evaluando el nuevo modelo...")
y_pred = modelo.predict(X_test)
print("\n--- Reporte de Clasificación ---")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Ataque']))

cm = confusion_matrix(y_test, y_pred)
print("\n--- Matriz de Confusión ---")
print(cm)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Ataque'], yticklabels=['Normal', 'Ataque'])
plt.title('Matriz de Confusión (Modelo Definitivo)')
plt.show()

print("\n[INFO] Guardando modelo y preprocesadores definitivos...")
dump(modelo, "modelo_ids.joblib")
with open("encoders.pkl", "wb") as f:
    pickle.dump(label_encoders, f)
dump(scaler, 'scaler.joblib')

print("[SUCCESS] Proceso completado.")

