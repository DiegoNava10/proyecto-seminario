import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import seaborn as sns
import matplotlib.pyplot as plt
from joblib import dump
import pickle

print("[INFO] Cargando y preparando el dataset...")

col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

data = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt", header=None, names=col_names)
data = data.drop(['difficulty', 'num_outbound_cmds'], axis=1)

data['label'] = data['label'].apply(lambda x: 0 if x == 'normal' else 1)
y = data['label']
X = data.drop('label', axis=1)

# ### CORRECCIÓN CLAVE AQUÍ ###
# Guardamos los encoders usando el índice numérico de la columna (0, 1, 2...) como clave.
label_encoders = {}
for col_name in X.select_dtypes(include=['object']).columns:
    le = LabelEncoder()
    # Obtenemos el índice numérico de la columna
    col_index = X.columns.get_loc(col_name)
    X[col_name] = le.fit_transform(X[col_name])
    label_encoders[col_index] = le

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("[INFO] Entrenando el modelo RandomForest...")
modelo = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42, n_jobs=-1)
modelo.fit(X_train, y_train)

print("\n[INFO] Evaluando el modelo...")
y_pred = modelo.predict(X_test)
print(f"Precisión (Accuracy): {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\n--- Reporte de Clasificación ---\n", classification_report(y_test, y_pred, target_names=['Normal', 'Ataque']))

print("\n[INFO] Guardando artefactos de IA...")
dump(modelo, "modelo_ids.joblib")
with open("encoders.pkl", "wb") as f:
    pickle.dump(label_encoders, f)
dump(scaler, 'scaler.joblib')
print("[SUCCESS] Proceso completado.")

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Ataque'], yticklabels=['Normal', 'Ataque'])
plt.xlabel('Predicción del Modelo')
plt.ylabel('Realidad')
plt.title('Matriz de Confusión')
plt.show()

