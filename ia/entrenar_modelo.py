import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from joblib import dump
import pickle

print("[INFO] Cargando dataset...")
data = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt", header=None)
X = data.iloc[:, :-1]
y = data.iloc[:, -1]


Y = y.apply(lambda X: 0 if X == 0 else 1)
vectores_normales = X[Y == 0].head(3).values.tolist()
vectores_ataques = X[Y == 1].head(3).values.tolist()
print("Ejemplos normales")
for v in vectores_normales:
    print(v)

print("Ejemplos ataques")
for v in vectores_ataques:
    print(v)


label_encoders = {}
for col in X.columns:
    if X[col].dtype == 'object':
        le = LabelEncoder()
        X[col] = LabelEncoder().fit_transform(X[col])
        label_encoders[col] = le

modelo = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
modelo.fit(X, Y)
dump(modelo, "modelo_ids.joblib")

with open("encoders.pkl", "wb") as f:
    pickle.dump(label_encoders, f)

print("Modelo entrenado y guardado")

# Extraer una fila real con etiqueta "normal"

ejemplo = X[Y == 0].sample(1, random_state=42)
print("Prediccion del modelo sobre un ejemplo real normal:")
print("->", modelo.predict(ejemplo.values))

ejemplo_normal = X[y==0].iloc[0]
print(ejemplo_normal.values)
print ("Prediccion para ejemplo normal: ", modelo.predict([ejemplo_normal.values]))
