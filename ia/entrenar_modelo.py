import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from joblib import dump

print("[INFO] Cargando dataset...")
data = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt", header=None)
X = data.iloc[:, :-1]
Y = data.iloc[:, -1].apply(lambda X: 0 if X == 'normal' else 1)

for col in X.columns:
    if X[col].dtype == 'object':
        X[col] = LabelEncoder().fit_transform(X[col])

modelo = RandomForestClassifier(n_estimators=100, random_state=42)
modelo.fit(X, Y)
dump(modelo, "modelo_ids.joblib")
print("Modelo entrenado y guardado")
