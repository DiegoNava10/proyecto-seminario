import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from joblib import dump

#Cargar dataset NSL-KDD (descargado previamente o desde URL
url = "https://raw.githubusercontent.com/defcom/NSL_KDD/master/KDDTrain+.txt"
print("Cargando datos")
df = pd.read_csv(url, header=None)

#Separar caracteristicas y etiqueta
x = df.iloc[:, :-1]
y = df.iloc[:, -1]

y = y.apply(lambda x: 0 if x == 'normal' else 1)

for col in x.columns:
    if x[col].dtype == 'object':
        x[col] = LabelEncoder().fit_transform(x[col])

print ("Entrenando modelo")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(x,y)

dump(clf, "modelo_ids.joblib")
print("Modelo guardado como modelo")