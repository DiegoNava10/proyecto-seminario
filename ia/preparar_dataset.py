import pandas as pd
import numpy as np
import os
import glob
from sklearn.model_selection import train_test_split
import gc

print("[INFO] Iniciando el protocolo de preparación de datos...")

# Rutas
RAW_DATA_PATH = "data_subset/"
PROCESSED_DATA_PATH = "data_processed/"
TRAIN_FILE = os.path.join(PROCESSED_DATA_PATH, "dataset_entrenamiento.csv")
TEST_FILE = os.path.join(PROCESSED_DATA_PATH, "dataset_prueba.csv")

# Limpieza previa
for f in [TRAIN_FILE, TEST_FILE]:
    if os.path.exists(f):
        os.remove(f)
print("[INFO] Archivos de entrenamiento/prueba anteriores eliminados.")

# Procesamiento y Consolidación
csv_files = glob.glob(os.path.join(RAW_DATA_PATH, "*.csv"))
if not csv_files:
    print(f"[ERROR] No se encontraron archivos CSV en la carpeta '{RAW_DATA_PATH}'.")
    print("[ERROR] Asegúrate de haber creado la carpeta 'data_subset' y movido los 4 archivos recomendados allí.")
    exit()

print(f"[INFO] Se encontraron {len(csv_files)} archivos de élite. Iniciando consolidación...")

df_list = []
for file in csv_files:
    print(f"  -> Leyendo archivo: {os.path.basename(file)}")
    try:
        df_temp = pd.read_csv(file, low_memory=False)
        # Limpieza Individual
        df_temp.columns = df_temp.columns.str.strip()
        df_temp.rename(columns={'Destination Port': 'Dst Port'}, inplace=True, errors='ignore')
        if 'Dst Port' in df_temp.columns:
            df_temp = df_temp[df_temp['Dst Port'].ne('Dst Port')]
        label_col_name = 'Label' if 'Label' in df_temp.columns else ' Label'
        if label_col_name not in df_temp.columns:
            print(f"     [AVISO] No se encontró la columna 'Label' en {os.path.basename(file)}. Se omitirá.")
            continue

        for col in df_temp.columns:
            if col != label_col_name and col != 'Timestamp':
                df_temp[col] = pd.to_numeric(df_temp[col], errors='coerce')
        
        df_temp.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_temp.dropna(inplace=True)
        
        df_list.append(df_temp)

    except Exception as e:
        print(f"     [AVISO] Ocurrió un error leyendo {file}, será omitido. Error: {e}")

# Unimos todos los bloques procesados
print(f"\n[INFO] Consolidando {len(df_list)} DataFrames limpios...")
try:
    df = pd.concat(df_list, ignore_index=True)
    del df_list
    gc.collect()
    print(f"[INFO] Consolidación completada. Total de filas limpias: {len(df):,}")

    label_col_name = 'Label' if 'Label' in df.columns else ' Label'
 
    print("\n[INFO] Buscando y filtrando clases con un solo miembro...")
    label_counts = df[label_col_name].value_counts()
    single_member_classes = label_counts[label_counts == 1].index.tolist()
    
    if single_member_classes:
        print(f"  -> Se encontraron {len(single_member_classes)} clases con un solo miembro. Serán eliminadas.")
        # Filtramos el DataFrame para excluir estas clases
        df = df[~df[label_col_name].isin(single_member_classes)]
        print(f"  -> Dataset filtrado. Nuevo total de filas: {len(df):,}")
    else:
        print("  -> No se encontraron clases con un solo miembro. ¡Excelente!")

    # Separación Estratificada Final
    print("\n[INFO] Realizando separación estratificada en entrenamiento (80%) y prueba (20%)...")
    
    train_df, test_df = train_test_split(
        df, test_size=0.2, random_state=42, stratify=df[label_col_name]
    )

    os.makedirs(PROCESSED_DATA_PATH, exist_ok=True)
    train_df.to_csv(TRAIN_FILE, index=False)
    test_df.to_csv(TEST_FILE, index=False)

    print(f"\n[SUCCESS] Los datasets han sido preparados y separados correctamente.")
    print(f"  -> Archivo de entrenamiento con {len(train_df):,} filas guardado.")
    print(f"  -> Archivo de prueba con {len(test_df):,} filas guardado.")

except MemoryError:
    print("\n[ERROR FATAL] Memoria insuficiente para consolidar los archivos.")
    exit()
except Exception as e:
    print(f"\n[ERROR FATAL] Ocurrió un error inesperado durante la consolidación final: {e}")
    exit()

