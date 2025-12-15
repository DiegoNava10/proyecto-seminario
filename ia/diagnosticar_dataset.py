import pandas as pd
import numpy as np
import os

print("[INFO] Iniciando el protocolo de diagnóstico ...")

# Archivo a diagnosticar debe estar en la carpeta 'data_subset/'
ARCHIVO_A_DIAGNOSTICAR = "data_subset/03-02-2018.csv"

if not os.path.exists(ARCHIVO_A_DIAGNOSTICAR):
    print(f"[ERROR] No se encontró el archivo a diagnosticar en la ruta: {ARCHIVO_A_DIAGNOSTICAR}")
    print("[ERROR] Asegúrate de que el archivo esté en la carpeta 'data_subset'.")
    exit()

print(f"[INFO] Analizando el archivo: {os.path.basename(ARCHIVO_A_DIAGNOSTICAR)}")

try:
    # Leemos el archivo problemático
    df = pd.read_csv(ARCHIVO_A_DIAGNOSTICAR, low_memory=False)
    print(f"  -> Lectura inicial exitosa. Filas crudas: {len(df):,}")

    # Replicamos el proceso de limpieza
    df.columns = df.columns.str.strip()
    df.rename(columns={'Destination Port': 'Dst Port'}, inplace=True, errors='ignore')
    
    if 'Dst Port' in df.columns:
        df = df[df['Dst Port'].ne('Dst Port')] # Elimina encabezados
    
    label_col_name = 'Label' if 'Label' in df.columns else ' Label'
    
    # Guardamos una copia antes de la conversión numérica para el análisis
    df_antes_de_limpieza = df.copy()

    for col in df.columns:
        if col != label_col_name and col != 'Timestamp':
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    print("\n--- REPORTE FORENSE DE VALORES NULOS (NaN) ---")
    
    # Contamos cuántos valores nulos hay en cada columna ANTES de eliminarlos
    null_counts = df.isnull().sum()
    null_counts = null_counts[null_counts > 0].sort_values(ascending=False)

    if null_counts.empty:
        print("No se encontraron valores nulos después de la conversión.")
    else:
        print("Se encontraron valores nulos en las siguientes columnas:")
        for col, count in null_counts.items():
            print(f"  - Columna '{col}': {count:,} valores nulos")

    # Realizamos la limpieza final
    filas_antes = len(df)
    df.dropna(inplace=True)
    filas_despues = len(df)
    
    print("\n--- RESUMEN DEL DIAGNÓSTICO ---")
    print(f"Filas antes de la limpieza final (dropna): {filas_antes:,}")
    print(f"Filas después de la limpieza final (dropna): {filas_despues:,}")
    print(f"Total de filas descartadas: {(filas_antes - filas_despues):,}")
    
    if filas_despues == 0:
        print("\n[CONCLUSIÓN] El archivo completo fue descartado. Las columnas con más valores nulos (listadas arriba) son la causa probable.")
    else:
        print("\n[CONCLUSIÓN] El archivo es parcialmente válido, pero se descartaron muchas filas.")

except Exception as e:
    print(f"\n[ERROR FATAL] Ocurrió un error irrecuperable durante el diagnóstico: {e}")
