import unittest
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 1. SIMULACIÓN DE TU CÓDIGO (Para no importar todo el proyecto complejo) ---
def encriptar_datos_simulado(key, datos_dict):
    """
    Esta función simula lo que hace tu sensor.py:
    Toma un diccionario, lo convierte a bytes y lo cifra.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    datos_bytes = json.dumps(datos_dict).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, datos_bytes, None)
    return nonce, ciphertext

# --- 2. LA CLASE DE PRUEBAS (Aquí empieza la magia) ---
class TestSeguridadCAST(unittest.TestCase):

    # El método setUp se ejecuta AUTOMÁTICAMENTE antes de cada prueba.
    # Sirve para preparar el terreno (crear claves, abrir archivos, etc.)
    def setUp(self):
        print("\n[SETUP] Preparando entorno de prueba...")
        self.clave_prueba = AESGCM.generate_key(bit_length=256)
        self.datos_secretos = {"ip": "192.168.1.50", "status": "atacante"}

    # PRUEBA 1: Verificar que el cifrado realmente oculte la información
    def test_confidencialidad_aes(self):
        print("[TEST] Ejecutando prueba de confidencialidad AES...")
        
        # 1. Ejecutamos la función
        nonce, texto_cifrado = encriptar_datos_simulado(self.clave_prueba, self.datos_secretos)
        
        # 2. Validaciones (Asserts)
        # A. El texto cifrado NO debe ser igual al texto original (Obvio, pero vital)
        texto_original_bytes = json.dumps(self.datos_secretos).encode('utf-8')
        self.assertNotEqual(texto_cifrado, texto_original_bytes, "¡Error! El cifrado no ocultó los datos.")
        
        # B. El texto cifrado no debe estar vacío
        self.assertTrue(len(texto_cifrado) > 0, "¡Error! El cifrado devolvió vacío.")

    # PRUEBA 2: Verificar que podemos descifrar lo que ciframos (Integridad)
    def test_integridad_descifrado(self):
        print("[TEST] Ejecutando prueba de ida y vuelta (Round-trip)...")
        
        # 1. Ciframos
        nonce, texto_cifrado = encriptar_datos_simulado(self.clave_prueba, self.datos_secretos)
        
        # 2. Desciframos (Simulando al servidor)
        aesgcm = AESGCM(self.clave_prueba)
        datos_recuperados_bytes = aesgcm.decrypt(nonce, texto_cifrado, None)
        datos_recuperados = json.loads(datos_recuperados_bytes.decode('utf-8'))
        
        # 3. Validamos que lo que entró es igual a lo que salió
        self.assertEqual(self.datos_secretos, datos_recuperados, "¡Error! Al descifrar obtuvimos datos corruptos.")

if __name__ == '__main__':
    unittest.main()