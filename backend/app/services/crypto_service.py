import os
import json
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from ..extensions import get_db

def get_fernet():
    master_key = os.environ.get('MASTER_KEY', '')
    if not master_key: raise ValueError("MASTER_KEY no definida en .env")
    return Fernet(master_key.encode())

def cifrar_archivo(file, usuario_email):
    contenido = file.read()
    nombre_original = file.filename
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(contenido, AES.block_size))

    key_b64 = base64.b64encode(key).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')

    clave_cifrada = get_fernet().encrypt(key_b64.encode()).decode()

    get_db()['archivos_cifrados'].insert_one({
        'nombre_original': nombre_original,
        'fecha': datetime.now(),
        'tamano_original': len(contenido),
        'clave_cifrada': clave_cifrada,
        'iv_base64': iv_b64,
        'usuario': usuario_email
    })

    metadatos = {'iv': iv_b64, 'nombre_original': nombre_original}
    metadatos_bytes = json.dumps(metadatos).encode('utf-8')
    return encrypted_data + metadatos_bytes + len(metadatos_bytes).to_bytes(4, 'big'), nombre_original

def descifrar_archivo(data, usuario_email):
    offset = len(data) - 4
    len_meta = int.from_bytes(data[offset:offset+4], 'big')
    inicio_meta = len(data) - 4 - len_meta
    metadatos = json.loads(data[inicio_meta:offset].decode('utf-8'))
    
    datos_cifrados = data[:inicio_meta]
    iv_b64 = metadatos['iv']
    nombre_original = metadatos.get('nombre_original', 'archivo')

    registro = get_db()['archivos_cifrados'].find_one(
        {'nombre_original': nombre_original, 'usuario': usuario_email}, sort=[('fecha', -1)]
    )
    if not registro: raise ValueError("No se encontró la clave")

    key_b64 = get_fernet().decrypt(registro['clave_cifrada'].encode()).decode()
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(datos_cifrados), AES.block_size), nombre_original