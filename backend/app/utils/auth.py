import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from ..extensions import get_db

def generate_token(email: str, rol: str) -> str:
    payload = {'email': email, 'rol': rol, 'exp': datetime.utcnow() + timedelta(hours=8), 'iat': datetime.utcnow()}
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '): return jsonify({'error': 'Token requerido'}), 401
        try:
            payload = jwt.decode(auth.replace('Bearer ', ''), current_app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = payload
            return f(*args, **kwargs)
        except Exception:
            return jsonify({'error': 'Token inválido o expirado'}), 401
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '): return jsonify({'error': 'Token requerido'}), 401
        try:
            payload = jwt.decode(auth.replace('Bearer ', ''), current_app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload.get('rol') != 'admin': return jsonify({'error': 'Requiere admin'}), 403
            request.user = payload
            return f(*args, **kwargs)
        except Exception:
            return jsonify({'error': 'Token inválido'}), 401
    return decorated

# Helper para guardar logs fácilmente en cualquier ruta
def registrar_log(accion, detalle, usuario="sistema"):
    get_db()['logs'].insert_one({
        'fecha': datetime.now().isoformat(),
        'accion': accion,
        'usuario': usuario,
        'detalle': detalle,
        'ip': request.remote_addr if request else '127.0.0.1',
        'timestamp': datetime.now()
    })