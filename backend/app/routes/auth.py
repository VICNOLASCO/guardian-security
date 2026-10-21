from flask import Blueprint, request, jsonify
from datetime import datetime
import secrets
from ..extensions import get_db, limiter, sesiones_activas
from ..utils.passwords import hash_password, verify_password
from ..utils.auth import generate_token, registrar_log

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json or {}
    email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify({"success": False, "message": "Faltan datos"}), 400

    user = get_db()['usuarios'].find_one({'email': email})
    if user and verify_password(password, user['password_hash']):
        token = generate_token(user['email'], user.get('rol', 'user'))
        
        session_id = secrets.token_hex(16)
        sesiones_activas[session_id] = {
            'id': session_id, 'email': email, 'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''), 'timestamp': datetime.now().isoformat()
        }
        registrar_log('login_exitoso', 'Inicio de sesión', user['email'])

        return jsonify({"success": True, "token": token, "usuario": {"email": user['email'], "rol": user.get('rol', 'user')}})
    return jsonify({"success": False, "message": "Credenciales incorrectas"}), 401

@auth_bp.route('/registro', methods=['POST'])
@limiter.limit("3 per minute")
def registro():
    data = request.json or {}
    email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify({"success": False, "message": "Faltan datos"}), 400
    if get_db()['usuarios'].find_one({'email': email}): return jsonify({"success": False, "message": "Correo ya registrado"}), 400

    get_db()['usuarios'].insert_one({
        'email': email, 'password_hash': hash_password(password), 'nombre': email.split('@')[0],
        'rol': 'user', 'fecha_creacion': datetime.now().isoformat(), 'activo': True
    })
    return jsonify({"success": True, "message": "Usuario registrado exitosamente."})