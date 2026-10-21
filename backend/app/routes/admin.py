from flask import Blueprint, request, jsonify, send_file
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import json, io
from bson import json_util
from ..extensions import get_db, sesiones_activas
from ..utils.auth import admin_required
from ..utils.passwords import hash_password

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/usuarios', methods=['GET'])
@admin_required
def listar_usuarios():
    usuarios = list(get_db()['usuarios'].find({}, {'password_hash': 0}))
    for u in usuarios:
        u['id'] = str(u['_id']); del u['_id']
    return jsonify(usuarios)

@admin_bp.route('/usuarios/<user_id>', methods=['PUT'])
@admin_required
def editar_usuario(user_id):
    data = request.json or {}
    update = {}
    if data.get('nombre'): update['nombre'] = data['nombre']
    if data.get('rol'): update['rol'] = data['rol']
    if update: get_db()['usuarios'].update_one({'_id': ObjectId(user_id)}, {'$set': update})
    return jsonify({"success": True})

@admin_bp.route('/usuarios/<user_id>', methods=['DELETE'])
@admin_required
def eliminar_usuario(user_id):
    get_db()['usuarios'].delete_one({'_id': ObjectId(user_id)})
    return jsonify({"success": True})

@admin_bp.route('/usuarios/<user_id>/cambiar-password', methods=['PUT'])
@admin_required
def cambiar_password_usuario(user_id):
    nueva = request.json.get('nueva_password')
    if nueva: get_db()['usuarios'].update_one({'_id': ObjectId(user_id)}, {'$set': {'password_hash': hash_password(nueva)}})
    return jsonify({"success": True})

@admin_bp.route('/logs', methods=['GET'])
@admin_required
def logs():
    logs = list(get_db()['logs'].find().sort('fecha', -1).limit(request.args.get('limit', 100, type=int)))
    for l in logs: l['_id'] = str(l['_id'])
    return jsonify(logs)

@admin_bp.route('/sesiones', methods=['GET'])
@admin_required
def sesiones():
    return jsonify(list(sesiones_activas.values()))

@admin_bp.route('/auditoria', methods=['GET'])
@admin_required
def auditoria():
    query = {}
    if request.args.get('usuario'): query['usuario'] = request.args['usuario']
    if request.args.get('accion'): query['accion'] = request.args['accion']
    logs = list(get_db()['logs'].find(query).sort('fecha', -1).limit(200))
    for l in logs: l['_id'] = str(l['_id'])
    return jsonify({'logs': logs, 'total': len(logs), 'usuarios': get_db()['logs'].distinct('usuario'), 'acciones': get_db()['logs'].distinct('accion')})

@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    hace_24h = datetime.now() - timedelta(hours=24)
    actividad = []
    for i in range(24):
        hora = datetime.now() - timedelta(hours=i)
        inicio = hora.replace(minute=0, second=0, microsecond=0)
        count = get_db()['logs'].count_documents({'fecha': {'$gte': inicio.isoformat(), '$lt': (inicio + timedelta(hours=1)).isoformat()}})
        actividad.append({'hora': hora.strftime('%H:00'), 'eventos': count})

    return jsonify({
        'total_usuarios': get_db()['usuarios'].count_documents({}),
        'usuarios_activos': get_db()['usuarios'].count_documents({'activo': True}),
        'usuarios_bloqueados': get_db()['usuarios'].count_documents({'activo': False}),
        'sesiones_hoy': get_db()['logs'].count_documents({'accion': 'login_exitoso', 'fecha': {'$gte': hace_24h.isoformat()}}),
        'intentos_fallidos': get_db()['logs'].count_documents({'accion': 'login_fallido', 'fecha': {'$gte': hace_24h.isoformat()}}),
        'actividad_por_hora': actividad
    })

@admin_bp.route('/backup', methods=['GET'])
@admin_required
def backup():
    coleccion = request.args.get('coleccion', 'usuarios')
    data = list(get_db()[coleccion].find({}))
    for doc in data: doc['_id'] = str(doc['_id'])
    json_data = json.dumps(data, default=json_util.default, indent=2)
    return send_file(io.BytesIO(json_data.encode('utf-8')), as_attachment=True, download_name=f'backup_{coleccion}.json', mimetype='application/json')

@admin_bp.route('/politicas-seguridad', methods=['GET', 'POST'])
@admin_required
def politicas():
    if request.method == 'POST':
        data = request.json or {}
        get_db()['configuracion'].update_one({}, {'$set': data}, upsert=True)
        return jsonify({"success": True, "message": "Políticas guardadas"})
    config = get_db()['configuracion'].find_one({}) or {}
    return jsonify({
        'longitud_minima': config.get('longitud_minima', 8), 'requiere_mayuscula': config.get('requiere_mayuscula', True),
        'requiere_numero': config.get('requiere_numero', True), 'requiere_especial': config.get('requiere_especial', True),
        'intentos_maximos': config.get('intentos_maximos', 5), 'bloqueo_tiempo': config.get('bloqueo_tiempo', 30),
        '2fa_obligatorio': config.get('2fa_obligatorio', False)
    })

@admin_bp.route('/configuracion', methods=['GET', 'POST'])
@admin_required
def config():
    if request.method == 'POST':
        data = request.json or {}
        data.pop('admin_email', None)
        get_db()['configuracion'].update_one({}, {'$set': data}, upsert=True)
        return jsonify({"success": True, "message": "Guardado"})
    config = get_db()['configuracion'].find_one({}) or {}
    config['_id'] = str(config.get('_id', ''))
    return jsonify(config)