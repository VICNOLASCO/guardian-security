from flask import Blueprint, jsonify
from datetime import datetime, timedelta
from ..extensions import get_db

stats_bp = Blueprint('stats', __name__)

@stats_bp.route('/estadisticas', methods=['GET'])
def estadisticas():
    db = get_db()
    hoy = datetime.now()
    dias = [(hoy - timedelta(days=i)).strftime('%a %d/%m') for i in range(6, -1, -1)]

    matriz = []
    for i, dia_offset in enumerate(range(6, -1, -1)):
        dia_base = (hoy - timedelta(days=dia_offset)).replace(hour=0, minute=0, second=0, microsecond=0)
        for h in range(24):
            inicio = dia_base + timedelta(hours=h)
            count = db['logs'].count_documents({'fecha': {'$gte': inicio.isoformat(), '$lt': (inicio + timedelta(hours=1)).isoformat()}})
            if count > 0: matriz.append({'dia': i, 'hora': h, 'count': count})

    logs_por_dia = []
    for i in range(6, -1, -1):
        dia = hoy - timedelta(days=i)
        inicio = dia.replace(hour=0, minute=0, second=0, microsecond=0)
        count = db['logs'].count_documents({'fecha': {'$gte': inicio.isoformat(), '$lt': (inicio + timedelta(days=1)).isoformat()}})
        logs_por_dia.append({'dia': dia.strftime('%d/%m'), 'eventos': count})

    return jsonify({
        'total_usuarios': db['usuarios'].count_documents({}), 'total_logs': db['logs'].count_documents({}),
        'total_dispositivos': db['dispositivos'].count_documents({}), 'total_archivos_cifrados': db['archivos_cifrados'].count_documents({}),
        'matriz_3d': {'dias': dias, 'matriz': matriz},
        'distribucion_roles': {'admins': db['usuarios'].count_documents({'rol': 'admin'}), 'users': db['usuarios'].count_documents({'rol': 'user'})},
        'acciones_top': [{'accion': a['_id'] or 'desconocida', 'count': a['count']} for a in db['logs'].aggregate([{'$group': {'_id': '$accion', 'count': {'$sum': 1}}}, {'$sort': {'count': -1}}, {'$limit': 6}])],
        'logs_por_dia': logs_por_dia
    })