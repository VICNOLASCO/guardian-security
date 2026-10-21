from flask import Blueprint, request, jsonify
from datetime import datetime
import socket, requests
from ..extensions import get_db

archivos_bp = Blueprint('archivos', __name__)

@archivos_bp.route('/estado', methods=['GET'])
def estado():
    return jsonify({
        "estado": "activo", "ip": "192.168.1.45", "dispositivo": "WORKSTATION-01",
        "ultima_conexion": datetime.now().isoformat(),
        "ubicacion": {"ciudad": "Buenos Aires", "lat": -34.6037, "lon": -58.3816, "precision": 25},
        "cifrado_porcentaje": 87, "archivos_protegidos": get_db()['archivos_cifrados'].count_documents({}), "archivos_totales": 154
    })

@archivos_bp.route('/logs', methods=['GET'])
def logs():
    logs = list(get_db()['logs'].find().sort('fecha', -1).limit(50))
    return jsonify([{"fecha": l['fecha'], "accion": l['accion'], "detalle": l['detalle']} for l in logs])

@archivos_bp.route('/ip-puertos', methods=['GET'])
def ip_puertos():
    try: ip_pub = requests.get('https://api.ipify.org?format=json', timeout=3).json().get('ip', 'N/A')
    except: ip_pub = 'No disponible'
    puertos = []
    for p in [22, 80, 443, 3306, 5432, 27017, 5000, 8080]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(0.5)
            if sock.connect_ex(('localhost', p)) == 0: puertos.append(p)
            sock.close()
        except: pass
    return jsonify({'ip_publica': ip_pub, 'puertos_abiertos': puertos, 'ip_local': socket.gethostbyname(socket.gethostname())})

@archivos_bp.route('/accesos', methods=['GET'])
def accesos():
    acc = list(get_db()['rastroe'].find({}).sort('fecha', -1).limit(50))
    for a in acc: a['_id'] = str(a['_id'])
    return jsonify(acc)

@archivos_bp.route('/ubicacion', methods=['POST'])
def ubicacion():
    data = request.json or {}
    if data.get('lat') is not None:
        get_db()['rastroe'].insert_one({'tipo': 'ubicacion', 'lat': data['lat'], 'lon': data['lon'], 'ip': request.remote_addr, 'fecha': datetime.now().isoformat()})
    return jsonify({"success": True})

@archivos_bp.route('/equipos', methods=['GET'])
def equipos():
    return jsonify(list(get_db()['dispositivos'].find({}, {'_id': 0})))