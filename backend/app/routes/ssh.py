from flask import Blueprint, request, jsonify
import paramiko, secrets, time
from ..utils.auth import token_required, registrar_log

ssh_bp = Blueprint('ssh', __name__)
sesiones_ssh = {} # Memoria local para esta ruta

@ssh_bp.route('/conectar', methods=['POST'])
@token_required
def conectar():
    data = request.json or {}
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=data['ip'], port=int(data.get('puerto', 22)), username=data['usuario'], password=data['password'], timeout=5)
        session_id = secrets.token_hex(16)
        sesiones_ssh[session_id] = {'client': ssh, 'channel': ssh.invoke_shell()}
        registrar_log("ssh_conexion", f"SSH a {data['ip']}", request.user['email'])
        return jsonify({"success": True, "session_id": session_id})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@ssh_bp.route('/ejecutar', methods=['POST'])
@token_required
def ejecutar():
    data = request.json or {}
    if data.get('session_id') not in sesiones_ssh: return jsonify({"success": False, "message": "Sesión no encontrada"}), 404
    try:
        stdin, stdout, stderr = sesiones_ssh[data['session_id']]['client'].exec_command(data['comando'])
        output = stdout.read().decode('utf-8', errors='ignore') + stderr.read().decode('utf-8', errors='ignore')
        return jsonify({"success": True, "output": output})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@ssh_bp.route('/desconectar', methods=['POST'])
@token_required
def desconectar():
    session_id = request.json.get('session_id')
    if session_id in sesiones_ssh:
        sesiones_ssh[session_id]['client'].close()
        del sesiones_ssh[session_id]
    return jsonify({"success": True})