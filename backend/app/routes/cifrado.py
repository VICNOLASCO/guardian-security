from flask import Blueprint, request, jsonify, send_file
import io, os, zipfile, tempfile, shutil, traceback
from datetime import datetime
from ..utils.auth import token_required
from ..services import crypto_service

cifrado_bp = Blueprint('cifrado', __name__)

@cifrado_bp.route('/cifrar', methods=['POST'])
@token_required
def cifrar():
    try:
        file = request.files.get('archivo')
        if not file or file.filename == '': return jsonify({'error': 'No se envió archivo'}), 400
        archivo_final, nombre = crypto_service.cifrar_archivo(file, request.user['email'])
        return send_file(io.BytesIO(archivo_final), as_attachment=True, download_name=f'{nombre}.bin', mimetype='application/octet-stream')
    except Exception as e:
        traceback.print_exc(); return jsonify({'error': str(e)}), 500

@cifrado_bp.route('/descifrar', methods=['POST'])
@token_required
def descifrar():
    try:
        file = request.files.get('archivo')
        if not file or not file.filename.lower().endswith('.bin'): return jsonify({'error': 'Debe ser .bin'}), 400
        datos_descifrados, nombre = crypto_service.descifrar_archivo(file.read(), request.user['email'])
        return send_file(io.BytesIO(datos_descifrados), as_attachment=True, download_name=nombre, mimetype='application/octet-stream')
    except ValueError as e: return jsonify({'error': str(e)}), 404
    except Exception as e:
        traceback.print_exc(); return jsonify({'error': str(e)}), 500

@cifrado_bp.route('/cifrar-carpeta', methods=['POST'])
@token_required
def cifrar_carpeta():
    try:
        files = request.files.getlist('archivos')
        rutas = request.form.get('rutas', '').split('|') if request.form.get('rutas') else []
        temp_dir = tempfile.mkdtemp()
        for idx, file in enumerate(files):
            if file.filename == '': continue
            ruta_rel = rutas[idx] if idx < len(rutas) else file.filename
            archivo_final, nombre_orig = crypto_service.cifrar_archivo(file, request.user['email'])
            dir_dest = os.path.join(temp_dir, os.path.dirname(ruta_rel))
            os.makedirs(dir_dest, exist_ok=True)
            with open(os.path.join(dir_dest, f"{nombre_orig}.bin"), 'wb') as f: f.write(archivo_final)
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files_in in os.walk(temp_dir):
                for f in files_in:
                    fp = os.path.join(root, f); zf.write(fp, os.path.relpath(fp, temp_dir))
        zip_buffer.seek(0); shutil.rmtree(temp_dir, ignore_errors=True)
        return send_file(zip_buffer, as_attachment=True, download_name=f'Carpeta_Cifrada_{datetime.now().strftime("%Y%m%d")}.zip', mimetype='application/zip')
    except Exception as e:
        traceback.print_exc(); return jsonify({'error': str(e)}), 500

@cifrado_bp.route('/descifrar-carpeta', methods=['POST'])
@token_required
def descifrar_carpeta():
    try:
        files = request.files.getlist('archivos')
        rutas = request.form.getlist('rutas')
        if len(rutas) == 1 and '|' in rutas[0]: rutas = rutas[0].split('|')
        temp_dir = tempfile.mkdtemp()
        for idx, file in enumerate(files):
            if file.filename == '': continue
            ruta_rel = rutas[idx] if idx < len(rutas) else file.filename
            datos, nombre_salida = crypto_service.descifrar_archivo(file.read(), request.user['email'])
            dir_dest = os.path.join(temp_dir, os.path.dirname(ruta_rel))
            os.makedirs(dir_dest, exist_ok=True)
            with open(os.path.join(dir_dest, nombre_salida), 'wb') as f: f.write(datos)
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files_in in os.walk(temp_dir):
                for f in files_in:
                    fp = os.path.join(root, f); zf.write(fp, os.path.relpath(fp, temp_dir))
        zip_buffer.seek(0); shutil.rmtree(temp_dir, ignore_errors=True)
        return send_file(zip_buffer, as_attachment=True, download_name=f'Carpeta_Descifrada_{datetime.now().strftime("%Y%m%d")}.zip', mimetype='application/zip')
    except Exception as e:
        traceback.print_exc(); return jsonify({'error': str(e)}), 500