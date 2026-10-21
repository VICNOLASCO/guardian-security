from pymongo import MongoClient
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = None
sesiones_activas = {} # <-- Para el panel de administración

socketio = SocketIO(async_mode='threading', cors_allowed_origins="*")
limiter = Limiter(key_func=get_remote_address, default_limits=["500 per hour"])

def init_mongo(uri):
    global db
    client = MongoClient(uri)
    db = client['guardian_db']
    db['usuarios'].create_index('email', unique=True)
    db['logs'].create_index('fecha')
    db['archivos_cifrados'].create_index('fecha')

def get_db():
    return db