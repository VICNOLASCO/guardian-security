from flask import Flask, send_from_directory
from .config import config_by_name
from .extensions import socketio, limiter, init_mongo, get_db
from .routes import register_blueprints
from .utils.passwords import hash_password
from flask_cors import CORS

def create_app(config_name='development'):
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_object(config_by_name[config_name])
    
    CORS(app, origins=app.config['CORS_ORIGINS'])
    limiter.init_app(app)
    socketio.init_app(app)
    
    # Iniciar Base de Datos
    init_mongo(app.config['MONGO_URI'])

    # ✅ CREAR/ACTUALIZAR ADMIN AUTOMÁTICAMENTE
    with app.app_context():
        db = get_db()
        admin = db['usuarios'].find_one({'email': 'admin@guardian.com'})
        if not admin:
            # Si no existe, lo crea
            db['usuarios'].insert_one({
                'email': 'admin@guardian.com',
                'password_hash': hash_password("admin123"),
                'nombre': 'Administrador',
                'rol': 'admin',
                'activo': True,
                'fecha_creacion': '2026-01-01T00:00:00'
            })
            print("✅ Usuario admin creado (pass: admin123)")
        else:
            # Si existe, verifica si la contraseña NO es bcrypt (empieza con $2b$)
            if not str(admin.get('password_hash', '')).startswith('$2b$'):
                db['usuarios'].update_one(
                    {'email': 'admin@guardian.com'},
                    {'$set': {'password_hash': hash_password("admin123")}}
                )
                print("✅ Contraseña de admin actualizada a bcrypt (pass: admin123)")

    register_blueprints(app)

    @app.route('/')
    def index(): return send_from_directory('templates', 'index.html')
    @app.route('/login.html')
    def login(): return send_from_directory('templates', 'login.html')
    @app.route('/dashboard.html')
    def dashboard(): return send_from_directory('templates', 'dashboard.html')

    return app