from .auth import auth_bp
from .admin import admin_bp
from .archivos import archivos_bp
from .cifrado import cifrado_bp # <-- IMPORTANTE

def register_blueprints(app):
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(archivos_bp, url_prefix='/api/files')
    app.register_blueprint(cifrado_bp, url_prefix='/api/crypto') # <-- IMPORTANTE