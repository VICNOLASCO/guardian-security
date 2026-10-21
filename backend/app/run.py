import os
import time
from app import create_app
from app.extensions import socketio
from pyngrok import ngrok

app = create_app('development')

if __name__ == '__main__':
    # Solo abrimos Ngrok si estamos en desarrollo local
    if os.getenv("FLASK_ENV") == "development":
        token = os.getenv('NGROK_AUTH_TOKEN')
        if token:
            ngrok.set_auth_token(token)
            try:
                # 1. Limpiar túneles colgados
                for t in ngrok.get_tunnels():
                    ngrok.disconnect(t.public_url)
                ngrok.kill()
                time.sleep(1)
            except Exception as e:
                print(f"Limpiando Ngrok: {e}")
            
            # 2. Crear túnel nuevo
            try:
                tunnel = ngrok.connect(5000)
                print(f"\n🌐 NGROK URL: {tunnel.public_url}\n")
            except Exception as e:
                print(f"\n❌ Error Ngrok: {e}")
                print("El servidor local seguirá funcionando en http://127.0.0.1:5000\n")

    # Ejecutar la app
    socketio.run(
        app,
        host='127.0.0.1',
        port=5000,
        debug=os.environ.get('FLASK_ENV') == 'development',
        allow_unsafe_werkzeug=True
    )