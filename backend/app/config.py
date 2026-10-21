import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key')
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    NGROK_AUTH_TOKEN = os.getenv('NGROK_AUTH_TOKEN', '')
    CORS_ORIGINS = ['http://localhost:5000', 'http://127.0.0.1:5000']
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024

config_by_name = {'development': Config, 'production': Config}