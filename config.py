import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'Htgs683kdojcu89203')
    
    # Configuración PostgreSQL con parámetros de conexión mejorados
    SQLALCHEMY_DATABASE_URI = "postgresql+pg8000://lvs_user:4SdeB2n6R9M61dyCzvSH64TEzP17TKzX@dpg-ctli2ojqf0us7388tc60-a.oregon-postgres.render.com/lvs"
    
    # Agregar estos parámetros
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_timeout': 30,
        'pool_recycle': 900,
        'max_overflow': 2,
        'connect_args': {
            'timeout': 30
        }
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Credenciales del administrador
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Triunfador21@')
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@gmail.com')