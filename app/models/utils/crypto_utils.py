from cryptography.fernet import Fernet
from flask import current_app
import os
from dotenv import load_dotenv

load_dotenv()

def get_encryption_key():
    """Obtiene o genera una clave de encriptación"""
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        # Generar nueva clave si no existe
        key = Fernet.generate_key()
        with open('.env', 'a') as f:
            f.write(f'\nENCRYPTION_KEY={key.decode()}\n')
    else:
        key = key.encode()
    return key

def encrypt_text(text):
    """Encripta un texto usando Fernet"""
    if not text:
        return None
    key = get_encryption_key()
    f = Fernet(key)
    return f.encrypt(text.encode())

def decrypt_text(encrypted_data):
    """Desencripta datos usando Fernet"""
    if not encrypted_data:
        return None
    key = get_encryption_key()
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()