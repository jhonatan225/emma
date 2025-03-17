from app import db
from datetime import datetime
from .utils.crypto_utils import encrypt_text, decrypt_text

class ImapConfiguration(db.Model):
    __tablename__ = 'imap_configurations'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(120), nullable=False)  # Removed unique=True
    email = db.Column(db.String(120), unique=True, nullable=False)  # Added unique=True
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    imap_server = db.Column(db.String(120), nullable=False)
    imap_port = db.Column(db.Integer, nullable=False, default=993)
    is_active = db.Column(db.Boolean, default=True)
    last_modified = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Encripta y guarda la contraseña"""
        self.password_encrypted = encrypt_text(password)

    def get_password(self):
        """Obtiene y desencripta la contraseña"""
        return decrypt_text(self.password_encrypted)

    def to_dict(self):
        """Convierte el modelo a diccionario para la API"""
        return {
            'id': self.id,
            'domain': self.domain,
            'email': self.email,
            'imap_server': self.imap_server,
            'imap_port': self.imap_port,
            'is_active': self.is_active,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None
        }

    def __repr__(self):
        return f'<ImapConfiguration {self.domain}>'