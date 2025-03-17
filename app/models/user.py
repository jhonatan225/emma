from app import db
from flask_login import UserMixin
import random
import string

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_guest = db.Column(db.Boolean, default=False)
    linked_guest_key = db.Column(db.String(25), index=True)  # Removida la restricción unique
    
    # Agregar la relación con los emails
    emails = db.relationship('UserEmail', backref='user', lazy=True, cascade='all, delete-orphan')

    def get_available_services(self):
        """Retorna los servicios disponibles según el tipo de usuario"""
        if self.is_guest:
            return {
                'disney': ['homeCode'],
                'netflix': ['updateHome', 'homeCode'],
                'crunchyroll': ['resetLink'],
                'max': ['resetLink'],
                'prime': ['loginCode']  # Agregado permiso para invitados
            }
        # Usuario normal tiene acceso completo
        return {
            'disney': ['loginCode', 'homeCode', 'resetLink'],
            'netflix': ['resetLink', 'updateHome', 'homeCode', 'country'],
            'crunchyroll': ['resetLink'],
            'max': ['resetLink'],
            'prime': ['loginCode']  # Agregado permiso para usuarios normales
        }

    def has_access_to_email(self, email: str) -> bool:
        """
        Verifica si el usuario tiene acceso a un email específico.
        Retorna True si el usuario tiene acceso, False en caso contrario.
        """
        # Los administradores tienen acceso a todos los emails
        if self.is_admin:
            return True
            
        # Verificar cada email del usuario
        for user_email in self.emails:
            # Si el email tiene permiso para buscar cualquier cuenta
            if user_email.can_search_any:
                return True
            # Si el email coincide exactamente
            if user_email.email.lower() == email.lower():
                return True
                
        return False

    @staticmethod
    def generate_guest_key():
        """Genera una key única para invitados"""
        while True:
            numbers = ''.join(random.choices(string.hexdigits.lower(), k=14))
            key = f"invitado-{numbers[:4]}-{numbers[4:8]}-{numbers[8:]}"
            # Verificar que la key no esté en uso por un usuario no invitado
            if not User.query.filter_by(linked_guest_key=key, is_guest=False).first():
                return key

    def __repr__(self):
        return f'<User {self.username}>'

class UserEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    can_search_any = db.Column(db.Boolean, default=False)  # Nuevo campo para permitir búsqueda de cualquier cuenta

    def __repr__(self):
        return f'<UserEmail {self.email}>'

class AllowedEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_domain = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<AllowedEmail {self.email_domain}>'