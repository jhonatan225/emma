from functools import wraps
from flask import current_app, request, abort
from datetime import datetime, timedelta
import re
import logging
from typing import Optional
import ssl
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)

class RateLimiter:
    """Implementa rate limiting basado en memoria para endpoints críticos"""
    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = {}
    
    def is_rate_limited(self, key: str) -> bool:
        now = datetime.now()
        # Limpiar entradas antiguas
        self._clean_old_entries(now)
        
        # Obtener o inicializar lista de timestamps para esta key
        requests = self._requests.get(key, [])
        
        if len(requests) >= self.max_requests:
            return True
            
        # Agregar nuevo timestamp
        requests.append(now)
        self._requests[key] = requests
        return False
        
    def _clean_old_entries(self, now: datetime):
        cutoff = now - timedelta(seconds=self.window_seconds)
        for key in list(self._requests.keys()):
            self._requests[key] = [ts for ts in self._requests[key] if ts > cutoff]
            if not self._requests[key]:
                del self._requests[key]

class SecurityValidator:
    """Valida entradas y previene inyecciones"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Valida formato de email y previene inyección"""
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(email_pattern.match(email))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Valida formato de dominio"""
        domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$')
        return bool(domain_pattern.match(domain))
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Valida que el puerto esté en rango válido"""
        return 1 <= port <= 65535
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitiza strings para prevenir XSS"""
        return re.sub(r'[<>&"\']', '', value)

class SecureSSLContext:
    """Proporciona contexto SSL seguro para conexiones"""
    
    @staticmethod
    def create_context() -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

class AdvancedEncryption:
    """Proporciona encriptación avanzada para datos sensibles"""
    
    def __init__(self, key: Optional[str] = None):
        if key:
            self.key = base64.urlsafe_b64decode(key)
        else:
            self.key = self._generate_key()
        self.fernet = Fernet(base64.urlsafe_b64encode(self.key))
    
    @staticmethod
    def _generate_key() -> bytes:
        """Genera una clave segura usando PBKDF2"""
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(secrets.token_bytes(32))
        return key
    
    def encrypt(self, data: str) -> bytes:
        """Encripta datos usando Fernet"""
        return self.fernet.encrypt(data.encode())
    
    def decrypt(self, token: bytes) -> str:
        """Desencripta datos usando Fernet"""
        return self.fernet.decrypt(token).decode()

def require_admin(f):
    """Decorator para asegurar que solo administradores accedan"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not getattr(request, 'current_user', None) or not request.current_user.is_admin:
            logger.warning(f"Intento de acceso no autorizado a {request.endpoint}")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(limiter: RateLimiter):
    """Decorator para implementar rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = f"{request.remote_addr}:{request.endpoint}"
            if limiter.is_rate_limited(key):
                logger.warning(f"Rate limit excedido para {key}")
                abort(429)
            return f(*args, **kwargs)
        return decorated_function
    return decorator