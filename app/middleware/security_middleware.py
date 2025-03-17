from functools import wraps
from flask import request, current_app, g
import time
from utils.security_utils import RateLimiter, SecurityValidator

# Crear instancias de rate limiters para diferentes endpoints
admin_limiter = RateLimiter(max_requests=20, window_seconds=60)  # 20 requests/minute
imap_test_limiter = RateLimiter(max_requests=5, window_seconds=60)  # 5 requests/minute
login_limiter = RateLimiter(max_requests=10, window_seconds=300)  # 10 requests/5 minutes

def init_app(app):
    """Inicializa el middleware de seguridad"""
    
    @app.before_request
    def before_request():
        # Agregar timestamp para medir duración de requests
        g.start = time.time()
        
        # Validar Content-Type para requests POST
        if request.method == 'POST':
            if not request.is_json and not request.form:
                return {'error': 'Content-Type no soportado'}, 415
        
        # Validar tamaño máximo de request
        if request.content_length and request.content_length > 10 * 1024 * 1024:  # 10MB
            return {'error': 'Request demasiado grande'}, 413
            
    @app.after_request
    def after_request(response):
        # Agregar headers de seguridad
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Remover headers sensibles
        response.headers.pop('Server', None)
        
        # Logging de requests lentos
        duration = time.time() - g.start
        if duration > 1.0:  # Log requests más lentos que 1 segundo
            current_app.logger.warning(
                f'Request lento ({duration:.2f}s): {request.method} {request.path}'
            )
            
        return response
        
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return {'error': 'Demasiadas solicitudes. Por favor, intente más tarde.'}, 429

def validate_imap_config(f):
    """Decorator para validar configuración IMAP"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        validator = SecurityValidator()
        
        domain = request.form.get('domain')
        email = request.form.get('email')
        imap_server = request.form.get('imap_server')
        imap_port = request.form.get('imap_port')
        
        if not all([
            validator.validate_domain(domain),
            validator.validate_email(email),
            validator.validate_domain(imap_server),
            validator.validate_port(int(imap_port))
        ]):
            return {'error': 'Datos de configuración IMAP inválidos'}, 400
            
        return f(*args, **kwargs)
    return decorated_function

def sanitize_input(f):
    """Decorator para sanitizar input de usuario"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        validator = SecurityValidator()
        
        if request.is_json:
            # Sanitizar JSON input
            sanitized_json = {
                k: validator.sanitize_string(v) if isinstance(v, str) else v
                for k, v in request.get_json().items()
            }
            request._cached_json = (sanitized_json, request._cached_json[1])
            
        if request.form:
            # Sanitizar form input
            request.form = {
                k: validator.sanitize_string(v) if isinstance(v, str) else v
                for k, v in request.form.items()
            }
            
        return f(*args, **kwargs)
    return decorated_function