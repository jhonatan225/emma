import os
from datetime import timedelta

# Configuración de seguridad base
SECURITY_CONFIG = {
    # Sesión
    'PERMANENT_SESSION_LIFETIME': timedelta(hours=1),
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    
    # CSRF
    'WTF_CSRF_ENABLED': True,
    'WTF_CSRF_TIME_LIMIT': 3600,
    
    # SSL/TLS
    'SSL_VERIFY': True,
    'SSL_VERSION': 'TLSv1_2',
    
    # Rate Limiting
    'RATELIMIT_ENABLED': True,
    'RATELIMIT_HEADERS_ENABLED': True,
    
    # Timeout de conexiones
    'IMAP_TIMEOUT': 30,  # segundos
    'REQUEST_TIMEOUT': 60,  # segundos
    
    # Tamaños máximos
    'MAX_CONTENT_LENGTH': 10 * 1024 * 1024,  # 10MB
    'MAX_UPLOAD_SIZE': 5 * 1024 * 1024,  # 5MB
    
    # Logging
    'LOG_LEVEL': 'INFO',
    'LOG_FILE': 'security.log',
    
    # Headers de seguridad
    'SECURE_HEADERS': {
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
    }
}

def load_security_config(app):
    """Carga la configuración de seguridad en la aplicación"""
    
    # Cargar configuración base
    for key, value in SECURITY_CONFIG.items():
        app.config[key] = value
    
    # Sobrescribir con variables de entorno si existen
    for key in SECURITY_CONFIG.keys():
        env_value = os.getenv(key)
        if env_value is not None:
            # Convertir valores según el tipo
            if isinstance(SECURITY_CONFIG[key], bool):
                app.config[key] = env_value.lower() in ('true', '1', 'yes')
            elif isinstance(SECURITY_CONFIG[key], int):
                app.config[key] = int(env_value)
            elif isinstance(SECURITY_CONFIG[key], timedelta):
                app.config[key] = timedelta(seconds=int(env_value))
            else:
                app.config[key] = env_value
    
    return app