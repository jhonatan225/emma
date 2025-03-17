from functools import wraps
import imaplib
import ssl
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

class IMAPConnectionError(Exception):
    pass

class IMAPTimeout(Exception):
    pass

def with_imap_connection(timeout: int = 30):
    """
    Decorator para manejar conexiones IMAP de forma segura.
    
    Args:
        timeout (int): Timeout en segundos para la conexión IMAP
    """
    def decorator(func):
        @wraps(func)
        def wrapper(config: Dict[str, Any], *args, **kwargs):
            try:
                # Configurar contexto SSL seguro
                context = ssl.create_default_context()
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                
                # Establecer conexión con timeout
                imap = imaplib.IMAP4_SSL(
                    host=config['imap_server'],
                    port=config['imap_port'],
                    ssl_context=context,
                    timeout=timeout
                )
                
                try:
                    # Login
                    imap.login(config['email'], config['password'])
                    
                    # Ejecutar función decorada
                    return func(imap, *args, **kwargs)
                    
                finally:
                    try:
                        imap.logout()
                    except:
                        pass
                        
            except imaplib.IMAP4.timeout:
                logger.error(f"IMAP timeout for {config['email']} on {config['imap_server']}")
                raise IMAPTimeout("La conexión IMAP ha excedido el tiempo de espera")
                
            except imaplib.IMAP4.error as e:
                logger.error(f"IMAP error for {config['email']}: {str(e)}")
                raise IMAPConnectionError(f"Error de conexión IMAP: {str(e)}")
                
            except Exception as e:
                logger.error(f"Unexpected error in IMAP connection: {str(e)}")
                raise IMAPConnectionError(f"Error inesperado: {str(e)}")
                
        return wrapper
    return decorator

def test_imap_connection(config: Dict[str, Any]) -> Optional[str]:
    """
    Prueba una conexión IMAP.
    
    Args:
        config: Diccionario con la configuración IMAP
        
    Returns:
        None si la conexión es exitosa, mensaje de error en caso contrario
    """
    @with_imap_connection(timeout=10)
    def _test(imap):
        # Intentar seleccionar INBOX para verificar permisos
        imap.select('INBOX')
        return None
        
    try:
        return _test(config)
    except (IMAPTimeout, IMAPConnectionError) as e:
        return str(e)
        
def search_recent_emails(config: Dict[str, Any], search_criteria: str, 
                        max_emails: int = 5) -> list:
    """
    Busca emails recientes que coincidan con los criterios.
    
    Args:
        config: Diccionario con la configuración IMAP
        search_criteria: Criterios de búsqueda en formato IMAP
        max_emails: Número máximo de emails a retornar
        
    Returns:
        Lista de IDs de emails encontrados
    """
    @with_imap_connection()
    def _search(imap):
        imap.select('INBOX')
        _, data = imap.search(None, search_criteria)
        if not data[0]:
            return []
            
        # Obtener IDs de emails más recientes
        email_ids = data[0].split()
        return email_ids[-max_emails:]
        
    try:
        return _search(config)
    except (IMAPTimeout, IMAPConnectionError):
        return []