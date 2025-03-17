from flask import current_app
import imaplib
import re
import ssl
import logging
from email import message_from_bytes
from email.policy import default
from app import db
from datetime import datetime, timedelta
from app.models.user import User, UserEmail
from app.models.imap_config import ImapConfiguration
from app.models.user import AllowedEmail
import traceback
from threading import Lock

logger = logging.getLogger(__name__)

class EmailService:
    _imap_connections = {}
    _connection_lock = Lock()

    # Direcciones de correo para la búsqueda
    FROM_ADDRESSES = {
        'disney': [
            'disneyplus@mail2.disneyplus.com',
            'disneyplus@mail.disneyplus.com'
        ],
        'netflix': [
            'info@account.netflix.com'
        ],
        'crunchyroll': [
            'hello@info.crunchyroll.com'
        ],
        'max': [         
            'no-reply@message.max.com'     
        ],
        'prime': [
        'account-update@primevideo.com'
        ]
    }

    # Patrones regex para cada servicio y opción
    PATTERNS = {
    'disney': {
        'loginCode': re.compile(r'<td[^>]*>\s*(\d{6})\s*</td>', re.IGNORECASE),
        'homeCode': re.compile(r'<div[^>]*class="body"[^>]*>[\s\S]*?(\d{4})[\s\S]*?</div>', re.IGNORECASE)
    },
    'netflix': {
        'resetLink': re.compile(r'https:\/\/www\.netflix\.com\/password\?g=[\s\S]+?(?=\s*\[|\s*$)', re.IGNORECASE),
        'updateHome': re.compile(r'https:\/\/www\.netflix\.com\/account\/update-primary-location\?nftoken=[\s\S]+?(?=\s*\[|\s*$)+', re.IGNORECASE),
        'homeCode': re.compile(r'https:\/\/www\.netflix\.com\/account\/travel\/verify\?nftoken=[\s\S]+?(?=\s*\[|\s*$)+', re.IGNORECASE)
    },
    'crunchyroll': {
        'resetLink': re.compile(r'https:\/\/links\.mail\.crunchyroll\.com\/ls\/click\?upn=[a-zA-Z0-9._\-=&%+]+', re.IGNORECASE)
    },
    'max': {
        'resetLink': re.compile(r'https:\/\/auth\.max\.com\/set-new-password\?passwordResetToken=[a-zA-Z0-9_\-=]+', re.IGNORECASE)
    },
    'prime': {
        'loginCode': re.compile(r'class="otp">\s*(\d{6})', re.IGNORECASE | re.DOTALL)
    }
}

    @staticmethod
    def normalize_email(email: str) -> tuple[str, str]:
        """
        Normaliza un email manteniendo la parte después del + y separando usuario y dominio.
        Returns: (email_completo, dominio)
        """
        try:
            if '@' not in email:
                return email, ''

            # Tomar la última ocurrencia de @ para manejar emails malformados
            parts = email.rsplit('@', 1)
            if len(parts) != 2:
                return email, ''
                
            user, domain = parts
            normalized_email = f"{user}@{domain}"
            return normalized_email, domain
        except Exception as e:
            logger.error(f"Error normalizing email {email}: {str(e)}")
            return email, email.rsplit('@', 1)[-1] if '@' in email else ''

    @staticmethod
    def verify_email_access(user_id, email):
        """Verifica si el usuario tiene acceso al correo especificado."""
        try:
            user = User.query.get(user_id)
            if not user:
                logger.error(f"Usuario no encontrado: {user_id}")
                return False
            
            normalized_email, _ = EmailService.normalize_email(email)
            
            if user.is_guest:
                # Si es invitado, buscar el usuario principal
                main_user = User.query.filter_by(
                    linked_guest_key=user.linked_guest_key,
                    is_guest=False
                ).first()
                
                if main_user:
                    # Verificar si tiene permiso de búsqueda abierta
                    if any(email.can_search_any for email in main_user.emails):
                        return True
                    
                    # Si no, verificar coincidencia exacta
                    for ue in main_user.emails:
                        norm_ue, _ = EmailService.normalize_email(ue.email)
                        if norm_ue == normalized_email:
                            return True
            else:
                # Verificar si tiene permiso de búsqueda abierta
                if any(email.can_search_any for email in user.emails):
                    return True
                
                # Si no, verificar coincidencia exacta
                for ue in user.emails:
                    norm_ue, _ = EmailService.normalize_email(ue.email)
                    if norm_ue == normalized_email:
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error verificando acceso a email: {str(e)}")
            return False

    @staticmethod
    def get_imap_configs(email: str) -> list[ImapConfiguration]:
        """
        Obtiene todas las configuraciones IMAP aplicables para un email.
        Primero busca configuración específica, luego por dominio, y finalmente todas si el dominio está permitido.
        """
        try:
            normalized_email, domain = EmailService.normalize_email(email)
            configs = []

            # 1. Buscar configuración específica para el email normalizado
            specific_config = ImapConfiguration.query.filter_by(
                email=normalized_email,
                is_active=True
            ).first()
            if specific_config:
                return [specific_config]

            # 2. Buscar configuraciones para el dominio
            domain_configs = ImapConfiguration.query.filter_by(
                domain=domain,
                is_active=True
            ).all()
            if domain_configs:
                return domain_configs

            # 3. Si el dominio está permitido, devolver todas las configuraciones activas
            if AllowedEmail.query.filter_by(email_domain=domain).first():
                return ImapConfiguration.query.filter_by(is_active=True).all()

            return []

        except Exception as e:
            logger.error(f"Error getting IMAP configs: {str(e)}")
            return []

    @classmethod
    def get_cached_connection(cls, config, force_new=False):
        """
        Obtiene una conexión IMAP cacheada o crea una nueva
        Args:
            config: Configuración IMAP
            force_new: Forzar nueva conexión aunque exista una cacheada
        Returns:
            Conexión IMAP activa
        """
        connection_key = f"{config.email}:{config.imap_server}"
        
        with cls._connection_lock:
            connection_info = cls._imap_connections.get(connection_key)
            
            # Verificar si la conexión existe y está activa
            if not force_new and connection_info:
                imap, last_used = connection_info
                if (datetime.now() - last_used) < timedelta(minutes=5):
                    try:
                        imap.noop()  # Verificar si la conexión sigue activa
                        cls._imap_connections[connection_key] = (imap, datetime.now())
                        return imap
                    except:
                        # Si falla noop(), creamos nueva conexión
                        pass
                        
            # Si llegamos aquí, necesitamos una nueva conexión
            try:
                # Cerrar conexión anterior si existe
                if connection_info:
                    old_imap, _ = connection_info
                    try:
                        old_imap.logout()
                    except:
                        pass
                
                # Crear nuevo contexto SSL seguro
                context = ssl.create_default_context()
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                
                # Establecer nueva conexión
                new_imap = imaplib.IMAP4_SSL(
                    host=config.imap_server,
                    port=config.imap_port,
                    ssl_context=context,
                    timeout=30
                )
                new_imap.login(config.email, config.get_password())
                
                # Cachear la nueva conexión
                cls._imap_connections[connection_key] = (new_imap, datetime.now())
                return new_imap
                
            except Exception as e:
                logger.error(f"Error creating IMAP connection: {str(e)}")
                raise

    @classmethod
    def cleanup_connections(cls):
        """Limpia conexiones IMAP antiguas"""
        with cls._connection_lock:
            current_time = datetime.now()
            for key, (imap, last_used) in list(cls._imap_connections.items()):
                if (current_time - last_used) > timedelta(minutes=10):
                    try:
                        imap.logout()
                    except:
                        pass
                    del cls._imap_connections[key]

    @classmethod
    def search_emails(cls, to_address: str, service: str) -> tuple[bool, bytes | None, str | None]:
        try:
            original_email = to_address
            base_email = original_email.split('+')[0] + '@' + original_email.split('@')[1]
            normalized_email, domain = cls.normalize_email(base_email)
            
            configs = cls.get_imap_configs(normalized_email)
            if not configs:
                return False, None, "No hay configuración IMAP disponible para este correo"

            last_error = None
            
            # Intentar con cada configuración disponible
            for config in configs:
                try:
                    # Siempre forzar una nueva conexión IMAP para obtener los mensajes más recientes
                    imap = cls.get_cached_connection(config, force_new=True)
                    
                    try:
                        imap.select('INBOX')
                    except imaplib.IMAP4.error as e:
                        logger.warning(f"Error selecting INBOX: {str(e)}")
                        continue

                    # Buscar correos del servicio usando el email original completo
                    for from_address in cls.FROM_ADDRESSES.get(service, []):
                        try:
                            search_criteria = f'(FROM "{from_address}" TO "{original_email}")'
                            logger.info(f"Buscando con criterio: {search_criteria}")
                            result, data = imap.search(None, search_criteria)

                            if result == 'OK' and data[0]:
                                # Obtener el email más reciente
                                latest_email_id = data[0].split()[-1]
                                result, msg_data = imap.fetch(latest_email_id, '(RFC822)')
                                
                                if result == 'OK':
                                    logger.info("Email encontrado. Contenido del mensaje:")
                                    try:
                                        msg = message_from_bytes(msg_data[0][1], policy=default)
                                        email_text = cls.extract_email_text(msg)
                                        return True, msg_data[0][1], None
                                    except Exception as e:
                                        logger.error(f"Error al procesar contenido del email: {str(e)}")

                        except imaplib.IMAP4.error as e:
                            last_error = f"Error buscando emails: {str(e)}"
                            logger.error(f"{last_error}\n{traceback.format_exc()}")
                            continue

                except Exception as e:
                    last_error = f"Error de conexión IMAP: {str(e)}"
                    logger.error(f"{last_error}\n{traceback.format_exc()}")
                    continue

            return False, None, last_error or "No se encontraron correos que coincidan con los criterios"
            
        except Exception as e:
            logger.error(f"Error general en search_emails: {str(e)}")
            return False, None, f"Error al buscar emails: {str(e)}"
        
        finally:
            # Limpiar conexiones antiguas
            cls.cleanup_connections()

    @staticmethod
    def extract_email_text(msg):
        """Extrae el texto de un mensaje de correo electrónico."""
        email_text = ""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() in ('text/plain', 'text/html'):
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                email_text += payload.decode('utf-8')
                            except UnicodeDecodeError:
                                try:
                                    email_text += payload.decode('latin-1')
                                except UnicodeDecodeError:
                                    try:
                                        email_text += payload.decode('iso-8859-1')
                                    except UnicodeDecodeError:
                                        logger.error("Failed to decode email part")
                                        continue
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    try:
                        email_text = payload.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            email_text = payload.decode('latin-1')
                        except UnicodeDecodeError:
                            try:
                                email_text = payload.decode('iso-8859-1')
                            except UnicodeDecodeError:
                                logger.error("Failed to decode email")
                                return ""
                                
            logger.debug(f"Email text extracted successfully, length: {len(email_text)}")
            return email_text
            
        except Exception as e:
            logger.error(f"Error extracting email text: {str(e)}")
            return ""

    @classmethod
    def process_email(cls, raw_email, service_type, option=None):
        try:
            msg = message_from_bytes(raw_email, policy=default)
            email_text = cls.extract_email_text(msg)
            
            if not email_text:
                logger.error("No se pudo extraer texto del email")
                return False, None
            
            # Procesar según el servicio
            if service_type == 'disney':
                patterns = cls.PATTERNS['disney']
                if option not in patterns:
                    logger.error(f"Opción no válida para Disney: {option}")
                    return False, None
                pattern = patterns[option]
                match = pattern.search(email_text)
                
                if match:
                    result = match.group(1)
                    logger.info(f"Patrón encontrado para Disney {option}")
                    return True, result
                    
            elif service_type == 'netflix':
                patterns = cls.PATTERNS['netflix']
                if option == 'country':
                    country_code = msg.get('X-localeCountry', '').strip()
                    if country_code:
                        if '::' in country_code:
                            country_code = country_code.split('::')[1]
                        logger.info(f"Código de país encontrado: {country_code}")
                        return True, country_code
                    return False, None
                
                if option not in patterns:
                    logger.error(f"Opción no válida para Netflix: {option}")
                    return False, None
                    
                pattern = patterns[option]
                match = pattern.search(email_text)
                
                if match:
                    link = match.group(0).strip()
                    link = link.split(']')[0].strip()
                    link = link.replace('&amp;', '&')
                    logger.info(f"Link de Netflix encontrado para {option}")
                    return True, link

            elif service_type == 'prime':
                patterns = cls.PATTERNS['prime']
                if option not in patterns:
                    logger.error(f"Opción no válida para Prime: {option}")
                    return False, None
                    
                pattern = patterns[option]
                match = pattern.search(email_text)
                
                if match:
                    result = match.group(1)
                    logger.info(f"Patrón encontrado para Prime {option}")
                    return True, result

            elif service_type == 'crunchyroll':
                patterns = cls.PATTERNS['crunchyroll']
                if option not in patterns:
                    logger.error(f"Opción no válida para Crunchyroll: {option}")
                    return False, None
                    
                pattern = patterns[option]
                match = pattern.search(email_text)
                
                if match:
                    link = match.group(0).strip()
                    logger.info(f"Link de Crunchyroll encontrado para {option}")
                    return True, link

            elif service_type == 'max':
                patterns = cls.PATTERNS['max']
                if option not in patterns:
                    logger.error(f"Opción no válida para Max: {option}")
                    return False, None
                    
                pattern = patterns[option]
                match = pattern.search(email_text)
                
                if match:
                    link = match.group(0).strip()
                    logger.info(f"Link de Max encontrado para {option}")
                    return True, link
                
            logger.warning(f"No se encontró información para {service_type} - {option}")
            return False, None

        except Exception as e:
            logger.error(f"Error procesando email: {str(e)}\n{traceback.format_exc()}")
            return False, None

    @classmethod
    def format_search_result(cls, result: str, service_type: str, option: str) -> str:
        """
        Formatea el resultado de la búsqueda según el servicio y opción.
        
        Args:
            result: Resultado encontrado
            service_type: Tipo de servicio
            option: Opción específica
            
        Returns:
            str: Resultado formateado
        """
        try:
            if service_type == 'netflix':
                if option in ['resetLink', 'updateHome', 'homeCode']:
                    # Asegurar que el link esté limpio y formateado
                    return result.replace('&amp;', '&').strip()
                elif option == 'country':
                    return result.upper().strip()
            elif service_type == 'disney':
                if option in ['loginCode', 'homeCode']:
                    # Asegurar que solo haya números
                    return ''.join(filter(str.isdigit, result))
                    
            return result.strip()
            
        except Exception as e:
            logger.error(f"Error formatting result: {str(e)}")
            return result

    @classmethod
    def validate_result(cls, result: str, service_type: str, option: str) -> bool:
        """
        Valida que el resultado cumpla con el formato esperado.
        
        Args:
            result: Resultado a validar
            service_type: Tipo de servicio
            option: Opción específica
            
        Returns:
            bool: True si el resultado es válido
        """
        try:
            if not result:
                return False
                
            if service_type == 'netflix':
                if option in ['resetLink', 'updateHome', 'homeCode']:
                    # Validar que sea un link de Netflix válido
                    return bool(re.match(r'https://www\.netflix\.com/[a-zA-Z0-9/?=&%+\-]+', result))
                elif option == 'country':
                    # Validar código de país (2 caracteres)
                    return bool(re.match(r'^[A-Z]{2}$', result))
                    
            elif service_type == 'disney':
                if option == 'loginCode':
                    # Validar código de 6 dígitos
                    return bool(re.match(r'^\d{6}$', result))
                elif option == 'homeCode':
                    # Validar código de 4 dígitos
                    return bool(re.match(r'^\d{4}$', result))

            elif service_type == 'crunchyroll':
                if option == 'resetLink':
                    # Validar que sea un link de Crunchyroll válido
                    return bool(re.match(r'https://links\.mail\.crunchyroll\.com/ls/click\?[a-zA-Z0-9=\-_&%]+', result))

            elif service_type == 'max':
                if option == 'resetLink':
                    # Validar que sea un link de Max válido
                    return bool(re.match(r'https://ablink\.marketing\.max\.com/ls/click\?upn=[a-zA-Z0-9._\-=%]+', result))

            elif service_type == 'prime':
                if option == 'loginCode':
                    # Validar código de 6 dígitos
                    return bool(re.match(r'^\d{6}$', result))
                        
            return True
                
        except Exception as e:
            logger.error(f"Error validating result: {str(e)}")
            return False

    @classmethod
    def search_and_process_email(cls, email: str, service: str, option: str) -> tuple[bool, str | None, str | None]:
        """
        Método principal que combina búsqueda y procesamiento de emails.
        
        Args:
            email: Email a buscar
            service: Servicio ('disney' o 'netflix')
            option: Opción específica
            
        Returns:
            tuple[bool, str | None, str | None]: (éxito, resultado, mensaje_error)
        """
        try:
            # Buscar email
            success, raw_email, error = cls.search_emails(email, service)
            if not success or not raw_email:
                return False, None, error or "No se encontró el email"

            # Procesar email
            success, result = cls.process_email(raw_email, service, option)
            if not success or not result:
                return False, None, "No se encontró la información solicitada"

            # Formatear resultado
            formatted_result = cls.format_search_result(result, service, option)
            
            # Validar resultado
            if not cls.validate_result(formatted_result, service, option):
                logger.error(f"Resultado inválido: {formatted_result}")
                return False, None, "El resultado no cumple con el formato esperado"

            return True, formatted_result, None

        except Exception as e:
            logger.error(f"Error en search_and_process_email: {str(e)}\n{traceback.format_exc()}")
            return False, None, f"Error procesando la solicitud: {str(e)}"