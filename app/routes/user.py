from flask import Blueprint, render_template, redirect, url_for, jsonify, request, flash
from flask_login import login_required, current_user
from app.models.user import User, UserEmail
from app.services.email_service import EmailService
from app import db
from functools import wraps
import logging

# Configurar logging
logger = logging.getLogger(__name__)

bp = Blueprint('user', __name__, url_prefix='/user')

def check_guest_permissions(allowed_services=None):
    """
    Decorador para verificar permisos de invitados.
    allowed_services: dict con los servicios y opciones permitidas
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_guest:
                service = request.get_json().get('service') if request.is_json else None
                option = request.get_json().get('option') if request.is_json else None
                
                if allowed_services and service and option:
                    if service not in allowed_services or option not in allowed_services[service]:
                        return jsonify({
                            'success': False,
                            'message': 'No tienes permiso para usar esta opción'
                        }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@bp.route('/dashboard')
@login_required
def dashboard():
    """Panel principal del usuario."""
    try:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        return render_template('user/dashboard.html')
    except Exception as e:
        logger.error(f"Error en dashboard: {str(e)}")
        flash('Error al cargar el dashboard')
        return redirect(url_for('auth.login'))

@bp.route('/get-user-emails', methods=['GET'])
@login_required
def get_user_emails():
    """Obtiene todos los correos asociados al usuario actual o al usuario de la key."""
    try:
        if current_user.is_guest:
            # Si es invitado, obtener el usuario principal
            main_user = User.query.filter_by(
                linked_guest_key=current_user.linked_guest_key,
                is_guest=False
            ).first()
            if main_user:
                user_emails = UserEmail.query.filter_by(user_id=main_user.id).all()
            else:
                user_emails = []
        else:
            # Si es usuario normal, solo obtener sus propios emails
            user_emails = UserEmail.query.filter_by(user_id=current_user.id).all()
        
        emails = [{
            'id': email.id,
            'email': email.email,
            'is_primary': email.is_primary,
            'can_search_any': email.can_search_any
        } for email in user_emails]
        
        return jsonify({
            'success': True,
            'emails': emails
        })
    except Exception as e:
        logger.error(f"Error getting emails: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error al obtener los emails'
        }), 500

@bp.route('/verify-email', methods=['POST'])
@login_required
def verify_email():
    """Verifica si un correo está permitido para el usuario actual."""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({
                'success': False, 
                'message': 'Email no proporcionado'
            }), 400

        # Normalizar el email ingresado
        normalized_email, domain = EmailService.normalize_email(email)

        # Verificar si el usuario tiene acceso al email
        if current_user.is_guest:
            # Si es invitado, buscar en todos los emails del usuario principal
            main_user = User.query.filter_by(
                linked_guest_key=current_user.linked_guest_key,
                is_guest=False
            ).first()
            
            if main_user and any(email.can_search_any for email in main_user.emails):
                return jsonify({
                    'success': True,
                    'message': 'Email verificado correctamente'
                })

            # Si no tiene permiso de búsqueda abierta, verificar coincidencia exacta
            if main_user:
                for ue in main_user.emails:
                    norm_ue, _ = EmailService.normalize_email(ue.email)
                    if norm_ue == normalized_email:
                        return jsonify({
                            'success': True,
                            'message': 'Email verificado correctamente'
                        })
        else:
            # Si es usuario normal, verificar sus permisos
            user_emails = UserEmail.query.filter_by(user_id=current_user.id).all()
            
            # Verificar si tiene permiso de búsqueda abierta
            if any(email.can_search_any for email in user_emails):
                return jsonify({
                    'success': True,
                    'message': 'Email verificado correctamente'
                })
            
            # Si no tiene permiso de búsqueda abierta, verificar coincidencia exacta
            for ue in user_emails:
                norm_ue, _ = EmailService.normalize_email(ue.email)
                if norm_ue == normalized_email:
                    return jsonify({
                        'success': True,
                        'message': 'Email verificado correctamente'
                    })

        return jsonify({
            'success': False,
            'message': 'No tienes acceso a este correo electrónico'
        }), 403

    except Exception as e:
        logger.error(f"Error verifying email: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error al verificar el email'
        }), 500

@bp.route('/search-service', methods=['POST'])
@login_required
@check_guest_permissions({
    'disney': ['homeCode'],
    'netflix': ['updateHome', 'homeCode'],
    'crunchyroll': ['resetLink'],
    'max': ['resetLink'],
    'prime': ['loginCode']  # Agregado en los permisos del decorador
})

def search_service():
    """Busca información en los correos según el servicio seleccionado."""
    try:
        data = request.get_json()
        email = data.get('email')
        service = data.get('service')
        option = data.get('option')

        if not all([email, service, option]):
            return jsonify({
                'success': False,
                'message': 'Faltan datos requeridos'
            }), 400

        # Normalizar el email y verificar acceso
        normalized_email, _ = EmailService.normalize_email(email)
        
        # Verificar acceso al email según el tipo de usuario
        if current_user.is_guest:
            main_user = User.query.filter_by(
                linked_guest_key=current_user.linked_guest_key,
                is_guest=False
            ).first()
            
            if not main_user:
                return jsonify({
                    'success': False,
                    'message': 'No se encontró el usuario principal'
                }), 403
                
            if not any(email.can_search_any for email in main_user.emails):
                # Verificar coincidencia exacta
                has_access = False
                for ue in main_user.emails:
                    norm_ue, _ = EmailService.normalize_email(ue.email)
                    if norm_ue == normalized_email:
                        has_access = True
                        break
                        
                if not has_access:
                    return jsonify({
                        'success': False,
                        'message': 'No tienes acceso a este correo electrónico'
                    }), 403
        else:
            user_emails = UserEmail.query.filter_by(user_id=current_user.id).all()
            if not any(email.can_search_any for email in user_emails):
                # Verificar coincidencia exacta
                has_access = False
                for ue in user_emails:
                    norm_ue, _ = EmailService.normalize_email(ue.email)
                    if norm_ue == normalized_email:
                        has_access = True
                        break
                        
                if not has_access:
                    return jsonify({
                        'success': False,
                        'message': 'No tienes acceso a este correo electrónico'
                    }), 403

        # Verificar si la opción está permitida para el tipo de usuario
        available_services = current_user.get_available_services()
        if service not in available_services or option not in available_services[service]:
            return jsonify({
                'success': False,
                'message': 'No tienes permiso para usar esta opción'
            }), 403

        # Buscar el correo
        success, raw_email, error = EmailService.search_emails(normalized_email, service)
        if not success:
            return jsonify({
                'success': False,
                'message': error or 'No se encontraron correos para este servicio'
            }), 404

        # Procesar el correo según el servicio y opción
        success, result = EmailService.process_email(raw_email, service, option)
        
        if not success or not result:
            return jsonify({
                'success': False,
                'message': 'No se encontró la información solicitada'
            }), 404

        # Preparar el mensaje según el tipo de servicio y opción
        messages = {
            'disney': {
                'loginCode': 'Código de inicio de sesión de Disney+',
                'homeCode': 'Código de hogar de Disney+'
            },
            'netflix': {
                'resetLink': 'Link de restablecimiento de Netflix',
                'updateHome': 'Link para actualizar hogar de Netflix',
                'homeCode': 'Código de hogar de Netflix',
                'country': 'País de la cuenta de Netflix'
            },
            'crunchyroll': {
                'resetLink': 'Link de restablecimiento de Crunchyroll'
            },
            'max': {
                'resetLink': 'Link de restablecimiento de Max'
            },
            'prime': {
                'loginCode': 'Código de inicio de sesión de Prime Video'
            }
        }

        return jsonify({
            'success': True,
            'result': result,
            'message': f'{messages[service][option]} encontrado exitosamente'
        })
    except Exception as e:
        logger.error(f"Error in search service: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error al procesar la solicitud'
        }), 500

@bp.route('/get-available-options', methods=['GET'])
@login_required
def get_available_options():
    """Retorna las opciones disponibles según el tipo de usuario."""
    try:
        return jsonify(current_user.get_available_services())
    except Exception as e:
        logger.error(f"Error getting available options: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error al obtener las opciones disponibles'
        }), 500