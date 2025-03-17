from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from app import db
from app.models.user import User, UserEmail, AllowedEmail
from app.models.imap_config import ImapConfiguration
from app.services.email_service import EmailService
import imaplib
import ssl
import logging
from datetime import datetime

# Configurar logging
logger = logging.getLogger(__name__)

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        flash('Acceso denegado. Se requieren privilegios de administrador.')
        return redirect(url_for('auth.login'))
    users = User.query.all()
    allowed_emails = AllowedEmail.query.all()
    imap_configs = ImapConfiguration.query.all()
    return render_template('admin/dashboard.html', 
                         users=users, 
                         allowed_emails=allowed_emails,
                         imap_configs=imap_configs)

@bp.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        username = request.form.get('username')
        emails_text = request.form.get('emails[]')  # Cambiar a emails[]
        password = request.form.get('password')
        can_search_any = 'can_search_any' in request.form
        
        if not all([username, emails_text, password]):
            flash('Todos los campos son requeridos')
            return redirect(url_for('admin.dashboard'))
        
        # Convertir el texto de emails en una lista y eliminar espacios en blanco
        emails = [email.strip() for email in emails_text.split('\n') if email.strip()]
        
        if not emails:  # Verificar que haya al menos un email
            flash('Debe proporcionar al menos un email')
            return redirect(url_for('admin.dashboard'))
        
        # Verificar si el usuario ya existe
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe')
            return redirect(url_for('admin.dashboard'))
        
        # Verificar dominios permitidos
        for email in emails:
            normalized_email, domain = EmailService.normalize_email(email)
            allowed_domain = AllowedEmail.query.filter_by(email_domain=domain).first()
            if not allowed_domain:
                flash(f'Dominio de email no permitido: {domain}')
                return redirect(url_for('admin.dashboard'))
        
        # Crear nuevo usuario
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            linked_guest_key=User.generate_guest_key()
        )
        
        # Agregar emails al usuario
        for i, email in enumerate(emails):
            user_email = UserEmail(
                email=email,
                is_primary=(i == 0),  # El primer email será el principal
                can_search_any=can_search_any
            )
            new_user.emails.append(user_email)
        
        db.session.add(new_user)
        db.session.commit()
        flash(f'Usuario creado exitosamente. Key de invitado: {new_user.linked_guest_key}')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        flash('Error al crear el usuario')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/regenerate_guest_key/<int:user_id>', methods=['POST'])
@login_required
def regenerate_guest_key(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    
    try:
        user = User.query.get_or_404(user_id)
        
        if user.is_admin:
            return jsonify({'success': False, 'message': 'No se puede regenerar la key para administradores'})
        
        user.linked_guest_key = User.generate_guest_key()
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Key regenerada exitosamente',
            'new_key': user.linked_guest_key
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error regenerating guest key: {str(e)}")
        return jsonify({'success': False, 'message': 'Error al regenerar la key'})

@bp.route('/user/<int:user_id>/emails', methods=['GET', 'POST'])
@login_required
def manage_user_emails(user_id):
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            if action == 'add':
                email = request.form.get('email')
                can_search_any = 'can_search_any' in request.form
                
                if not email:
                    flash('Email es requerido')
                    return redirect(url_for('admin.manage_user_emails', user_id=user_id))
                
                normalized_email, domain = EmailService.normalize_email(email)
                allowed_domain = AllowedEmail.query.filter_by(email_domain=domain).first()
                
                if not allowed_domain:
                    flash('Dominio de email no permitido')
                    return redirect(url_for('admin.manage_user_emails', user_id=user_id))
                
                new_email = UserEmail(
                    email=email, 
                    user=user,
                    can_search_any=can_search_any,
                    is_primary=not user.emails  # Será principal solo si no hay otros emails
                )
                db.session.add(new_email)
                
            elif action == 'delete':
                email_id = request.form.get('email_id')
                email = UserEmail.query.get_or_404(email_id)
                
                # Si es el último email, no permitir eliminarlo
                if len(user.emails) <= 1:
                    flash('No se puede eliminar el último email del usuario')
                    return redirect(url_for('admin.manage_user_emails', user_id=user_id))
                
                # Si es el email principal, asignar otro como principal
                if email.is_primary:
                    # Buscar otro email para hacerlo principal
                    other_email = UserEmail.query.filter(
                        UserEmail.user_id == user.id,
                        UserEmail.id != email.id
                    ).first()
                    if other_email:
                        other_email.is_primary = True
                
                db.session.delete(email)
                
            elif action == 'set_primary':
                email_id = request.form.get('email_id')
                # Quitar primary de todos los emails del usuario
                for e in user.emails:
                    e.is_primary = False
                # Establecer el nuevo email primario
                new_primary = UserEmail.query.get_or_404(email_id)
                new_primary.is_primary = True
            
            db.session.commit()
            flash('Emails actualizados exitosamente')
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error managing user emails: {str(e)}")
            flash('Error al actualizar los emails')
        
        return redirect(url_for('admin.manage_user_emails', user_id=user_id))
    
    return render_template('admin/manage_emails.html', user=user)

@bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        user = User.query.get_or_404(user_id)
        
        # No permitir eliminar al propio usuario admin
        if user.is_admin and user.id == current_user.id:
            flash('No puedes eliminar tu propio usuario administrador')
            return redirect(url_for('admin.dashboard'))
        
        db.session.delete(user)
        db.session.commit()
        flash('Usuario eliminado exitosamente')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        flash('Error al eliminar el usuario')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/add_imap_config', methods=['POST'])
@login_required
def add_imap_config():
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        domain = request.form.get('domain')
        email = request.form.get('email')
        password = request.form.get('password')
        imap_server = request.form.get('imap_server')
        imap_port = int(request.form.get('imap_port', 993))
        is_active = 'is_active' in request.form
        add_as_allowed = 'add_as_allowed_domain' in request.form
        
        # Verificar si ya existe una configuración para este email específico
        existing_config = ImapConfiguration.query.filter_by(email=email).first()
        if existing_config:
            flash('Ya existe una configuración para este email')
            return redirect(url_for('admin.dashboard'))
        
        # Crear nueva configuración
        new_config = ImapConfiguration(
            domain=domain,
            email=email,
            imap_server=imap_server,
            imap_port=imap_port,
            is_active=is_active
        )
        new_config.set_password(password)
        
        # Si se marcó la opción, agregar como dominio permitido
        if add_as_allowed:
            existing_allowed = AllowedEmail.query.filter_by(email_domain=domain).first()
            if not existing_allowed:
                new_allowed = AllowedEmail(email_domain=domain)
                db.session.add(new_allowed)
        
        db.session.add(new_config)
        db.session.commit()
        
        # Probar la conexión inmediatamente
        test_result = test_imap_connection_internal(new_config)
        if test_result:
            flash(f'Configuración IMAP agregada, pero hay un error de conexión: {test_result}')
        else:
            flash('Configuración IMAP agregada y probada exitosamente')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding IMAP config: {str(e)}")
        flash(f'Error al agregar la configuración IMAP: {str(e)}')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/get-imap-config/<int:config_id>')
@login_required
def get_imap_config(config_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        config = ImapConfiguration.query.get_or_404(config_id)
        return jsonify(config.to_dict())
    except Exception as e:
        logger.error(f"Error getting IMAP config: {str(e)}")
        return jsonify({'error': 'Error al obtener la configuración'}), 500

@bp.route('/update_imap_config/<int:config_id>', methods=['POST'])
@login_required
def update_imap_config(config_id):
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        config = ImapConfiguration.query.get_or_404(config_id)
        
        # Verificar si el nuevo email ya existe en otra configuración
        new_email = request.form.get('email')
        if new_email != config.email:
            existing_config = ImapConfiguration.query.filter_by(email=new_email).first()
            if existing_config:
                flash('Ya existe una configuración para este email')
                return redirect(url_for('admin.dashboard'))
                
        config.domain = request.form.get('domain')
        config.email = new_email
        config.imap_server = request.form.get('imap_server')
        config.imap_port = int(request.form.get('imap_port', 993))
        config.is_active = 'is_active' in request.form
        
        # Actualizar contraseña solo si se proporciona una nueva
        new_password = request.form.get('password')
        if new_password:
            config.set_password(new_password)
        
        config.last_modified = datetime.utcnow()
        db.session.commit()
        
        # Probar la conexión después de actualizar
        test_result = test_imap_connection_internal(config)
        if test_result:
            flash(f'Configuración IMAP actualizada, pero hay un error de conexión: {test_result}')
        else:
            flash('Configuración IMAP actualizada y probada exitosamente')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating IMAP config: {str(e)}")
        flash(f'Error al actualizar la configuración IMAP: {str(e)}')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/delete_imap_config/<int:config_id>', methods=['POST'])
@login_required
def delete_imap_config(config_id):
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        config = ImapConfiguration.query.get_or_404(config_id)
        db.session.delete(config)
        db.session.commit()
        flash('Configuración IMAP eliminada exitosamente')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting IMAP config: {str(e)}")
        flash(f'Error al eliminar la configuración IMAP: {str(e)}')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/test-imap/<int:config_id>', methods=['POST'])
@login_required
def test_imap_connection(config_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'No autorizado'}), 403
    
    try:
        config = ImapConfiguration.query.get_or_404(config_id)
        error = test_imap_connection_internal(config)
        
        if error:
            return jsonify({
                'success': False,
                'message': error
            })
        
        return jsonify({
            'success': True,
            'message': '¡La conexión IMAP está funcionando correctamente! 🚀'
        })
        
    except Exception as e:
        logger.error(f"Error testing IMAP connection: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error al probar la conexión: {str(e)}'
        })

def test_imap_connection_internal(config):
    """Función interna para probar la conexión IMAP"""
    try:
        # Crear contexto SSL seguro
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        
        # Intentar conexión con timeout
        with imaplib.IMAP4_SSL(
            host=config.imap_server,
            port=config.imap_port,
            ssl_context=context,
            timeout=30
        ) as imap:
            imap.login(config.email, config.get_password())
            imap.select('INBOX')
            return None  # Conexión exitosa
            
    except imaplib.IMAP4.error as e:
        logger.error(f"IMAP authentication error for {config.email}: {str(e)}")
        return f'Error de autenticación IMAP: {str(e)}'
    except Exception as e:
        logger.error(f"IMAP connection error for {config.email}: {str(e)}")
        return f'Error de conexión: {str(e)}'

@bp.route('/delete_allowed_email/<int:domain_id>', methods=['POST'])
@login_required
def delete_allowed_email(domain_id):
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        domain = AllowedEmail.query.get_or_404(domain_id)
        # Verificar si hay usuarios usando este dominio
        user_emails = UserEmail.query.filter(UserEmail.email.like(f'%@{domain.email_domain}')).all()
        if user_emails:
            flash('No se puede eliminar el dominio porque hay usuarios que lo están usando')
            return redirect(url_for('admin.dashboard'))
            
        db.session.delete(domain)
        db.session.commit()
        flash('Dominio eliminado exitosamente')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting allowed email domain: {str(e)}")
        flash('Error al eliminar el dominio')
    
    return redirect(url_for('admin.dashboard'))

@bp.route('/add_allowed_email', methods=['POST'])
@login_required
def add_allowed_email():
    if not current_user.is_admin:
        return redirect(url_for('auth.login'))
    
    try:
        domain = request.form.get('email_domain')
        if not domain:
            flash('El dominio es requerido')
            return redirect(url_for('admin.dashboard'))
            
        existing = AllowedEmail.query.filter_by(email_domain=domain).first()
        if existing:
            flash('Este dominio ya está permitido')
            return redirect(url_for('admin.dashboard'))
            
        new_domain = AllowedEmail(email_domain=domain)
        db.session.add(new_domain)
        db.session.commit()
        flash('Dominio agregado exitosamente')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding allowed email domain: {str(e)}")
        flash('Error al agregar el dominio')
    
    return redirect(url_for('admin.dashboard'))