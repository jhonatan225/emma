from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app.models.user import User, UserEmail
from app import db
import uuid, secrets
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
import logging

logger = logging.getLogger(__name__)

bp = Blueprint('auth', __name__)

def clear_user_session():
    """Limpia completamente la sesión del usuario"""
    try:
        # Limpiar Flask-Login
        logout_user()
        
        # Limpiar sesión de Flask
        session.clear()
        
        # Generar nuevo CSRF token si es necesario
        if 'csrf_token' in session:
            session['csrf_token'] = secrets.token_hex(32)
            
    except Exception as e:
        logger.error(f"Error clearing session: {str(e)}")

def validate_user_session():
    """
    Valida la sesión actual del usuario.
    Retorna True si la sesión es válida, False si necesita reautenticación.
    """
    try:
        if not current_user.is_authenticated:
            return False
            
        login_time = session.get('login_time')
        if not login_time:
            return False
            
        login_datetime = datetime.fromisoformat(login_time)
        session_duration = datetime.utcnow() - login_datetime
        
        # Verificar expiración de sesión (1 hora)
        if session_duration > timedelta(hours=1):
            return False
            
        # Verificar que el usuario aún existe y está activo
        user = User.query.get(current_user.id)
        if not user:
            return False
            
        # Para usuarios invitados, verificar que el usuario principal aún existe
        if user.is_guest:
            main_user = User.query.filter_by(
                linked_guest_key=user.linked_guest_key,
                is_guest=False
            ).first()
            if not main_user:
                return False
                
        return True
        
    except Exception as e:
        logger.error(f"Error validating session: {str(e)}")
        return False

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Maneja el proceso de login para usuarios normales y invitados.
    Implementa limpieza de sesión y validación mejorada.
    """
    try:
        # Siempre limpiar sesión anterior al intentar login
        clear_user_session()
        
        if request.method == 'POST':
            login_type = request.form.get('login_type', 'normal')
            
            if login_type == 'normal':
                return handle_normal_login()
            elif login_type == 'guest':
                return handle_guest_login()
            else:
                flash('Tipo de login inválido')
                return render_template('auth/login.html')
                
        return render_template('auth/login.html')
        
    except Exception as e:
        logger.error(f"Error in login route: {str(e)}")
        flash('Error en el proceso de login')
        return render_template('auth/login.html')

def handle_normal_login():
    """Maneja el proceso de login para usuarios normales"""
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Por favor ingrese usuario y contraseña')
            return render_template('auth/login.html')

        user = User.query.filter_by(username=username).first()
        
        if not user:
            # Usar tiempo constante para evitar timing attacks
            check_password_hash('dummy_hash', password)
            flash('Usuario o contraseña inválidos')
            return render_template('auth/login.html')
        
        if not check_password_hash(user.password_hash, password):
            flash('Usuario o contraseña inválidos')
            return render_template('auth/login.html')
            
        # Iniciar sesión
        session['user_id'] = user.id
        session['login_time'] = datetime.utcnow().isoformat()
        session['session_id'] = secrets.token_hex(16)
        
        login_user(user)
        
        logger.info(f"Login exitoso para usuario: {username}")
        return redirect(url_for('user.dashboard'))
        
    except Exception as e:
        logger.error(f"Error in normal login: {str(e)}")
        flash('Error en el proceso de login')
        return render_template('auth/login.html')

def handle_guest_login():
    """Maneja el proceso de login para usuarios invitados"""
    try:
        guest_key = request.form.get('guest_key')
        
        if not guest_key:
            flash('Por favor ingrese la key de invitado')
            return render_template('auth/login.html')

        # Buscar el usuario principal
        main_user = User.query.filter_by(
            linked_guest_key=guest_key,
            is_guest=False
        ).first()
        
        if not main_user:
            flash('Key de invitado inválida')
            return render_template('auth/login.html')

        # Limpiar usuarios invitados antiguos
        cleanup_guest_users(guest_key)
        
        # Crear nuevo usuario invitado
        guest_user = create_guest_user(guest_key)
        if not guest_user:
            flash('Error al crear sesión de invitado')
            return render_template('auth/login.html')
            
        # Iniciar sesión
        session['user_id'] = guest_user.id
        session['guest_key'] = guest_key
        session['login_time'] = datetime.utcnow().isoformat()
        session['session_id'] = secrets.token_hex(16)
        
        login_user(guest_user)
        
        logger.info(f"Login exitoso para invitado con key: {guest_key}")
        return redirect(url_for('user.dashboard'))
        
    except Exception as e:
        logger.error(f"Error in guest login: {str(e)}")
        flash('Error al crear sesión de invitado')
        return render_template('auth/login.html')

def cleanup_guest_users(guest_key):
    """Limpia usuarios invitados antiguos"""
    try:
        old_guests = User.query.filter_by(
            is_guest=True,
            linked_guest_key=guest_key
        ).all()
        
        for guest in old_guests:
            db.session.delete(guest)
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error cleaning up guest users: {str(e)}")
        db.session.rollback()

def create_guest_user(guest_key):
    """Crea un nuevo usuario invitado"""
    try:
        guest_username = f"guest_{uuid.uuid4().hex[:8]}"
        guest_user = User(
            username=guest_username,
            password_hash=generate_password_hash(str(uuid.uuid4())),
            is_guest=True,
            linked_guest_key=guest_key
        )
        
        db.session.add(guest_user)
        db.session.commit()
        
        return guest_user
        
    except Exception as e:
        logger.error(f"Error creating guest user: {str(e)}")
        db.session.rollback()
        return None

@bp.route('/logout')
@login_required
def logout():
    """
    Maneja el proceso de logout.
    Implementa limpieza completa de sesión y recursos.
    """
    try:
        user_id = current_user.id
        is_guest = current_user.is_guest
        
        # Primero hacer logout y limpiar sesión
        clear_user_session()
        
        # Si es usuario invitado, eliminarlo
        if is_guest:
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                
        logger.info(f"Logout exitoso para usuario ID: {user_id}")
        return redirect(url_for('auth.login'))
        
    except Exception as e:
        logger.error(f"Error in logout: {str(e)}")
        # Asegurar logout aunque haya error
        clear_user_session()
        return redirect(url_for('auth.login'))

@bp.before_app_request
def validate_session_before_request():
    """
    Middleware para validar la sesión antes de cada request.
    Implementa verificaciones de seguridad y limpieza automática.
    """
    try:
        if current_user.is_authenticated:
            # Si la sesión no es válida, hacer logout
            if not validate_user_session():
                clear_user_session()
                flash('Su sesión ha expirado. Por favor, inicie sesión nuevamente.')
                return redirect(url_for('auth.login'))
                
            # Renovar timestamp de sesión
            session['login_time'] = datetime.utcnow().isoformat()
            
    except Exception as e:
        logger.error(f"Error validating session in middleware: {str(e)}")
        # En caso de error, hacer logout por seguridad
        clear_user_session()
        return redirect(url_for('auth.login'))

# Limpieza periódica de usuarios invitados huérfanos
@bp.before_app_request
def cleanup_orphaned_guests():
    """Limpia periódicamente usuarios invitados sin usuario principal"""
    try:
        # Ejecutar limpieza ocasionalmente (1 de cada 100 requests)
        if secrets.randbelow(100) == 0:
            guest_users = User.query.filter_by(is_guest=True).all()
            for guest in guest_users:
                # Verificar si existe usuario principal
                main_user = User.query.filter_by(
                    linked_guest_key=guest.linked_guest_key,
                    is_guest=False
                ).first()
                
                if not main_user:
                    db.session.delete(guest)
            
            db.session.commit()
            
    except Exception as e:
        logger.error(f"Error cleaning up orphaned guests: {str(e)}")
        db.session.rollback()
