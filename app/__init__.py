from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config
import os
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Inicializar las extensiones
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.session_protection = 'strong'

def create_app():
    # Crear la aplicación Flask
    app = Flask(__name__)
    
    try:
        # Configurar la aplicación
        app.config.from_object(Config)
        logger.info(f"URL de base de datos configurada: {app.config['SQLALCHEMY_DATABASE_URI']}")
        
        # Asegurar que existe el directorio instance
        instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
        os.makedirs(instance_path, exist_ok=True)
        
        # Inicializar las extensiones con la aplicación
        db.init_app(app)
        migrate.init_app(app, db)  # Inicializar Flask-Migrate
        login_manager.init_app(app)
        
        # Configurar el cargador de usuarios para Flask-Login
        @login_manager.user_loader
        def load_user(user_id):
            try:
                from app.models.user import User
                return User.query.get(int(user_id))
            except Exception as e:
                logger.error(f"Error loading user: {str(e)}")
                return None

        # Importar y registrar los blueprints
        from .routes import auth, admin, user
        from .routes.main import main
        
        app.register_blueprint(main)
        app.register_blueprint(auth.bp)
        app.register_blueprint(admin.bp)
        app.register_blueprint(user.bp)
        
        # Importar modelos para asegurar que Flask-Migrate los detecte
        from app.models.user import User, UserEmail, AllowedEmail
        from app.models.imap_config import ImapConfiguration
        
        # Crear todas las tablas de la base de datos si no existen
        with app.app_context():
            try:
                db.create_all()
                logger.info("Database tables created successfully")
            except Exception as e:
                logger.error(f"Error creating database tables: {str(e)}")
                logger.error(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
                raise

        # Configurar manejo de errores
        @app.errorhandler(404)
        def not_found_error(error):
            return render_template('errors/404.html'), 404

        @app.errorhandler(500)
        def internal_error(error):
            db.session.rollback()
            return render_template('errors/500.html'), 500

    except Exception as e:
        logger.error(f"Error initializing app: {str(e)}")
        raise

    return app