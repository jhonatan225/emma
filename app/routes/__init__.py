from .auth import bp as auth_bp
from .admin import bp as admin_bp
from .user import bp as user_bp
from .main import main as main_bp

def init_app(app):
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)