from app import create_app, db
from app.models.user import User, UserEmail, AllowedEmail
from werkzeug.security import generate_password_hash
import os

def init_db():
    app = create_app()
    
    # Forzar la URL de PostgreSQL usando pg8000
    app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql+pg8000://enmma_user:JOjDpxkxI9F97DNPnzBi2APJf34y1SuA@dpg-cvbnbplsvqrc73c9q350-a.oregon-postgres.render.com/enmma"
    
    # Asegurarse de que el directorio instance existe
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    
    with app.app_context():
        try:
            # Eliminar todas las tablas existentes
            db.drop_all()
            print("Tablas eliminadas exitosamente")
            
            # Crear todas las tablas
            db.create_all()
            print("Tablas creadas exitosamente")
            
            # Crear usuario admin


            admin = User(
                username='admin',
                password_hash=generate_password_hash('Triunfador21@'),  # Usar hash de la contraseña
                is_admin=True,
                is_guest=False,
                linked_guest_key=User.generate_guest_key()
            )
            
            # Agregar el email del admin
            admin_email = UserEmail(
                email='admin@gmail.com',
                is_primary=True
            )
            admin.emails.append(admin_email)
            
            # Agregar dominio permitido por defecto
            default_domain = AllowedEmail(
                email_domain=''
            )
            
            db.session.add(admin)
            db.session.add(default_domain)
            db.session.commit()
            print("Base de datos inicializada y usuario admin creado")
            print(f"Key de invitado del admin: {admin.linked_guest_key}")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error al inicializar la base de datos: {str(e)}")
            raise

if __name__ == "__main__":
    init_db()
