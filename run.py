from app import create_app, db
from flask_migrate import Migrate
import os

app = create_app()
migrate = Migrate(app, db)

# Asegúrate de que el directorio instance existe
instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

if __name__ == '__main__':
    app.run(debug=True)