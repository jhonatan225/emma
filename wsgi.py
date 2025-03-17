from app import create_app

app = create_app()
application = app  # Agrega esta línea para que Gunicorn la reconozca

if __name__ == '__main__':
    app.run()
