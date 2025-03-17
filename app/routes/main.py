from flask import Blueprint, redirect, url_for

# Crear un nuevo blueprint para las rutas principales
main = Blueprint('main', __name__)

@main.route('/')
def index():
    return redirect(url_for('auth.login'))