# app.py
from flask import Flask, send_from_directory
from flask_cors import CORS
# Importa la función init_app a nivel de módulo desde extensions
from extensions import mysql, bcrypt, init_app as inicializar_extensiones # Renombrada para mayor claridad
import os
from datetime import timedelta # Importar timedelta para la configuración de JWT
from flask_jwt_extended import JWTManager # Importar JWTManager

# Crear la aplicación y configurar CORS
app = Flask(__name__)

# ---
## ADVERTENCIA DE SEGURIDAD IMPORTANTE: Permitir TODOS los Orígenes

CORS(app, resources={r"/*": {"origins": "*"}})
# Esta configuración permite solicitudes desde CUALQUIER origen a CUALQUIER ruta de tu API.
# Aunque es conveniente para el desarrollo, usar "origins": "*" en un entorno de producción
# es un riesgo de seguridad significativo, ya que hace que tu API sea vulnerable a la falsificación de solicitudes entre sitios (CSRF)
# y otros ataques maliciosos.

# Para producción, SIEMPRE enumera explícitamente los orígenes que deben permitirse:
# CORS(app, resources={r"/*": {"origins": ["http://tufrotnend.com", "https://otrofrontend.com"]}})


# Configuración de MySQL
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'gods_of_eternia')
app.config['MYSQL_CHARSET'] = 'utf8mb4'

# Configuración de Correo Electrónico
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# --- Configuración de Flask-JWT-Extended ---
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY') # ¡MUY IMPORTANTE! Coge la clave secreta de las variables de entorno
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) # Configura la expiración del token de acceso (ej. 1 hora)
# Puedes añadir más configuraciones JWT aquí si las necesitas, como JWT_REFRESH_TOKEN_EXPIRES

# Inicializa JWTManager
jwt = JWTManager(app)

# Define el directorio base de la aplicación para rutas relativas
basedir = os.path.abspath(os.path.dirname(__file__))

# --- CONFIGURACIONES PARA LAS CARPETAS ---

# Carpeta para uploads (imágenes de perfil)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, UPLOAD_FOLDER)

# Carpeta para PDFs
PDF_FOLDER = 'pdfs'
app.config['PDF_FOLDER'] = os.path.join(basedir, PDF_FOLDER)

# Crea las carpetas si no existen al iniciar la aplicación Flask.
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PDF_FOLDER'], exist_ok=True)

# Limite de tamaño y extensiones permitidas para uploads
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['API_BASE_URL'] = os.getenv('API_BASE_URL', 'http://localhost:5000')


# Inicializa TODAS las extensiones usando la función central init_app de extensions.py
# ¡Esto también inicializará Redis!
inicializar_extensiones(app) # <--- ESTE ES EL CAMBIO CRUCIAL

# --- RUTA PARA SERVIR LAS IMÁGENES ESTÁTICAS ---
@app.route('/uploads/<username>/<filename>')
def uploaded_file(username, filename):
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    return send_from_directory(user_upload_folder, filename)

# Importar y registrar blueprints
from routes.auth import auth_bp
from routes.user import user_bp

# CORRECCIÓN AQUÍ: Importaciones directas para support.py y pdf_routes.py
# asumiendo que están en el mismo nivel que app.py
from support import support_bp
from pdf_routes import pdf_bp

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(support_bp)
app.register_blueprint(pdf_bp)

if __name__ == '__main__':
    # Asegúrate de que tus variables de entorno estén configuradas, por ejemplo:
    # export REDIS_HOST=localhost
    # export REDIS_PORT=6379
    # export REDIS_DB=0
    # export MAIL_USER=tu_correo@gmail.com
    # export MAIL_PASS=tu_contraseña_de_aplicación
    # export JWT_SECRET_KEY=TU_SUPER_SECRETO_ALEATORIO_Y_LARGO_PARA_JWT
    app.run(host='0.0.0.0', port=5000, debug=True)