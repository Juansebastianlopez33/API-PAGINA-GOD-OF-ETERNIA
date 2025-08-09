from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
from extensions import mysql, bcrypt, init_app as inicializar_extensiones
import os
from datetime import timedelta
from flask_jwt_extended import JWTManager
# Importar las excepciones específicas de Flask-JWT-Extended
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
# Importar InvalidTokenError, ExpiredSignatureError y DecodeError desde jwt.exceptions
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, DecodeError
import sys # Importar sys para imprimir en stderr

# Crear la aplicación y configurar CORS
app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})

# Configuración de MySQL
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'flask_api')
app.config['MYSQL_CHARSET'] = 'utf8mb4'

# Configuración de Correo Electrónico
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# --- Configuración de Flask-JWT-Extended ---
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

# La impresión de JWT_SECRET_KEY se ha eliminado ya que no es necesaria para la depuración continua.
# print(f"DEBUG: JWT_SECRET_KEY cargada en app.config: '{app.config['JWT_SECRET_KEY']}'", file=sys.stderr)
# if not app.config['JWT_SECRET_KEY']:
#     print("WARNING: JWT_SECRET_KEY no está configurada. Esto causará errores de autenticación.", file=sys.stderr)


jwt = JWTManager(app)

# --- MANEJADORES DE ERRORES ESPECÍFICOS DE JWT ---
# Se mantienen para una mejor gestión de errores en producción, pero se eliminan los prints de depuración.
@app.errorhandler(NoAuthorizationError)
def handle_auth_error(e):
    # print(f"ERROR JWT: NoAuthorizationError - {e}", file=sys.stderr) # Eliminado debug
    return jsonify({"msg": str(e)}), 401

@app.errorhandler(InvalidHeaderError)
def handle_invalid_header_error(e):
    # print(f"ERROR JWT: InvalidHeaderError - {e}", file=sys.stderr) # Eliminado debug
    return jsonify({"msg": str(e)}), 422 

@app.errorhandler(InvalidTokenError)
def handle_invalid_token_error(e):
    # print(f"ERROR JWT: InvalidTokenError - {e}", file=sys.stderr) # Eliminado debug
    return jsonify({"msg": "Token inválido. Por favor, inicie sesión de nuevo."}), 401

@app.errorhandler(ExpiredSignatureError)
def handle_expired_token_error(e):
    # print(f"ERROR JWT: ExpiredSignatureError - {e}", file=sys.stderr) # Eliminado debug
    return jsonify({"msg": "Token expirado. Por favor, refresque el token o inicie sesión de nuevo."}), 401

@app.errorhandler(DecodeError)
def handle_decode_error(e):
    # print(f"ERROR JWT: DecodeError - {e}", file=sys.stderr) # Eliminado debug
    return jsonify({"msg": "Error al decodificar el token. El token es malformado o la clave secreta es incorrecta."}), 422 

# Define el directorio base de la aplicación para rutas relativas
basedir = os.path.abspath(os.path.dirname(__file__))

# --- CONFIGURACIONES PARA LAS CARPETAS DE UPLOADS ---
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, UPLOAD_FOLDER)

os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'fotos_perfil'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'publicaciones'), exist_ok=True)

PDF_FOLDER = 'pdfs'
app.config['PDF_FOLDER'] = os.path.join(basedir, PDF_FOLDER)

os.makedirs(app.config['PDF_FOLDER'], exist_ok=True)

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['API_BASE_URL'] = os.getenv('API_BASE_URL', 'http://localhost:5000')

# Inicializa TODAS las extensiones
inicializar_extensiones(app)

# --- GANCHO DE DEBUGGING PARA TODAS LAS SOLICITUDES ---
# El gancho before_request se ha eliminado ya que no es necesario para la depuración continua.
# @app.before_request
# def log_request_info():
#     print(f"\n--- INICIO DE SOLICITUD ---", file=sys.stderr)
#     print(f"Método: {request.method}", file=sys.stderr)
#     print(f"Ruta: {request.path}", file=sys.stderr)
#     print(f"Encabezados: {request.headers}", file=sys.stderr)
    
#     if request.method in ['POST', 'PUT', 'PATCH'] and request.content_length:
#         try:
#             body_data = request.get_data(as_text=True)
#             print(f"Cuerpo de la solicitud: {body_data}", file=sys.stderr)
#         except Exception as e:
#             print(f"Error al leer el cuerpo de la solicitud: {e}", file=sys.stderr)
    
#     print(f"--- FIN DE SOLICITUD ---", file=sys.stderr)


# --- RUTAS PARA SERVIR LAS IMÁGENES ESTÁTICAS ---
@app.route('/uploads/fotos_perfil/<int:user_id>/<filename>')
def uploaded_profile_picture(user_id, filename):
    profile_picture_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'fotos_perfil', str(user_id))
    return send_from_directory(profile_picture_folder, filename)

@app.route('/uploads/publicaciones/<folder_name>/<filename>')
def uploaded_publication_image(folder_name, filename):
    publication_images_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'publicaciones', folder_name)
    return send_from_directory(publication_images_folder, filename)

@app.route('/uploads/<username>/<filename>')
def uploaded_file_legacy(username, filename):
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    return send_from_directory(user_upload_folder, filename)


# Importar y registrar blueprints
from routes.auth import auth_bp
from routes.user import user_bp
from support import support_bp
from pdf_routes import pdf_bp

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(support_bp)
app.register_blueprint(pdf_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
