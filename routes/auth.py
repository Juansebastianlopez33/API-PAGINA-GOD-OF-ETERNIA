from flask import Blueprint, request, jsonify
from extensions import mysql, bcrypt
import random
import string
from datetime import datetime, timedelta, timezone # Importar timezone aquí
from email.mime.text import MIMEText
from email.header import Header
import smtplib
import os
import re
from dotenv import load_dotenv
import sys
import traceback

# Importar PyJWT (la librería 'jwt')
import jwt
from MySQLdb.cursors import DictCursor # Importar DictCursor para los resultados de la base de datos

load_dotenv()

auth_bp = Blueprint('auth', __name__)

MAIL_USER = os.getenv('MAIL_USER')
MAIL_PASS = os.getenv('MAIL_PASS')

# --- Configuración JWT ---
# ¡IMPORTANTE!: En producción, esta clave DEBE ser una cadena muy larga, aleatoria y guardada en una variable de entorno.
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'tu_clave_secreta_jwt_muy_segura_aqui')
JWT_EXPIRATION_DELTA = timedelta(hours=1) # El token expirará en 1 hora


def generar_codigo_verificacion():
    """Genera un código de verificación numérico de 6 dígitos."""
    return str(random.randint(100000, 999999))

def enviar_correo_verificacion(destinatario, codigo):
    """
    Envía un correo electrónico con el código de verificación.
    Retorna True si el envío es exitoso, False en caso contrario.
    """
    html_cuerpo = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 20px auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }}
            .header {{ background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ padding: 20px; text-align: center; }}
            .code {{ font-size: 24px; font-weight: bold; color: #333333; margin: 20px 0; padding: 10px; border: 2px dashed #4CAF50; display: inline-block; }}
            .footer {{ text-align: center; font-size: 12px; color: #777777; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Verificación de Cuenta</h2>
            </div>
            <div class="content">
                <p>Gracias por registrarte en nuestra plataforma. Para verificar tu cuenta, usa el siguiente código:</p>
                <div class="code">{codigo}</div>
                <p>Este código es válido por un tiempo limitado.</p>
                <p>Si no solicitaste esta verificación, por favor ignora este correo.</p>
            </div>
            <div class="footer">
                <p>&copy; {datetime.now().year} TuEmpresa. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    msg = MIMEText(html_cuerpo, 'html', 'utf-8')
    msg['From'] = Header(f"Tu Empresa <{MAIL_USER}>", 'utf-8')
    msg['To'] = destinatario
    msg['Subject'] = Header("Código de Verificación de Cuenta", 'utf-8')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(MAIL_USER, MAIL_PASS)
            smtp.send_message(msg)
        print(f"Correo de verificación enviado a {destinatario}")
        return True
    except Exception as e:
        print(f"Error al enviar correo de verificación a {destinatario}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return False

def generar_codigo_restablecimiento():
    """Genera un código de restablecimiento alfanumérico aleatorio y corto."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def enviar_correo_restablecimiento(destinatario, codigo):
    """
    Envía un correo electrónico con el código de restablecimiento de contraseña.
    Retorna True si el envío es exitoso, False en caso contrario.
    """
    html_cuerpo = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 20px auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }}
            .header {{ background-color: #f0ad4e; color: white; padding: 10px 20px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ padding: 20px; text-align: center; }}
            .code {{ font-size: 24px; font-weight: bold; color: #333333; margin: 20px 0; padding: 10px; border: 2px dashed #f0ad4e; display: inline-block; }}
            .footer {{ text-align: center; font-size: 12px; color: #777777; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Restablecimiento de Contraseña</h2>
            </div>
            <div class="content">
                <p>Has solicitado restablecer tu contraseña. Usa el siguiente código para continuar:</p>
                <div class="code">{codigo}</div>
                <p>Este código es válido por 10 minutos.</p>
                <p>Si no solicitaste esto, por favor ignora este correo.</p>
            </div>
            <div class="footer">
                <p>&copy; {datetime.now().year} TuEmpresa. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    """

    msg = MIMEText(html_cuerpo, 'html', 'utf-8')
    msg['From'] = Header(f"Tu Empresa <{MAIL_USER}>", 'utf-8')
    msg['To'] = destinatario
    msg['Subject'] = Header("Código de Restablecimiento de Contraseña", 'utf-8')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(MAIL_USER, MAIL_PASS)
            smtp.send_message(msg)
        print(f"Correo de restablecimiento enviado a {destinatario}")
        return True
    except Exception as e:
        print(f"Error al enviar correo de restablecimiento a {destinatario}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return False

def validar_password(password):
    if len(password) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r"[0-9]", password):
        return "La contraseña debe contener al menos un número."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "La contraseña debe contener al menos un carácter especial."
    return None

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({"error": "Faltan campos requeridos."}), 400

    password_error = validar_password(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"error": "El nombre de usuario ya existe."}), 409

        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "El correo electrónico ya está registrado."}), 409

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        verification_code = generar_codigo_verificacion()

        cursor.execute(
            "INSERT INTO users (username, email, password_hash, verificado, verification_code, code_expiration) VALUES (%s, %s, %s, %s, %s, %s)",
            (username, email, hashed_password, False, verification_code, datetime.now() + timedelta(minutes=10)) # Código expira en 10 minutos
        )
        mysql.connection.commit()

        if enviar_correo_verificacion(email, verification_code):
            return jsonify({"message": "Registro exitoso. Se ha enviado un código de verificación a tu correo."}), 201
        else:
            return jsonify({"error": "Error al enviar correo de verificación. Por favor, intenta de nuevo."}), 500
    except Exception as e:
        print(f"Error en /register: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        cursor.close()

@auth_bp.route('/verify', methods=['POST'])
def verify_account():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not all([email, code]):
        return jsonify({"error": "Faltan campos requeridos: email y código."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT verification_code, code_expiration FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()

        if not result:
            return jsonify({"error": "Correo electrónico no encontrado."}), 404

        stored_code, code_expiration = result

        if stored_code == code and code_expiration and datetime.now() < code_expiration:
            cursor.execute("UPDATE users SET verificado = TRUE, verification_code = NULL, code_expiration = NULL WHERE email = %s", (email,))
            mysql.connection.commit()
            return jsonify({"message": "Cuenta verificada exitosamente."}), 200
        else:
            if code_expiration and datetime.now() >= code_expiration:
                return jsonify({"error": "El código de verificación ha expirado."}), 400
            else:
                return jsonify({"error": "Código de verificación inválido."}), 400
    except Exception as e:
        print(f"Error en /verify: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        cursor.close()

@auth_bp.route('/resend_verification_code', methods=['POST'])
def resend_verification_code():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "El campo 'email' es requerido."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT verificado FROM users WHERE email = %s", (email,))
        user_status = cursor.fetchone()

        if not user_status:
            return jsonify({"error": "Usuario no encontrado."}), 404
        
        if user_status[0]:
            return jsonify({"message": "La cuenta ya está verificada."}), 400

        new_code = generar_codigo_verificacion()
        new_expiration = datetime.now() + timedelta(minutes=10)

        cursor.execute(
            "UPDATE users SET verification_code = %s, code_expiration = %s WHERE email = %s",
            (new_code, new_expiration, email)
        )
        mysql.connection.commit()

        if enviar_correo_verificacion(email, new_code):
            return jsonify({"message": "Nuevo código de verificación enviado."}), 200
        else:
            return jsonify({"error": "Error al reenviar el correo de verificación."}), 500

    except Exception as e:
        print(f"Error en /resend_verification_code: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        cursor.close()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"error": "Faltan campos requeridos."}), 400

    # Usar DictCursor para acceder a los resultados por nombre de columna
    cursor = mysql.connection.cursor(DictCursor) 
    try:
        cursor.execute("SELECT id, username, email, password_hash, verificado FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            if not user['verificado']:
                return jsonify({"error": "Cuenta no verificada. Por favor, verifica tu correo."}), 403

            # Crear el token JWT con PyJWT
            payload = {
                "user_id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "verificado": user['verificado'],
                "exp": datetime.now(timezone.utc) + JWT_EXPIRATION_DELTA
            }
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

            return jsonify(access_token=token), 200
        else:
            return jsonify({"error": "Credenciales inválidas."}), 401
    except Exception as e:
        print(f"Error en /login: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        cursor.close()

@auth_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "El correo electrónico es requerido."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if not cursor.fetchone():
            return jsonify({"error": "Usuario no encontrado."}), 404

        reset_code = generar_codigo_restablecimiento()
        reset_token_expira = datetime.now() + timedelta(minutes=10)

        cursor.execute(
            "UPDATE users SET reset_token = %s, reset_token_expira = %s WHERE email = %s",
            (reset_code, reset_token_expira, email)
        )
        mysql.connection.commit()

        if enviar_correo_restablecimiento(email, reset_code):
            return jsonify({"message": "Se ha enviado un código de restablecimiento a tu correo."}), 200
        else:
            return jsonify({"error": "Error al enviar correo de restablecimiento."}), 500
    except Exception as e:
        print(f"Error en /forgot_password: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        cursor.close()

@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    reset_code = data.get('code')
    new_password = data.get('new_password')

    if not all([reset_code, new_password]):
        return jsonify({"error": "Faltan campos requeridos: código de restablecimiento y nueva contraseña."}), 400
    
    password_error = validar_password(new_password)
    if password_error:
        return jsonify({"error": password_error}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT email, reset_token_expira FROM users WHERE reset_token = %s", (reset_code,))
        user_info = cursor.fetchone()
        if not user_info:
            return jsonify({"error": "Código de restablecimiento inválido."}), 400

        email, expira = user_info
        if expira is None or datetime.now() > expira:
            cursor.execute("UPDATE users SET reset_token = NULL, reset_token_expira = NULL WHERE email = %s", (email,))
            mysql.connection.commit()
            return jsonify({"error": "El código de restablecimiento ha expirado."}), 400

        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cursor.execute("""
            UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expira = NULL
            WHERE email = %s
        """, (hashed_new_password, email))
        mysql.connection.commit()
        return jsonify({"message": "Contraseña restablecida exitosamente."}), 200
    except Exception as e:
        print(f"Error en /reset_password: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor."}), 500
    finally:
        cursor.close()