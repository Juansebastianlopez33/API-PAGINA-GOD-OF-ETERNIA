from flask import Blueprint, request, jsonify
from extensions import mysql, bcrypt
import random
import string
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.header import Header
import smtplib
import os
import re # Importar el módulo de expresiones regulares
from dotenv import load_dotenv

load_dotenv()

auth_bp = Blueprint('auth', __name__)

MAIL_USER = os.getenv('MAIL_USER')
MAIL_PASS = os.getenv('MAIL_PASS')

def generar_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))

def generar_codigo_verificacion():
    return str(random.randint(100000, 999999))

def enviar_correo_verificacion(destinatario, codigo):
    cuerpo = f"Este es tu código de verificación. No lo compartas con nadie: {codigo}"
    msg = MIMEText(cuerpo, 'plain', 'utf-8')
    msg['Subject'] = Header('Código de Verificación', 'utf-8')
    msg['From'] = MAIL_USER
    msg['To'] = destinatario

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(MAIL_USER, MAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print("Error al enviar correo:", str(e))
        return False

# Nueva función para enviar correo de restablecimiento de contraseña
def enviar_correo_restablecimiento(destinatario, reset_token):
    reset_link = f"Por favor, usa este token para restablecer tu contraseña: {reset_token}\n" \
                 "Este token expirará en 1 hora. Si no solicitaste esto, ignora este correo."
    
    msg = MIMEText(reset_link, 'plain', 'utf-8')
    msg['Subject'] = Header('Restablecimiento de Contraseña', 'utf-8')
    msg['From'] = MAIL_USER
    msg['To'] = destinatario

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(MAIL_USER, MAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print("Error al enviar correo de restablecimiento:", str(e))
        return False

def enviar_correo_bienvenida(nombre_usuario, destinatario):
    cuerpo = f"Hola {nombre_usuario}, tu cuenta ha sido verificada exitosamente. ¡Bienvenido a God of Eternia!"
    msg = MIMEText(cuerpo, 'plain', 'utf-8')
    msg['Subject'] = Header('¡Bienvenido a God of Eternia!', 'utf-8')
    msg['From'] = MAIL_USER
    msg['To'] = destinatario

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(MAIL_USER, MAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print("Error al enviar correo de bienvenida:", str(e))
        return False

# --- NUEVA FUNCIÓN DE VALIDACIÓN DE CONTRASEÑA ---
def validar_password(password):
    if len(password) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r"[0-9]", password):
        return "La contraseña debe contener al menos un número."
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]|:;<>,.?/~`]", password):
        # Esta regex incluye la mayoría de los caracteres especiales comunes. Puedes ajustarla.
        return "La contraseña debe contener al menos un carácter especial."
    return None # Retorna None si la contraseña es válida

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    descripcion = data.get('descripcion', '')

    if not all([username, email, password]):
        return jsonify({"error": "Todos los campos son obligatorios"}), 400

    # --- APLICAR VALIDACIÓN DE CONTRASEÑA ---
    password_error = validar_password(password)
    if password_error:
        return jsonify({"error": password_error}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    codigo = generar_codigo_verificacion()
    expira = datetime.now() + timedelta(hours=1)
    expira_str = expira.strftime('%Y-%m-%d %H:%M:%S')

    if not enviar_correo_verificacion(email, codigo):
        return jsonify({"error": "No se pudo enviar el correo de verificación"}), 500

    cursor = mysql.connection.cursor()
    try:
        token = generar_token() # Este token se guarda sin "Bearer "
        cursor.execute("""
            INSERT INTO users (token, username, email, password_hash, DescripUsuario, verificacion_codigo, verificacion_expira, verificado)
            VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE)
        """, (token, username, email, hashed_password, descripcion, codigo, expira_str))
        mysql.connection.commit()
    except Exception as e:
        # Aquí podrías añadir más lógica para verificar si el error es por 'UNIQUE constraint' (ej. usuario/email ya existe)
        return jsonify({"error": f"Error al registrar: {str(e)}"}), 500
    finally:
        cursor.close()

    return jsonify({"message": "Usuario registrado exitosamente. Revisa tu correo para verificar tu cuenta."}), 201

@auth_bp.route('/verificar', methods=['POST'])
def verificar():
    data = request.get_json()
    email = data.get('email')
    codigo = data.get('codigo')

    if not all([email, codigo]):
        return jsonify({"error": "Email y código son requeridos para la verificación"}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT verificacion_codigo, verificacion_expira, verificado FROM users WHERE email = %s", (email,))
        resultado = cursor.fetchone()
        if not resultado:
            return jsonify({"error": "Usuario no encontrado"}), 404

        codigo_correcto, expira, verificado = resultado

        if verificado:
            return jsonify({"message": "La cuenta ya está verificada."}), 200

        if expira is None:
            return jsonify({"error": "Fecha de expiración de la verificación no encontrada. Por favor, contacta al soporte."}), 500

        if datetime.now() > expira:
            return jsonify({"error": "El código ha expirado. Solicita un nuevo código de verificación."}), 400

        if codigo != codigo_correcto:
            return jsonify({"error": "Código incorrecto"}), 400

        # Actualizar a verificado
        cursor.execute("""
            UPDATE users SET verificado = TRUE, verificacion_codigo = NULL, verificacion_expira = NULL
            WHERE email = %s
        """, (email,))
        mysql.connection.commit()

        # Obtener nombre del usuario y enviar correo de bienvenida
        cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
        user_info = cursor.fetchone()
        if user_info:
            enviar_correo_bienvenida(user_info[0], email)

        return jsonify({"message": "Cuenta verificada exitosamente"}), 200

    finally:
        cursor.close()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"error": "Correo y contraseña son obligatorios"}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT token, password_hash, verificado FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Correo o contraseña incorrectos"}), 401

        token, password_hash, verificado = user

        if not bcrypt.check_password_hash(password_hash, password):
            return jsonify({"error": "Correo o contraseña incorrectos"}), 401

        if not verificado:
            return jsonify({"error": "La cuenta no ha sido verificada. Por favor, revisa tu correo."}), 403

        return jsonify({"token": token, "message": "Login exitoso"}), 200

    finally:
        cursor.close()

@auth_bp.route('/logeado', methods=['GET'])
def logeado():
    # Obtiene el encabezado 'Authorization'
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({"logeado": 0}), 200 # No se proporcionó encabezado de autorización

    # Verifica si el encabezado comienza con 'Bearer '
    if "Bearer " in auth_header:
        token = auth_header.split(" ")[1] # Extrae el token real
    else:
        # Si no tiene "Bearer ", asume que es el token directamente (menos seguro/estándar)
        # O podrías devolver un error 400 si esperas siempre el formato Bearer
        token = auth_header
        # return jsonify({"logeado": 0, "error": "Formato de token inválido"}), 400

    cursor = mysql.connection.cursor()
    try:
        # Ahora busca el token real en la base de datos
        cursor.execute("SELECT id FROM users WHERE token = %s AND verificado = TRUE", (token,))
        user = cursor.fetchone()

        if user:
            return jsonify({"logeado": 1}), 200
        else:
            return jsonify({"logeado": 0}), 200 # Token no encontrado o usuario no verificado

    except Exception as e:
        print(f"Error en /logeado: {str(e)}")
        return jsonify({"logeado": 0, "error": "Error interno del servidor"}), 500
    finally:
        cursor.close()

# --- Endpoints para Recuperación de Contraseña ---

@auth_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "El correo electrónico es obligatorio"}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            # Por seguridad, no reveles si el correo no existe
            return jsonify({"message": "Si el correo existe, se ha enviado un enlace para restablecer la contraseña."}), 200

        # Generar token de restablecimiento y fecha de expiración
        reset_token = generar_token()
        expira = datetime.now() + timedelta(hours=1) # El token expira en 1 hora
        expira_str = expira.strftime('%Y-%m-%d %H:%M:%S')

        # Guardar el token de restablecimiento y su expiración en la base de datos
        cursor.execute("""
            UPDATE users SET reset_token = %s, reset_token_expira = %s
            WHERE email = %s
        """, (reset_token, expira_str, email))
        mysql.connection.commit()

        # Enviar el correo con el token de restablecimiento
        if not enviar_correo_restablecimiento(email, reset_token):
            return jsonify({"error": "No se pudo enviar el correo de restablecimiento de contraseña"}), 500

        return jsonify({"message": "Si el correo existe, se ha enviado un enlace para restablecer la contraseña."}), 200

    except Exception as e:
        print(f"Error en /forgot_password: {str(e)}")
        return jsonify({"error": "Error interno del servidor al procesar la solicitud de restablecimiento"}), 500
    finally:
        cursor.close()

@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not all([token, new_password]):
        return jsonify({"error": "Token y nueva contraseña son obligatorios"}), 400

    # --- APLICAR VALIDACIÓN DE CONTRASEÑA ---
    password_error = validar_password(new_password)
    if password_error:
        return jsonify({"error": password_error}), 400

    cursor = mysql.connection.cursor()
    try:
        # Buscar usuario por el token de restablecimiento
        cursor.execute("SELECT email, reset_token_expira FROM users WHERE reset_token = %s", (token,))
        user_info = cursor.fetchone()

        if not user_info:
            return jsonify({"error": "Token inválido o no encontrado"}), 400

        email, expira = user_info

        # Verificar si el token ha expirado
        if expira is None or datetime.now() > expira:
            return jsonify({"error": "El token ha expirado. Por favor, solicita uno nuevo."}), 400

        # Hashear la nueva contraseña
        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Actualizar la contraseña y limpiar el token de restablecimiento
        cursor.execute("""
            UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expira = NULL
            WHERE email = %s
        """, (hashed_new_password, email))
        mysql.connection.commit()

        return jsonify({"message": "Contraseña restablecida exitosamente"}), 200

    except Exception as e:
        print(f"Error en /reset_password: {str(e)}")
        return jsonify({"error": "Error interno del servidor al restablecer la contraseña"}), 500
    finally:
        cursor.close()