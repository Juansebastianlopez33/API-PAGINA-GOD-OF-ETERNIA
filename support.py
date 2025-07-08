from flask import Blueprint, request, jsonify, current_app
from extensions import mysql, redis_client # Importar redis_client
import sys
import traceback
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import ssl
import time
from datetime import datetime, timedelta, timezone

support_bp = Blueprint('support', __name__, url_prefix='/api')

# --- Constantes para Redis Keys ---
USER_COOLDOWN_KEY_PREFIX = "user_support_cooldown:"
GLOBAL_REQUEST_KEY = "global_support_requests"

# --- Rate Limiting Parameters ---
# CAMBIO AQUÍ: Cooldown de 5 minutos por usuario
COOLDOWN_PERIOD_PER_USER_SECONDS = 300 # 5 minutos (5 * 60 segundos)
GLOBAL_COOLDOWN_WINDOW_SECONDS = 300 # 5 minutos (5 * 60 segundos)
MAX_GLOBAL_REQUESTS_IN_WINDOW = 100 # Máximo 100 solicitudes en el período global

@support_bp.route('/support', methods=['POST'])
def handle_support_request():
    data = request.get_json()
    nombre = data.get('nombre')
    correo = data.get('correo')
    motivo = data.get('motivo')

    # Validaciones básicas
    if not all([nombre, correo, motivo]):
        return jsonify({"error": "Faltan campos requeridos: nombre, correo, motivo."}), 400

    if "@" not in correo or "." not in correo:
        return jsonify({"error": "El formato del correo electrónico es inválido."}), 400

    # Asegurarse de que Redis está conectado
    if redis_client is None:
        print("ERROR: Redis no está conectado. Las funciones de rate-limiting no están activas.", file=sys.stderr)
        # Si Redis no está disponible, puedes decidir si permites el envío de correos sin límite
        # o si bloqueas todas las solicitudes para evitar spam si no hay protección.
        # Por seguridad, es mejor bloquear si el rate-limiting es crítico.
        return jsonify({"error": "Error interno del servidor: el sistema de protección no está activo. Intente más tarde."}), 500


    current_time_utc = time.time() # Timestamp actual en segundos

    # --- Lógica de Protección Global contra Sobrecarga/Spam (usando Sorted Set en Redis) ---
    # Pipe para ejecutar múltiples comandos Redis de forma atómica
    pipe = redis_client.pipeline()
    
    # 1. Añadir el timestamp actual al set ordenado global
    # El score y el miembro son el timestamp actual para facilitar el rango por score
    pipe.zadd(GLOBAL_REQUEST_KEY, {current_time_utc: current_time_utc})
    
    # 2. Eliminar todas las entradas que estén fuera de la ventana de tiempo (5 minutos)
    oldest_timestamp_allowed = current_time_utc - GLOBAL_COOLDOWN_WINDOW_SECONDS
    pipe.zremrangebyscore(GLOBAL_REQUEST_KEY, '-inf', oldest_timestamp_allowed)
    
    # 3. Obtener el número actual de solicitudes en la ventana
    pipe.zcard(GLOBAL_REQUEST_KEY)
    
    # Ejecutar la transacción
    try:
        _, _, global_request_count = pipe.execute()
    except Exception as e:
        print(f"ERROR: Fallo en la operación de Redis para rate-limiting global: {e}", file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al verificar la carga global."}), 500

    if global_request_count > MAX_GLOBAL_REQUESTS_IN_WINDOW:
        print(f"ALERTA: Servidor bajo posible ataque de spam. {global_request_count} solicitudes en {GLOBAL_COOLDOWN_WINDOW_SECONDS} segundos. Bloqueando envío de correos.", file=sys.stderr)
        return jsonify({"message": "Hemos recibido su solicitud, pero estamos experimentando una alta demanda. Por favor, intente de nuevo más tarde.", "server_overload_detected": True}), 200

    # --- Lógica de Rate Limiting por Usuario (usando SETNX en Redis) ---
    user_cooldown_key = f"{USER_COOLDOWN_KEY_PREFIX}{correo}"
    
    try:
        # Intenta establecer la clave de cooldown. 
        # setnx devuelve 1 si la clave se estableció (no existía antes), 0 si ya existía.
        # Esto asegura atomicidad.
        # El valor (aquí '1') no importa mucho, solo si la clave existe o no.
        # El expire es para el tiempo de cooldown.
        cooldown_set = redis_client.set(user_cooldown_key, 1, nx=True, ex=COOLDOWN_PERIOD_PER_USER_SECONDS)

        if not cooldown_set:
            # Si cooldown_set es False (0), la clave ya existía, el usuario está en cooldown.
            print(f"DEBUG: Solicitud de soporte de '{correo}' ignorada por spam (cooldown activo en Redis).", file=sys.stderr)
            time_remaining = redis_client.ttl(user_cooldown_key)
            minutes_remaining = int(time_remaining / 60) if time_remaining else 0
            if minutes_remaining == 0 and time_remaining > 0:
                minutes_remaining = 1
            
            return jsonify({
                "message": f"Ya ha enviado una solicitud recientemente. Por favor, espere aproximadamente {minutes_remaining} minuto(s) antes de enviar otra.", 
                "email_not_sent": True
            }), 200
    except Exception as e:
        print(f"ERROR: Fallo en la operación de Redis para rate-limiting por usuario: {e}", file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al verificar el límite de solicitudes."}), 500

    # Si llegamos aquí, significa que la clave de cooldown se estableció correctamente (o no había error en Redis)
    # y podemos proceder con el envío del correo.
    print(f"DEBUG: Solicitud de soporte recibida de: {nombre} ({correo}), Motivo: {motivo}", file=sys.stderr)

    # --- LÓGICA DE ENVÍO DE CORREO ELECTRÓNICO USANDO SMTPLIB con STARTTLS ---
    try:
        # Obtener las credenciales del correo desde la configuración de la aplicación
        MAIL_USER = current_app.config['MAIL_USERNAME']
        MAIL_PASS = current_app.config['MAIL_PASSWORD']
        MAIL_SERVER = current_app.config.get('MAIL_SERVER', 'smtp.gmail.com')
        MAIL_PORT_TLS = current_app.config.get('MAIL_PORT', 587) # Usamos el puerto 587 para STARTTLS

        # Obtener la hora actual en UTC y convertirla a la hora de Colombia (UTC-5)
        utc_now = datetime.now(timezone.utc)
        colombia_offset = timedelta(hours=-5)
        colombia_time = utc_now + colombia_offset
        timestamp = colombia_time.strftime('%Y-%m-%d %H:%M:%S (UTC-5)')

        # --- Cuerpo del correo HTML con más detalle y estilo ---
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f7f6; margin: 0; padding: 0; }}
                .email-container {{ max-width: 600px; margin: 30px auto; background-color: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
                .header {{ background-color: #2c3e50; padding: 25px; text-align: center; color: #ffffff; border-bottom: 5px solid #3498db; }}
                .header h2 {{ margin: 0; font-size: 28px; font-weight: 600; }}
                .content {{ padding: 30px; }}
                .content p {{ margin-bottom: 15px; font-size: 16px; }}
                .content ul {{ list-style: none; padding: 0; margin-bottom: 20px; border-left: 4px solid #3498db; padding-left: 15px; }}
                .content ul li {{ margin-bottom: 8px; font-size: 15px; }}
                .content ul li strong {{ color: #2c3e50; }}
                .message-box {{ background-color: #ecf0f1; border-left: 5px solid #7f8c8d; padding: 20px; border-radius: 5px; margin-top: 20px; font-style: italic; color: #444; }}
                .message-box p {{ margin: 0; white-space: pre-wrap; font-family: 'Courier New', Courier, monospace; }}
                .footer {{ background-color: #ecf0f1; padding: 20px; text-align: center; font-size: 13px; color: #7f8c8d; border-top: 1px solid #e0e0e0; }}
                .footer p {{ margin: 5px 0; }}
                a {{ color: #3498db; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <h2>Gods Of Eternia - Sistema de Soporte</h2>
                </div>
                <div class="content">
                    <p>Estimado equipo de soporte,</p>
                    <p>Se ha recibido una <strong>nueva solicitud de asistencia</strong> a través del formulario de contacto de nuestro sitio web. Por favor, revise los detalles a continuación para dar el seguimiento correspondiente.</p>

                    <p><strong>Detalles de la Solicitud:</strong></p>
                    <ul>
                        <li><strong>Fecha y Hora de Envío:</strong> {timestamp}</li>
                        <li><strong>Nombre Completo del Usuario:</strong> {nombre}</li>
                        <li><strong>Correo Electrónico de Contacto:</strong> <a href="mailto:{correo}">{correo}</a></li>
                    </ul>

                    <p><strong>Mensaje del Usuario:</strong></p>
                    <div class="message-box">
                        <p>{motivo}</p>
                    </div>

                    <p>Es importante atender esta solicitud a la brevedad posible para mantener la satisfacción de nuestros usuarios.</p>
                </div>
                <div class="footer">
                    <p>Este es un correo electrónico generado automáticamente por el sistema de Gods Of Eternia.</p>
                    <p>Por favor, no responda directamente a este mensaje.</p>
                    <p>&copy; {datetime.now().year} Gods Of Eternia. Todos los derechos reservados.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Crear el objeto de mensaje MIME
        msg = MIMEText(html_body, 'html', 'utf-8')
        msg['Subject'] = Header(f'Nueva Solicitud de Soporte: {nombre}', 'utf-8')
        msg['From'] = MAIL_USER
        msg['To'] = MAIL_USER # El correo de soporte recibirá la solicitud

        # Configuración y envío del correo
        context = ssl.create_default_context()
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT_TLS) as server:
            server.starttls(context=context) # Iniciar la conexión TLS
            server.login(MAIL_USER, MAIL_PASS)
            server.send_message(msg)

        # Ya no necesitamos llamar a setex aquí, ya que set(..., nx=True, ex=...) lo hizo arriba.
        # El correo se envía solo si se pudo establecer la clave de cooldown al principio.

        print("DEBUG: Correo de soporte enviado exitosamente con smtplib y STARTTLS.", file=sys.stderr)

        return jsonify({"message": "Solicitud de soporte recibida y correo enviado exitosamente."}), 200

    except Exception as e:
        print(f"ERROR: No se pudo enviar el correo de soporte: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        
        # IMPORTANTE: Si el envío del correo falla, elimina la clave de cooldown
        # para que el usuario pueda intentarlo de nuevo sin esperar el cooldown completo.
        try:
            redis_client.delete(user_cooldown_key)
            print(f"DEBUG: Cooldown de '{correo}' eliminado debido a fallo en el envío del correo.", file=sys.stderr)
        except Exception as redis_err:
            print(f"ADVERTENCIA: Fallo al eliminar la clave de cooldown para {correo} después de un error de envío: {redis_err}", file=sys.stderr)
            
        return jsonify({"error": "Error interno del servidor al enviar el correo de soporte."}), 500