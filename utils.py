import random
import string
from email.mime.text import MIMEText
from email.header import Header
import smtplib
import os
from dotenv import load_dotenv

load_dotenv()


MAIL_USER = os.getenv('MAIL_USER')
MAIL_PASS = os.getenv('MAIL_PASS') 

def generar_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))

def generar_codigo_verificacion():
    return str(random.randint(100000, 999999))

def enviar_correo_verificacion(destinatario, codigo):
    cuerpo = f"Tu código de verificación es: {codigo}"
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
