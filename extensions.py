# extensions.py
from flask import Flask
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import redis
import os
import sys

mysql = MySQL()
bcrypt = Bcrypt()
redis_client = None # Variable global para el cliente Redis

def init_app(app: Flask):
    mysql.init_app(app)
    bcrypt.init_app(app)

    global redis_client
    # Obtener detalles de conexión de Redis de variables de entorno o config de la app
    redis_host = app.config.get('REDIS_HOST', os.getenv('REDIS_HOST', 'localhost'))
    redis_port = int(app.config.get('REDIS_PORT', os.getenv('REDIS_PORT', 6379)))
    redis_db = int(app.config.get('REDIS_DB', os.getenv('REDIS_DB', 0)))

    try:
        redis_client = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
        # Probar la conexión a Redis
        redis_client.ping()
        print("INFO: Conectado exitosamente a Redis!")
    except redis.exceptions.ConnectionError as e:
        print(f"ERROR: No se pudo conectar a Redis: {e}. Las funciones de rate-limiting NO funcionarán correctamente.", file=sys.stderr)
        redis_client = None # Asegúrate de que el cliente sea None si la conexión falla
    except Exception as e:
        print(f"ERROR: Error inesperado al conectar a Redis: {e}", file=sys.stderr)
        redis_client = None