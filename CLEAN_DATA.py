import os
import mysql.connector
from dotenv import load_dotenv

# Cargar variables de entorno desde el archivo .env
# Asegúrate de que este script esté en la raíz de tu proyecto donde .env se encuentra
load_dotenv()

# --- Configuración de la Base de Datos ---
# Se obtienen los valores del archivo .env, pero el HOST es forzado a '127.0.0.1'.
# Esto es CRÍTICO porque el script se ejecuta desde la máquina HOST,
# y la base de datos MySQL en Docker es accesible desde el HOST a través de localhost (127.0.0.1)
# si el puerto 3307 (o el que uses) está mapeado en docker-compose.yml.
DB_HOST = '127.0.0.1' 
DB_PORT = 3307 # <--- PUERTO DE LA BASE DE DATOS ACTUALIZADO A 3307
DB_USER = os.getenv('MYSQL_USER', 'root')
DB_PASSWORD = os.getenv('MYSQL_PASSWORD', '') # Asegúrate de que esta sea la contraseña correcta para MYSQL_USER
DB_NAME = os.getenv('MYSQL_DB', 'flask_api')

# --- Configuración de la Carpeta de Fotos ---
# IMPORTANTE: Esta debe ser la RUTA DE LA CARPETA EN TU MÁQUINA HOST
# que está mapeada al volumen de Docker (ej. ./data/uploaded_images)
# Asegúrate de que esta ruta sea correcta para tu configuración de Docker Compose.
# Si tu docker-compose.yml usa './data/uploaded_images:/app/uploads',
# entonces 'UPLOAD_FOLDER_HOST' debe ser './data/uploaded_images'.
UPLOAD_FOLDER_HOST = os.getenv('UPLOAD_FOLDER_HOST_PATH', './data/uploaded_images')

# Lista de tablas a truncar (en orden para evitar problemas de Foreign Key,
# aunque se desactivan las comprobaciones de FK para mayor seguridad)
TABLES_TO_TRUNCATE = [
    "comentarios",
    "imagenes_publicacion",
    "publicaciones",
    "leaderboard",
    "partidas",
    "users" # La tabla de usuarios es la última en vaciarse
]

def clean_uploaded_photos(folder_path):
    """
    Elimina todos los archivos (fotos) de la carpeta especificada en el host.
    """
    if not os.path.exists(folder_path):
        print(f"La carpeta '{folder_path}' no existe. No hay fotos para eliminar.")
        return

    print(f"Limpiando fotos en: {os.path.abspath(folder_path)}")
    deleted_count = 0
    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                deleted_count += 1
                # print(f"  Eliminado: {filename}") # Descomentar para ver cada archivo eliminado
        print(f"Se eliminaron {deleted_count} fotos de la carpeta '{folder_path}'.")
    except Exception as e:
        print(f"Error al limpiar fotos: {e}")

def truncate_database_tables(host, port, user, password, database, tables): # Añadido 'port'
    """
    Se conecta a la base de datos y trunca las tablas especificadas.
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port, # <--- Se pasa el puerto aquí
            user=user,
            password=password,
            database=database
        )
        cursor = conn.cursor()

        print(f"\nConectado a la base de datos '{database}' en '{host}:{port}'.") # Actualizado el mensaje
        print("Desactivando comprobaciones de clave foránea...")
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
        conn.commit()

        for table in tables:
            print(f"Truncando tabla: {table}...")
            cursor.execute(f"TRUNCATE TABLE {table};")
            conn.commit()
            print(f"  Tabla '{table}' truncada.")

        print("\nReactivando comprobaciones de clave foránea...")
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
        conn.commit()
        print("Base de datos limpiada exitosamente.")

    except mysql.connector.Error as err:
        print(f"Error de base de datos al conectar o truncar: {err}")
        print(f"Asegúrate de que la base de datos esté corriendo y que '{host}:{port}' sea accesible.")
        print(f"Verifica las credenciales (usuario: {user}, contraseña) y el nombre de la DB '{database}'.")
        print(f"Si tu base de datos está en Docker, asegúrate de que el puerto '{port}' esté mapeado a localhost en tu docker-compose.yml.")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
            print("Conexión a la base de datos cerrada.")

if __name__ == "__main__":
    print("--- INICIANDO PROCESO DE LIMPIEZA ---")
    
    # 1. Limpiar fotos
    clean_uploaded_photos(UPLOAD_FOLDER_HOST)
    
    # 2. Limpiar datos de la base de datos
    truncate_database_tables(DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, TABLES_TO_TRUNCATE) # Pasamos DB_PORT
    
    print("\n--- PROCESO DE LIMPIEZA COMPLETADO ---")

