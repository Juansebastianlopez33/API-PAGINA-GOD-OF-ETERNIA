from flask import Blueprint, request, jsonify, current_app
from extensions import mysql
from MySQLdb.cursors import DictCursor # Importa DictCursor para obtener resultados como diccionarios
from werkzeug.utils import secure_filename
import os
import sys
import traceback
from datetime import datetime

# Importar PyJWT
import jwt

user_bp = Blueprint('user', __name__)

# --- Configuración JWT ---
# IMPORTANTE: Esta clave DEBE ser la MISMA que en auth.py
# Lo ideal sería cargarla desde app.config si la hubieras pasado desde app.py
# Por simplicidad aquí, la redefinimos, pero si la app crece, considera pasarla via current_app.config
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'tu_clave_secreta_jwt_muy_segura_aqui')


def get_user_from_jwt(auth_header):
    """
    Extrae el token del encabezado de autorización y decodifica el JWT.
    Retorna el payload decodificado o None en caso de error/token inválido.
    """
    token = None
    if auth_header and "Bearer " in auth_header:
        token = auth_header.split(" ")[1]
    else:
        print("Advertencia: Encabezado de autorización sin 'Bearer ' o no proporcionado.", file=sys.stderr)
        return None

    if not token:
        print("Advertencia: Token real no extraído del encabezado de autorización.", file=sys.stderr)
        return None

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("Advertencia: Token expirado.", file=sys.stderr)
        return None
    except jwt.InvalidTokenError:
        print("Advertencia: Token inválido.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error al decodificar JWT: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None

# Función auxiliar para obtener detalles completos del usuario desde la DB
def get_user_details(user_id):
    cursor = mysql.connection.cursor(DictCursor)
    try:
        cursor.execute("SELECT id, username, email, DescripUsuario, verificado, foto_perfil FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"Error al obtener detalles del usuario {user_id}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None
    finally:
        cursor.close()

# --- Rutas protegidas ---

@user_bp.route('/logeado', methods=['GET'])
def logeado():
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"logeado": 0, "error": "Token de autorización inválido o ausente."}), 401
    
    if not user_payload.get('verificado'):
        return jsonify({"logeado": 0, "error": "Cuenta no verificada."}), 403

    return jsonify({
        "logeado": 1,
        "user_id": user_payload.get('user_id'),
        "username": user_payload.get('username'),
        "email": user_payload.get('email')
    }), 200

@user_bp.route('/perfil', methods=['GET', 'PUT'])
def perfil():
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    if not user_payload.get('verificado'):
        return jsonify({"error": "Usuario no verificado."}), 403

    current_user_id = user_payload.get('user_id')
    username_from_jwt = user_payload.get('username')
    email_from_jwt = user_payload.get('email')

    user_details_from_db = get_user_details(current_user_id)
    if not user_details_from_db:
        return jsonify({"error": "Usuario no encontrado en la base de datos."}), 404

    descripcion = user_details_from_db.get('DescripUsuario')
    foto_perfil = user_details_from_db.get('foto_perfil')

    cursor = mysql.connection.cursor()
    try:
        if request.method == 'GET':
            cursor.execute("SELECT dificultad_id, puntaje_actual FROM partidas WHERE user_id = %s", (current_user_id,))
            puntajes = cursor.fetchall()

            return jsonify({
                "username": username_from_jwt, # Usamos el username del JWT
                "email": email_from_jwt,     # Usamos el email del JWT
                "descripcion": descripcion,  # Obtenido de la DB
                "foto_perfil": foto_perfil,  # Obtenido de la DB
                "puntajes": [{"dificultad": p[0], "puntaje": p[1]} for p in puntajes]
            }), 200
        
        elif request.method == 'PUT':
            data = request.get_json()
            nueva_descripcion = data.get("descripcion")
            nuevo_username = data.get("username")

            if nueva_descripcion is None or nuevo_username is None:
                return jsonify({"error": "Faltan campos requeridos: descripcion y username."}), 400

            # Verificar si el nuevo username ya está en uso por otro usuario
            cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (nuevo_username, current_user_id))
            if cursor.fetchone():
                return jsonify({"error": "El nombre de usuario ya está en uso."}), 409

            cursor.execute("UPDATE users SET DescripUsuario = %s, username = %s WHERE id = %s", (nueva_descripcion, nuevo_username, current_user_id))
            mysql.connection.commit()
            
            # Nota: Si el username cambia, el JWT actual seguirá teniendo el viejo.
            # Para reflejar el cambio inmediatamente, el cliente debería solicitar un nuevo JWT (volver a iniciar sesión).
            return jsonify({"mensaje": "Perfil actualizado correctamente. El nombre de usuario en tu token actual puede no estar actualizado hasta un nuevo login."}), 200
    
    except Exception as e:
        print(f"ERROR en /perfil: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al obtener/actualizar perfil."}), 500
    finally:
        cursor.close()


@user_bp.route('/publicaciones', methods=['GET'])
def publicaciones():
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    if not user_payload.get('verificado'):
        return jsonify({"error": "Usuario no verificado."}), 403

    current_user_id = user_payload.get('user_id')

    cursor = mysql.connection.cursor(DictCursor)
    try:
        cursor.execute("""
            SELECT p.id AS publicacion_id, u.username AS autor, p.created_at, p.texto
            FROM publicaciones p
            JOIN users u ON p.autor_id = u.id
            WHERE p.autor_id = %s
            ORDER BY p.created_at DESC
        """, (current_user_id,))
        publicaciones = cursor.fetchall()

        for pub in publicaciones:
            cursor.execute("SELECT COUNT(*) AS cantidad FROM comentarios WHERE publicacion_id = %s", (pub['publicacion_id'],))
            pub['cantidad_comentarios'] = cursor.fetchone()['cantidad']
            pub['created_at'] = pub['created_at'].isoformat() if pub['created_at'] else None

        cursor.execute("""
            SELECT c.id AS comentario_id, c.texto AS comentario_texto, u.username AS autor_comentario, c.created_at, p.texto AS publicacion_texto
            FROM comentarios c
            JOIN publicaciones p ON c.publicacion_id = p.id
            JOIN users u ON c.autor_id = u.id
            WHERE c.autor_id = %s
            ORDER BY c.created_at DESC
        """, (current_user_id,))
        comentarios = cursor.fetchall()

        for c in comentarios:
            c['created_at'] = c['created_at'].isoformat() if c['created_at'] else None

        return jsonify({
            "publicaciones": publicaciones,
            "comentarios": comentarios
        }), 200
    except Exception as e:
        print(f"Error en /publicaciones: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al obtener publicaciones/comentarios."}), 500
    finally:
        cursor.close()

@user_bp.route('/crear-publicacion', methods=['POST'])
def crear_publicacion():
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    if not user_payload.get('verificado'):
        return jsonify({"error": "Usuario no verificado."}), 403

    current_user_id = user_payload.get('user_id')
    texto = request.json.get('texto')

    if not texto:
        return jsonify({"error": "Texto de publicación es requerido."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("INSERT INTO publicaciones (autor_id, texto) VALUES (%s, %s)", (current_user_id, texto))
        mysql.connection.commit()
        return jsonify({"message": "Publicación creada exitosamente."}), 201
    except Exception as e:
        print(f"Error al crear publicación: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al crear publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/editar-publicacion/<int:publicacion_id>', methods=['PUT'])
def editar_publicacion(publicacion_id):
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    current_user_id = user_payload.get('user_id')
    nuevo_texto = request.json.get('texto')

    if not nuevo_texto:
        return jsonify({"error": "Nuevo texto de publicación es requerido."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != current_user_id:
            return jsonify({"error": "No autorizado para editar esta publicación."}), 403

        cursor.execute("UPDATE publicaciones SET texto = %s WHERE id = %s", (nuevo_texto, publicacion_id))
        mysql.connection.commit()
        return jsonify({"message": "Publicación editada correctamente."}), 200
    except Exception as e:
        print(f"Error al editar publicación: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al editar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-publicacion/<int:publicacion_id>', methods=['DELETE'])
def eliminar_publicacion(publicacion_id):
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    current_user_id = user_payload.get('user_id')

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != current_user_id:
            return jsonify({"error": "No autorizado para eliminar esta publicación."}), 403

        cursor.execute("DELETE FROM publicaciones WHERE id = %s", (publicacion_id,))
        mysql.connection.commit()
        return jsonify({"message": "Publicación eliminada correctamente."}), 200
    except Exception as e:
        print(f"Error al eliminar publicación: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al eliminar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/comentar-publicacion', methods=['POST'])
def comentar_publicacion():
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    if not user_payload.get('verificado'):
        return jsonify({"error": "Usuario no verificado."}), 403

    current_user_id = user_payload.get('user_id')
    publicacion_id = request.json.get('publicacion_id')
    comentario = request.json.get('comentario')

    if publicacion_id is None or not comentario:
        return jsonify({"error": "ID de publicación y comentario son requeridos."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id FROM publicaciones WHERE id = %s", (publicacion_id,))
        if not cursor.fetchone():
            return jsonify({"error": "La publicación no existe."}), 404

        cursor.execute(
            "INSERT INTO comentarios (publicacion_id, autor_id, texto) VALUES (%s, %s, %s)",
            (publicacion_id, current_user_id, comentario)
        )
        mysql.connection.commit()
        return jsonify({"message": "Comentario publicado exitosamente."}), 201
    except Exception as e:
        print(f"Error al comentar publicación: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al comentar."}), 500
    finally:
        cursor.close()


@user_bp.route('/editar-comentario/<int:comentario_id>', methods=['PUT'])
def editar_comentario(comentario_id):
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    current_user_id = user_payload.get('user_id')
    nuevo_texto = request.json.get('comentario')

    if not nuevo_texto:
        return jsonify({"error": "Nuevo texto del comentario requerido."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM comentarios WHERE id = %s", (comentario_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != current_user_id:
            return jsonify({"error": "No autorizado para editar este comentario."}), 403

        cursor.execute("UPDATE comentarios SET texto = %s WHERE id = %s", (nuevo_texto, comentario_id))
        mysql.connection.commit()
        return jsonify({"message": "Comentario editado correctamente."}), 200
    except Exception as e:
        print(f"Error al editar comentario: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al editar comentario."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-comentario/<int:comentario_id>', methods=['DELETE'])
def eliminar_comentario(comentario_id):
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    current_user_id = user_payload.get('user_id')

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM comentarios WHERE id = %s", (comentario_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != current_user_id:
            return jsonify({"error": "No autorizado para eliminar este comentario."}), 403

        cursor.execute("DELETE FROM comentarios WHERE id = %s", (comentario_id,))
        mysql.connection.commit()
        return jsonify({"message": "Comentario eliminado correctamente."}), 200
    except Exception as e:
        print(f"Error al eliminar comentario: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al eliminar comentario."}), 500
    finally:
        cursor.close()


@user_bp.route('/perfil/foto', methods=['PUT'])
def upload_profile_picture():
    auth_header = request.headers.get('Authorization')
    user_payload = get_user_from_jwt(auth_header)

    if not user_payload:
        return jsonify({"error": "No autorizado: Token inválido o ausente."}), 401
    
    if not user_payload.get('verificado'):
        return jsonify({"error": "Usuario no verificado."}), 403

    current_user_id = user_payload.get('user_id')
    username = user_payload.get('username') # Obtener el username del payload del JWT

    # Obtener la URL de la foto de perfil actual desde la base de datos
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT foto_perfil FROM users WHERE id = %s", (current_user_id,))
        result = cursor.fetchone()
        old_profile_picture_url = result[0] if result else None
    except Exception as e:
        print(f"Error al obtener foto_perfil antigua para user {current_user_id}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno al obtener la foto de perfil existente."}), 500
    finally:
        cursor.close()

    if 'profile_picture' not in request.files:
        return jsonify({'error': 'No se encontró el archivo de imagen en la solicitud. El campo esperado es "profile_picture".'}), 400
    
    file = request.files['profile_picture']

    if file.filename == '':
        return jsonify({'error': 'No se seleccionó ningún archivo.'}), 400
    
    allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif'})
    
    if file and '.' in file.filename and \
       file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
        
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if not upload_folder:
            print("ERROR: UPLOAD_FOLDER no está configurado en app.config.", file=sys.stderr)
            return jsonify({"error": "Error de configuración del servidor (UPLOAD_FOLDER no definido)."}, 500)

        # Se utiliza el username del JWT para la carpeta de usuario
        user_folder = os.path.join(upload_folder, str(username))
        
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        new_filename = secure_filename(f"profile_picture.{file_extension}")
        filepath = os.path.join(user_folder, new_filename)
        
        try:
            # Eliminar la foto de perfil antigua si existe
            if old_profile_picture_url:
                old_filename_from_url = os.path.basename(old_profile_picture_url)
                old_filepath = os.path.join(user_folder, old_filename_from_url)
                if os.path.exists(old_filepath) and old_filepath != filepath: # Evitar borrar si es el mismo archivo
                    os.remove(old_filepath)
                    print(f"Old profile picture removed: {old_filepath}", file=sys.stderr)

            file.save(filepath)

            base_url = current_app.config.get('API_BASE_URL', request.url_root.rstrip('/')) 
            image_url = f"{base_url}/uploads/{username}/{new_filename}"

            cursor = mysql.connection.cursor()
            try:
                cursor.execute("UPDATE users SET foto_perfil = %s WHERE id = %s", (image_url, current_user_id))
                mysql.connection.commit()
                return jsonify({
                    'message': 'Foto de perfil actualizada exitosamente.', 
                    'foto_perfil_url': image_url
                }), 200
            except Exception as db_e:
                if os.path.exists(filepath):
                    os.remove(filepath)
                print(f"Error DB al actualizar foto de perfil para user {current_user_id}: {db_e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                return jsonify({"error": "Error interno del servidor al guardar la URL de la foto de perfil."}), 500
            finally:
                cursor.close()

        except Exception as save_e:
            print(f"Error al guardar el archivo: {save_e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return jsonify({"error": "Error interno del servidor al guardar la imagen."}), 500
    else:
        return jsonify({'error': f"Tipo de archivo no permitido o nombre de archivo inválido. Solo se permiten {', '.join(allowed_extensions)}."}), 400