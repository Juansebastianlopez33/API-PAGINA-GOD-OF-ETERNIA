from flask import Blueprint, request, jsonify, current_app
from extensions import mysql
from MySQLdb.cursors import DictCursor
from werkzeug.utils import secure_filename
import os
import sys
import traceback
from datetime import datetime
import shutil # Importar shutil para eliminar directorios

# Importar funciones de Flask-JWT-Extended
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from jwt import ExpiredSignatureError, InvalidTokenError, DecodeError # Importar excepciones de PyJWT

user_bp = Blueprint('user', __name__)

# Función auxiliar para obtener detalles completos del usuario desde la DB
def get_user_details(user_id):
    cursor = mysql.connection.cursor(DictCursor)
    try:
        cursor.execute("SELECT id, username, email, DescripUsuario, verificado, foto_perfil FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"ERROR: get_user_details - Error al obtener detalles del usuario {user_id}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None
    finally:
        cursor.close()

# --- Rutas protegidas (ahora usando @jwt_required) ---

@user_bp.route('/logeado', methods=['GET'])
@jwt_required() # Requiere un access token válido
def logeado():
    try:
        current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
        claims = get_jwt() # Obtiene todos los claims adicionales del token

        # DEBUG: Información de claims en token
        print(f"DEBUG BACKEND: /logeado -> Claims: {claims.get('verificado')}, UserID: {current_user_id}", file=sys.stderr)

        if claims.get('verificado', False): # Verifica el claim 'verificado' del token
            return jsonify({
                "logeado": 1,
                "user_id": current_user_id,
                "username": claims.get('username'), # Obtener del token
                "email": claims.get('email')        # Obtener del token
            }), 200
        else:
            return jsonify({"logeado": 0, "error": "Cuenta no verificada."}), 403
    except ExpiredSignatureError:
        print("ERROR: /logeado -> Token expirado.", file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Token de acceso expirado."}), 401
    except InvalidTokenError:
        print("ERROR: /logeado -> Token inválido.", file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Token de acceso inválido."}), 401
    except DecodeError: # Añadir manejo para errores de decodificación
        print("ERROR: /logeado -> Error al decodificar token.", file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Error al decodificar el token."}), 401
    except Exception as e:
        print(f"ERROR: /logeado -> Error inesperado: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Error interno del servidor al verificar sesión."}), 500


@user_bp.route('/perfil', methods=['GET', 'PUT'])
@jwt_required() # Requiere un access token válido
def perfil():
    try:
        current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
        user_details_from_db = get_user_details(current_user_id)
        if not user_details_from_db:
            print(f"ERROR: /perfil -> Usuario {current_user_id} no encontrado en DB.", file=sys.stderr)
            return jsonify({"error": "Usuario no encontrado en la base de datos."}), 404

        username_from_db = user_details_from_db.get('username')
        email_from_db = user_details_from_db.get('email')
        descripcion = user_details_from_db.get('DescripUsuario')
        foto_perfil = user_details_from_db.get('foto_perfil')

        cursor = mysql.connection.cursor()
        try:
            if request.method == 'GET':
                cursor.execute("SELECT dificultad_id, puntaje FROM leaderboard WHERE user_id = %s", (current_user_id,))
                puntajes_raw = cursor.fetchall()

                puntajes_formateados = []
                for p in puntajes_raw:
                    puntajes_formateados.append({"dificultad_id": p[0], "puntaje": p[1]})
                
                print(f"DEBUG BACKEND: /perfil -> Perfil para UserID {current_user_id} cargado.", file=sys.stderr)
                return jsonify({
                    "username": username_from_db,
                    "email": email_from_db,
                    "descripcion": descripcion,  
                    "foto_perfil": foto_perfil,  
                    "puntajes": puntajes_formateados
                }), 200

            elif request.method == 'PUT':
                data = request.get_json()
                nueva_descripcion = data.get("descripcion")
                nuevo_username = data.get("username")

                if nueva_descripcion is None or nuevo_username is None:
                    return jsonify({"error": "Faltan campos requeridos: descripcion y username."}), 400

                cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (nuevo_username, current_user_id))
                if cursor.fetchone():
                    print(f"DEBUG BACKEND: /perfil -> Nombre de usuario '{nuevo_username}' ya en uso.", file=sys.stderr)
                    return jsonify({"error": "El nombre de usuario ya está en uso."}), 409

                cursor.execute("UPDATE users SET DescripUsuario = %s, username = %s WHERE id = %s", (nueva_descripcion, nuevo_username, current_user_id))
                mysql.connection.commit()
                print(f"DEBUG BACKEND: /perfil -> Perfil para UserID {current_user_id} actualizado. Nuevo username: {nuevo_username}.", file=sys.stderr)
                return jsonify({
                    "message": "Perfil actualizado correctamente. Para que el nuevo nombre de usuario se refleje completamente en la aplicación, por favor, cierre sesión y vuelva a iniciarla.",
                    "updated_username": nuevo_username,
                    "updated_descripcion": nueva_descripcion
                }), 200
        except Exception as e:
            print(f"ERROR: /perfil -> Error en operación de DB/lógica: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return jsonify({"error": "Error interno del servidor al obtener/actualizar perfil."}), 500
        finally:
            cursor.close()

    except ExpiredSignatureError:
        print("ERROR: /perfil -> Token expirado.", file=sys.stderr)
        return jsonify({"error": "Token de acceso expirado. Por favor, inicie sesión de nuevo."}), 401
    except InvalidTokenError:
        print("ERROR: /perfil -> Token inválido.", file=sys.stderr)
        return jsonify({"error": "Token de acceso inválido. Por favor, inicie sesión de nuevo."}), 401
    except DecodeError: # Añadir manejo para errores de decodificación
        print("ERROR: /perfil -> Error al decodificar token.", file=sys.stderr)
        return jsonify({"error": "Error al decodificar el token."}), 401
    except Exception as e:
        print(f"ERROR: /perfil -> Error inesperado antes de la lógica de método: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al procesar el perfil."}), 500


@user_bp.route('/publicaciones', methods=['GET'])
def publicaciones():
    # Este endpoint es público, no requiere autenticación JWT.
    cursor = mysql.connection.cursor(DictCursor)
    try:
        cursor.execute("""
            SELECT
                p.id,
                p.autor_id,
                u.username AS author,
                p.titulo AS title,
                p.texto AS content,
                p.created_at,
                GROUP_CONCAT(ip.url ORDER BY ip.orden ASC) AS all_image_urls
            FROM publicaciones p
            JOIN users u ON p.autor_id = u.id
            LEFT JOIN imagenes_publicacion ip ON p.id = ip.publicacion_id
            GROUP BY p.id, p.autor_id, u.username, p.titulo, p.texto, p.created_at
            ORDER BY p.created_at DESC
        """)
        publicaciones = cursor.fetchall()

        for pub in publicaciones:
            cursor.execute("SELECT COUNT(*) AS cantidad FROM comentarios WHERE publicacion_id = %s", (pub['id'],))
            pub['cantidad_comentarios'] = cursor.fetchone()['cantidad']

            pub['created_at'] = pub['created_at'].isoformat() if pub['created_at'] else None

            all_urls_str = pub.pop('all_image_urls')
            if all_urls_str:
                all_urls = [url for url in all_urls_str.split(',') if url]
                pub['imageUrl'] = all_urls[0] if all_urls else None
                pub['imagenes_adicionales_urls'] = all_urls[1:] if len(all_urls) > 1 else []
            else:
                pub['imageUrl'] = None
                pub['imagenes_adicionales_urls'] = []

        print(f"DEBUG BACKEND: /publicaciones -> {len(publicaciones)} publicaciones obtenidas.", file=sys.stderr)
        return jsonify(publicaciones), 200
    except Exception as e:
        print(f"ERROR: /publicaciones -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al obtener publicaciones."}), 500
    finally:
        cursor.close()

@user_bp.route('/crear-publicacion', methods=['POST'])
@jwt_required() # Requiere un access token válido
def crear_publicacion():
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
    claims = get_jwt()
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /crear-publicacion -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    texto = request.json.get('texto')
    titulo = request.json.get('titulo')

    if not texto or not titulo:
        print(f"DEBUG BACKEND: /crear-publicacion -> Faltan título o texto.", file=sys.stderr)
        return jsonify({"error": "Título y texto de la publicación son requeridos."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("INSERT INTO publicaciones (autor_id, titulo, texto) VALUES (%s, %s, %s)", (current_user_id, titulo, texto))
        mysql.connection.commit()

        new_post_id = cursor.lastrowid
        print(f"DEBUG BACKEND: /crear-publicacion -> Publicación {new_post_id} creada por UserID {current_user_id}. Devolviendo 201 OK.", file=sys.stderr)
        return jsonify({"message": "Publicación creada exitosamente.", "publicacion_id": new_post_id}), 201
    except Exception as e:
        print(f"ERROR: /crear-publicacion -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor"}), 500
    finally:
        cursor.close()

@user_bp.route('/editar-publicacion/<int:publicacion_id>', methods=['PUT'])
@jwt_required() # Requiere un access token válido
def editar_publicacion(publicacion_id):
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt()

    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /editar-publicacion -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    nuevo_texto = request.json.get('texto')
    nuevo_titulo = request.json.get('titulo')

    if not nuevo_texto or not nuevo_titulo:
        print(f"DEBUG BACKEND: /editar-publicacion -> Faltan título o texto.", file=sys.stderr)
        return jsonify({"error": "Nuevo título y texto de publicación son requeridos."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        
        # DEBUG: Comprobación de autoría
        post_author_id_from_db = resultado[0] if resultado else 'N/A'
        print(f"DEBUG BACKEND: /editar-publicacion -> UserID: {current_user_id}, Post AuthorID (DB): {post_author_id_from_db}. Match: {current_user_id == post_author_id_from_db}", file=sys.stderr)

        if not resultado or resultado[0] != current_user_id:
            print(f"DEBUG BACKEND: /editar-publicacion -> Acceso DENEGADO (ID no coincide). Devolviendo 403.", file=sys.stderr)
            return jsonify({"error": "No autorizado para editar esta publicación."}), 403
        
        cursor.execute("UPDATE publicaciones SET texto = %s, titulo = %s WHERE id = %s", (nuevo_texto, nuevo_titulo, publicacion_id))
        mysql.connection.commit()
        print(f"DEBUG BACKEND: /editar-publicacion -> Publicación {publicacion_id} editada por UserID {current_user_id}. Devolviendo 200 OK.", file=sys.stderr)
        return jsonify({"message": "Publicación editada correctamente."}), 200
    except Exception as e:
        print(f"ERROR: /editar-publicacion -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al editar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-publicacion/<int:publicacion_id>', methods=['DELETE'])
@jwt_required() # Requiere un access token válido
def eliminar_publicacion(publicacion_id):
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt()
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /eliminar-publicacion -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        
        # DEBUG: Comprobación de autoría
        post_author_id_from_db = resultado[0] if resultado else 'N/A'
        print(f"DEBUG BACKEND: /eliminar-publicacion -> UserID: {current_user_id}, Post AuthorID (DB): {post_author_id_from_db}. Match: {current_user_id == post_author_id_from_db}", file=sys.stderr)

        if not resultado or resultado[0] != current_user_id:
            print(f"DEBUG BACKEND: /eliminar-publicacion -> Acceso DENEGADO (ID no coincide). Devolviendo 403.", file=sys.stderr)
            return jsonify({"error": "No autorizado para eliminar esta publicación."}), 403

        # DEBUG: Autorización OK, iniciando eliminación
        print(f"DEBUG BACKEND: /eliminar-publicacion -> Autorización PASÓ. Eliminando publicación {publicacion_id}.", file=sys.stderr)

        # --- Lógica para eliminar la carpeta completa de la publicación ---
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        base_publicaciones_path = os.path.join(upload_folder, 'publicaciones')
        publicacion_folder_name = f"publicacion-{publicacion_id}" 
        publicacion_folder_path = os.path.join(base_publicaciones_path, publicacion_folder_name)

        if os.path.exists(publicacion_folder_path):
            try:
                shutil.rmtree(publicacion_folder_path)
                print(f"DEBUG BACKEND: Carpeta de publicación eliminada: {publicacion_folder_path}", file=sys.stderr)
            except Exception as e:
                print(f"ERROR: No se pudo eliminar la carpeta de publicación {publicacion_folder_path}: {e}", file=sys.stderr)

        cursor.execute("DELETE FROM publicaciones WHERE id = %s", (publicacion_id,))
        mysql.connection.commit()
        print(f"DEBUG BACKEND: /eliminar-publicacion -> Publicación {publicacion_id} eliminada por UserID {current_user_id}. Devolviendo 200 OK.", file=sys.stderr)
        return jsonify({"message": "Publicación eliminada correctamente."}), 200
    except Exception as e:
        print(f"ERROR: /eliminar-publicacion -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al eliminar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/comentar-publicacion', methods=['POST'])
@jwt_required() # Requiere un access token válido
def comentar_publicacion():
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt()
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /comentar-publicacion -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    publicacion_id = request.json.get('publicacion_id')
    comentario = request.json.get('comentario')

    if publicacion_id is None or not comentario:
        print(f"DEBUG BACKEND: /comentar-publicacion -> ID de publicación o comentario faltante.", file=sys.stderr)
        return jsonify({"error": "ID de publicación y comentario son requeridos."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id FROM publicaciones WHERE id = %s", (publicacion_id,))
        if not cursor.fetchone():
            print(f"DEBUG BACKEND: /comentar-publicacion -> Publicación {publicacion_id} no encontrada.", file=sys.stderr)
            return jsonify({"error": "La publicación no existe."}), 404

        cursor.execute(
            "INSERT INTO comentarios (publicacion_id, autor_id, texto) VALUES (%s, %s, %s)",
            (publicacion_id, current_user_id, comentario)
        )
        mysql.connection.commit()
        print(f"DEBUG BACKEND: /comentar-publicacion -> Comentario para Publicación {publicacion_id} creado por UserID {current_user_id}. Devolviendo 201 OK.", file=sys.stderr)
        return jsonify({"message": "Comentario publicado exitosamente."}), 201
    except Exception as e:
        print(f"ERROR: /comentar-publicacion -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al comentar."}), 500
    finally:
        cursor.close()

# Ruta para obtener comentarios de una publicación
@user_bp.route('/publicaciones/<int:publicacion_id>/comentarios', methods=['GET'])
def get_comentarios_publicacion(publicacion_id):
    try:
        conn = mysql.connection
        cursor = conn.cursor(DictCursor)

        cursor.execute("SELECT id FROM publicaciones WHERE id = %s", (publicacion_id,))
        publication_exists = cursor.fetchone()
        if not publication_exists:
            print(f"DEBUG BACKEND: /publicaciones/<id>/comentarios -> Publicación {publicacion_id} no encontrada.", file=sys.stderr)
            return jsonify({"error": "Publicación no encontrada."}), 404

        cursor.execute("""
            SELECT 
                c.id, 
                c.autor_id, 
                u.username AS author, 
                c.texto AS text, 
                c.created_at 
            FROM 
                comentarios c
            JOIN 
                users u ON c.autor_id = u.id
            WHERE 
                c.publicacion_id = %s
            ORDER BY 
                c.created_at DESC
        """, (publicacion_id,))
        comentarios = cursor.fetchall()

        for comentario in comentarios:
            if isinstance(comentario['created_at'], datetime):
                comentario['created_at'] = comentario['created_at'].isoformat()
        
        print(f"DEBUG BACKEND: /publicaciones/<id>/comentarios -> {len(comentarios)} comentarios para Publicación {publicacion_id} obtenidos.", file=sys.stderr)
        return jsonify(comentarios), 200
    except Exception as e:
        print(f"ERROR: /publicaciones/<id>/comentarios -> Error: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al obtener comentarios."}), 500
    finally:
        cursor.close()


@user_bp.route('/editar-comentario/<int:comentario_id>', methods=['PUT'])
@jwt_required() # Requiere un access token válido
def editar_comentario(comentario_id):
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt()
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /editar-comentario -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    nuevo_texto = request.json.get('comentario')

    if not nuevo_texto:
        print(f"DEBUG BACKEND: /editar-comentario -> Texto de comentario faltante.", file=sys.stderr)
        return jsonify({"error": "Nuevo texto del comentario requerido."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM comentarios WHERE id = %s", (comentario_id,))
        resultado = cursor.fetchone()
        
        # DEBUG: Comprobación de autoría
        comment_author_id_from_db = resultado[0] if resultado else 'N/A'
        print(f"DEBUG BACKEND: /editar-comentario -> UserID: {current_user_id}, Comment AuthorID (DB): {comment_author_id_from_db}. Match: {current_user_id == comment_author_id_from_db}", file=sys.stderr)

        if not resultado or resultado[0] != current_user_id:
            print(f"DEBUG BACKEND: /editar-comentario -> Acceso DENEGADO (ID no coincide). Devolviendo 403.", file=sys.stderr)
            return jsonify({"error": "No autorizado para editar este comentario."}), 403

        cursor.execute("UPDATE comentarios SET texto = %s WHERE id = %s", (nuevo_texto, comentario_id))
        mysql.connection.commit()
        print(f"DEBUG BACKEND: /editar-comentario -> Comentario {comentario_id} editado por UserID {current_user_id}. Devolviendo 200 OK.", file=sys.stderr)
        return jsonify({"message": "Comentario editado correctamente."}), 200
    except Exception as e:
        print(f"ERROR: /editar-comentario -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al editar comentario."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-comentario/<int:comentario_id>', methods=['DELETE'])
@jwt_required() # Requiere un access token válido
def eliminar_comentario(comentario_id):
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt()
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /eliminar-comentario -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM comentarios WHERE id = %s", (comentario_id,))
        resultado = cursor.fetchone()

        # DEBUG: Comprobación de autoría
        comment_author_id_from_db = resultado[0] if resultado else 'N/A'
        print(f"DEBUG BACKEND: /eliminar-comentario -> UserID: {current_user_id}, Comment AuthorID (DB): {comment_author_id_from_db}. Match: {current_user_id == comment_author_id_from_db}", file=sys.stderr)

        if not resultado or resultado[0] != current_user_id:
            print(f"DEBUG BACKEND: /eliminar-comentario -> Acceso DENEGADO (ID no coincide). Devolviendo 403.", file=sys.stderr)
            return jsonify({"error": "No autorizado para eliminar este comentario."}), 403

        cursor.execute("DELETE FROM comentarios WHERE id = %s", (comentario_id,))
        mysql.connection.commit()
        print(f"DEBUG BACKEND: /eliminar-comentario -> Comentario {comentario_id} eliminado por UserID {current_user_id}. Devolviendo 200 OK.", file=sys.stderr)
        return jsonify({"message": "Comentario eliminado correctamente."}), 200
    except Exception as e:
        print(f"ERROR: /eliminar-comentario -> Error: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al eliminar comentario."}), 500
    finally:
        cursor.close()


@user_bp.route('/perfil/foto', methods=['PUT'])
@jwt_required() # Requiere un access token válido
def upload_profile_picture():
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt() 
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /perfil/foto -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    if 'profile_picture' not in request.files:
        print(f"DEBUG BACKEND: /perfil/foto -> Archivo de imagen faltante.", file=sys.stderr)
        return jsonify({'error': 'No se encontró el archivo de imagen en la solicitud. El campo esperado es "profile_picture".'}), 400

    file = request.files['profile_picture']

    if file.filename == '':
        print(f"DEBUG BACKEND: /perfil/foto -> Nombre de archivo vacío.", file=sys.stderr)
        return jsonify({'error': 'No se seleccionó ningún archivo.'}), 400

    allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif'})

    if file and '.' in file.filename and \
    file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:

        file_extension = file.filename.rsplit('.', 1)[1].lower()

        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if not upload_folder:
            print("ERROR: UPLOAD_FOLDER no está configurado en app.config.", file=sys.stderr)
            return jsonify({"error": "Error de configuración del servidor (UPLOAD_FOLDER no definido)."}, 500)

        base_profile_pictures_path = os.path.join(upload_folder, 'fotos_perfil')
        user_folder = os.path.join(base_profile_pictures_path, str(current_user_id))

        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        new_filename = secure_filename(f"profile_picture_{timestamp}.{file_extension}")
        filepath = os.path.join(user_folder, new_filename)

        cursor = mysql.connection.cursor()
        try:
            for existing_file in os.listdir(user_folder):
                if existing_file.startswith("profile_picture_") and existing_file != new_filename:
                    existing_filepath = os.path.join(user_folder, existing_file)
                    try:
                        os.remove(existing_filepath)
                        print(f"DEBUG BACKEND: Eliminada foto de perfil antigua: {existing_filepath}", file=sys.stderr)
                    except Exception as delete_e:
                        print(f"ERROR: No se pudo eliminar la foto de perfil antigua {existing_filepath}: {delete_e}", file=sys.stderr)

            file.save(filepath)

            base_url = current_app.config.get('API_BASE_URL', request.url_root.rstrip('/'))
            image_url = f"{base_url}/uploads/fotos_perfil/{current_user_id}/{new_filename}"

            cursor.execute("UPDATE users SET foto_perfil = %s WHERE id = %s", (image_url, current_user_id))
            mysql.connection.commit()
            print(f"DEBUG BACKEND: /perfil/foto -> Foto de perfil para UserID {current_user_id} actualizada. Devolviendo 200 OK.", file=sys.stderr)
            return jsonify({
                'message': 'Foto de perfil actualizada exitosamente.',
                'foto_perfil_url': image_url
            }), 200
        except Exception as save_e:
            if os.path.exists(filepath):
                os.remove(filepath)
            print(f"ERROR: /perfil/foto -> Error al guardar archivo o DB: {save_e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return jsonify({"error": "Error interno del servidor al guardar la foto de perfil."}), 500
        finally:
            cursor.close()
    else:
        print(f"DEBUG BACKEND: /perfil/foto -> Tipo de archivo no permitido: {file.filename}", file=sys.stderr)
        return jsonify({'error': f"Tipo de archivo no permitido o nombre de archivo inválido. Solo se permiten {', '.join(allowed_extensions)}."}), 400


@user_bp.route('/publicaciones/<int:publicacion_id>/upload_imagen', methods=['POST'])
@jwt_required() # Requiere un access token válido
def upload_publicacion_image(publicacion_id):
    current_user_id_str = get_jwt_identity()
    current_user_id = int(current_user_id_str)
    claims = get_jwt()
    
    # DEBUG: Verificación de usuario
    if not claims.get('verificado', False):
        print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> Usuario NO verificado (UserID: {current_user_id}). Devolviendo 403.", file=sys.stderr)
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor()
    try:
        # 1. Verificar si la publicación existe y pertenece al usuario actual
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        publicacion = cursor.fetchone()
        
        # DEBUG: Comprobación de autoría
        post_author_id_from_db = publicacion[0] if publicacion else 'N/A'
        print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> UserID: {current_user_id}, Post AuthorID (DB): {post_author_id_from_db}. Match: {current_user_id == post_author_id_from_db}", file=sys.stderr)

        if not publicacion or publicacion[0] != current_user_id:
            print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> Acceso DENEGADO (ID no coincide o publicación no encontrada). Devolviendo 403.", file=sys.stderr)
            return jsonify({"error": "No tienes permiso para subir imágenes a esta publicación."}), 403

        if 'imagen_publicacion' not in request.files:
            print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> Archivo de imagen faltante.", file=sys.stderr)
            return jsonify({'error': 'No se encontró el archivo de imagen en la solicitud. El campo esperado es "imagen_publicacion".'}), 400

        file = request.files['imagen_publicacion']

        if file.filename == '':
            print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> Nombre de archivo vacío.", file=sys.stderr)
            return jsonify({'error': 'No se seleccionó ningún archivo.'}), 400

        allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif'})

        if file and '.' in file.filename and \
        file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:

            file_extension = file.filename.rsplit('.', 1)[1].lower()

            upload_folder = current_app.config.get('UPLOAD_FOLDER')
            if not upload_folder:
                print("ERROR: UPLOAD_FOLDER no está configurado en app.config.", file=sys.stderr)
                return jsonify({"error": "Error de configuración del servidor (UPLOAD_FOLDER no definido)."}, 500)

            base_publicaciones_path = os.path.join(upload_folder, 'publicaciones')
            publicacion_folder_name = f"publicacion-{publicacion_id}" 
            publicacion_folder_path = os.path.join(base_publicaciones_path, publicacion_folder_name)

            if not os.path.exists(publicacion_folder_path):
                os.makedirs(publicacion_folder_path)

            timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
            original_filename_secure = secure_filename(file.filename.rsplit('.', 1)[0])
            new_filename = f"{original_filename_secure}_{timestamp}.{file_extension}"
            filepath = os.path.join(publicacion_folder_path, new_filename)

            try:
                file.save(filepath)

                base_url = current_app.config.get('API_BASE_URL', request.url_root.rstrip('/'))
                image_url = f"{base_url}/uploads/publicaciones/{publicacion_folder_name}/{new_filename}"

                cursor.execute("INSERT INTO imagenes_publicacion (publicacion_id, url) VALUES (%s, %s)", (publicacion_id, image_url))
                mysql.connection.commit()
                print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> Imagen subida para PostID {publicacion_id} por UserID {current_user_id}. Devolviendo 201 OK.", file=sys.stderr)
                return jsonify({
                    'message': 'Imagen de publicación subida exitosamente.',
                    'imagen_url': image_url
                }), 201
            except Exception as save_e:
                if os.path.exists(filepath):
                    os.remove(filepath)
                print(f"ERROR: /publicaciones/<id>/upload_imagen -> Error al guardar archivo o DB: {save_e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                return jsonify({"error": "Error interno del servidor al guardar la imagen de la publicación."}), 500
        else:
            print(f"DEBUG BACKEND: /publicaciones/<id>/upload_imagen -> Tipo de archivo no permitido: {file.filename}", file=sys.stderr)
            return jsonify({'error': f"Tipo de archivo no permitido o nombre de archivo inválido. Solo se permiten {', '.join(allowed_extensions)}."}), 400
    finally:
        cursor.close()
