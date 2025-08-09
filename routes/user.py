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
        # print(f"DEBUG: get_user_details - Buscando usuario con ID: {user_id}", file=sys.stderr) # Eliminado debug
        cursor.execute("SELECT id, username, email, DescripUsuario, verificado, foto_perfil FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        # if user: # Eliminado debug
        #     print(f"DEBUG: get_user_details - Usuario encontrado: {user['username']}", file=sys.stderr)
        # else:
        #     print(f"DEBUG: get_user_details - Usuario con ID {user_id} NO encontrado.", file=sys.stderr)
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

        # print(f"DEBUG: /logeado - User ID from JWT: {current_user_id}", file=sys.stderr) # Eliminado debug
        # print(f"DEBUG: /logeado - Claims from JWT: {claims}", file=sys.stderr) # Eliminado debug

        if claims.get('verificado', False): # Verifica el claim 'verificado' del token
            return jsonify({
                "logeado": 1,
                "user_id": current_user_id,
                "username": claims.get('username'), # Obtener del token
                "email": claims.get('email')        # Obtener del token
            }), 200
        else:
            # print(f"DEBUG: /logeado - Usuario {current_user_id} no verificado según JWT claims.", file=sys.stderr) # Eliminado debug
            return jsonify({"logeado": 0, "error": "Cuenta no verificada."}), 403
    except ExpiredSignatureError:
        print("ERROR: /logeado - Token expirado.", file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Token de acceso expirado."}), 401
    except InvalidTokenError:
        print("ERROR: /logeado - Token inválido.", file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Token de acceso inválido."}), 401
    except DecodeError: # Añadir manejo para errores de decodificación
        print("ERROR: /logeado - Error al decodificar el token.", file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Error al decodificar el token."}), 401
    except Exception as e:
        print(f"ERROR: /logeado - Error inesperado: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"logeado": 0, "error": "Error interno del servidor al verificar sesión."}), 500


@user_bp.route('/perfil', methods=['GET', 'PUT'])
@jwt_required() # Requiere un access token válido
def perfil():
    # print("DEBUG: Entrando a la ruta /perfil", file=sys.stderr) # Eliminado debug
    try:
        current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
        # print(f"DEBUG: /perfil - User ID from JWT: {current_user_id}", file=sys.stderr) # Eliminado debug

        # SIEMPRE obtener los detalles del usuario de la DB para asegurar que sean los más recientes
        user_details_from_db = get_user_details(current_user_id)
        if not user_details_from_db:
            print(f"ERROR: /perfil - No se encontraron detalles del usuario {current_user_id} en la DB.", file=sys.stderr)
            return jsonify({"error": "Usuario no encontrado en la base de datos."}), 404

        # Usamos los datos de la DB para la respuesta GET y para la lógica PUT
        username_from_db = user_details_from_db.get('username')
        email_from_db = user_details_from_db.get('email')
        descripcion = user_details_from_db.get('DescripUsuario')
        foto_perfil = user_details_from_db.get('foto_perfil')

        cursor = mysql.connection.cursor()
        try:
            if request.method == 'GET':
                # print("DEBUG: /perfil - Método GET", file=sys.stderr) # Eliminado debug
                cursor.execute("SELECT dificultad_id, puntaje FROM leaderboard WHERE user_id = %s", (current_user_id,))
                puntajes_raw = cursor.fetchall()
                # print(f"DEBUG: /perfil - Datos de puntajes obtenidos: {puntajes_raw}", file=sys.stderr) # Eliminado debug

                # Formatear los puntajes para el frontend
                puntajes_formateados = []
                for p in puntajes_raw:
                    # Asumiendo que p[0] es dificultad_id y p[1] es puntaje
                    # Puedes necesitar mapear dificultad_id a nombres si no lo haces en el frontend
                    puntajes_formateados.append({"dificultad_id": p[0], "puntaje": p[1]})


                return jsonify({
                    "username": username_from_db, # Usamos el username más reciente de la DB
                    "email": email_from_db,      # Usamos el email más reciente de la DB
                    "descripcion": descripcion,  
                    "foto_perfil": foto_perfil,  
                    "puntajes": puntajes_formateados
                }), 200

            elif request.method == 'PUT':
                # print("DEBUG: /perfil - Método PUT", file=sys.stderr) # Eliminado debug
                data = request.get_json()
                nueva_descripcion = data.get("descripcion")
                nuevo_username = data.get("username")

                # print(f"DEBUG: /perfil - PUT Data: username={nuevo_username}, descripcion={nueva_descripcion}", file=sys.stderr) # Eliminado debug

                if nueva_descripcion is None or nuevo_username is None:
                    # print("ERROR: /perfil - PUT - Faltan campos requeridos.", file=sys.stderr) # Eliminado debug
                    return jsonify({"error": "Faltan campos requeridos: descripcion y username."}), 400

                # Verificar si el nuevo username ya está en uso por otro usuario
                cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (nuevo_username, current_user_id))
                if cursor.fetchone():
                    # print(f"ERROR: /perfil - PUT - Username '{nuevo_username}' ya en uso.", file=sys.stderr) # Eliminado debug
                    return jsonify({"error": "El nombre de usuario ya está en uso."}), 409

                cursor.execute("UPDATE users SET DescripUsuario = %s, username = %s WHERE id = %s", (nueva_descripcion, nuevo_username, current_user_id))
                mysql.connection.commit()
                # print(f"DEBUG: /perfil - PUT - Perfil actualizado en DB para {current_user_id}.", file=sys.stderr) # Eliminado debug

                # Mensaje claro para el frontend sobre la actualización del JWT
                return jsonify({
                    "message": "Perfil actualizado correctamente. Para que el nuevo nombre de usuario se refleje completamente en la aplicación, por favor, cierre sesión y vuelva a iniciarla.",
                    "updated_username": nuevo_username, # Devolver el nuevo username para que el frontend lo use inmediatamente si lo desea
                    "updated_descripcion": nueva_descripcion
                }), 200
        except Exception as e:
            # Este es un catch interno para errores dentro de la lógica GET/PUT
            print(f"ERROR: /perfil - Error durante la operación de DB/lógica: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return jsonify({"error": "Error interno del servidor al obtener/actualizar perfil."}), 500
        finally:
            cursor.close()

    except ExpiredSignatureError:
        print("ERROR: /perfil - Token expirado.", file=sys.stderr)
        return jsonify({"error": "Token de acceso expirado. Por favor, inicie sesión de nuevo."}), 401
    except InvalidTokenError:
        print("ERROR: /perfil - Token inválido.", file=sys.stderr)
        return jsonify({"error": "Token de acceso inválido. Por favor, inicie sesión de nuevo."}), 401
    except DecodeError: # Añadir manejo para errores de decodificación
        print("ERROR: /perfil - Error al decodificar el token.", file=sys.stderr)
        return jsonify({"error": "Error al decodificar el token."}), 401
    except Exception as e:
        # Este es un catch para errores que ocurren antes de la lógica GET/PUT (ej. en get_jwt_identity())
        print(f"ERROR: /perfil - Error inesperado antes de la lógica de método: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al procesar el perfil."}), 500


@user_bp.route('/publicaciones', methods=['GET'])
def publicaciones():
    # Este endpoint es público, no requiere autenticación JWT.
    cursor = mysql.connection.cursor(DictCursor)
    try:
        # Obtener todas las publicaciones y todas sus URLs de imágenes asociadas
        cursor.execute("""
            SELECT
                p.id,
                p.autor_id,
                u.username AS author,
                p.titulo AS title,
                p.texto AS content,
                p.created_at,
                GROUP_CONCAT(ip.url ORDER BY ip.orden ASC) AS all_image_urls -- Obtener todas las URLs de imágenes ordenadas
            FROM publicaciones p
            JOIN users u ON p.autor_id = u.id
            LEFT JOIN imagenes_publicacion ip ON p.id = ip.publicacion_id
            GROUP BY p.id, p.autor_id, u.username, p.titulo, p.texto, p.created_at
            ORDER BY p.created_at DESC
        """)
        publicaciones = cursor.fetchall()

        for pub in publicaciones:
            # Obtener cantidad de comentarios para cada publicación
            cursor.execute("SELECT COUNT(*) AS cantidad FROM comentarios WHERE publicacion_id = %s", (pub['id'],))
            pub['cantidad_comentarios'] = cursor.fetchone()['cantidad']

            pub['created_at'] = pub['created_at'].isoformat() if pub['created_at'] else None

            # Procesar las URLs de las imágenes en Python
            all_urls_str = pub.pop('all_image_urls') # Eliminar la cadena combinada del diccionario
            if all_urls_str:
                # Filtrar valores None/vacíos que puedan resultar de GROUP_CONCAT con datos inconsistentes
                all_urls = [url for url in all_urls_str.split(',') if url]
                pub['imageUrl'] = all_urls[0] if all_urls else None # La primera URL como imagen principal
                pub['imagenes_adicionales_urls'] = all_urls[1:] if len(all_urls) > 1 else [] # El resto como adicionales
            else:
                pub['imageUrl'] = None
                pub['imagenes_adicionales_urls'] = []


        return jsonify(publicaciones), 200
    except Exception as e:
        print(f"Error en /publicaciones: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al obtener publicaciones."}), 500
    finally:
        cursor.close()

@user_bp.route('/crear-publicacion', methods=['POST'])
@jwt_required() # Requiere un access token válido
def crear_publicacion():
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
    claims = get_jwt()
    if not claims.get('verificado', False):
        return jsonify({"error": "Usuario no verificado."}), 403

    texto = request.json.get('texto')
    titulo = request.json.get('titulo')

    if not texto or not titulo:
        return jsonify({"error": "Título y texto de la publicación son requeridos."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("INSERT INTO publicaciones (autor_id, titulo, texto) VALUES (%s, %s, %s)", (current_user_id, titulo, texto))
        mysql.connection.commit()

        new_post_id = cursor.lastrowid
        return jsonify({"message": "Publicación creada exitosamente.", "publicacion_id": new_post_id}), 201
    except Exception as e:
        print(f"Error al crear publicación: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor"}), 500
    finally:
        cursor.close()

@user_bp.route('/editar-publicacion/<int:publicacion_id>', methods=['PUT'])
@jwt_required() # Requiere un access token válido
def editar_publicacion(publicacion_id):
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token

    nuevo_texto = request.json.get('texto')
    nuevo_titulo = request.json.get('titulo')

    if not nuevo_texto or not nuevo_titulo:
        return jsonify({"error": "Nuevo título y texto de publicación son requeridos."}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != current_user_id:
            return jsonify({"error": "No autorizado para editar esta publicación."}), 403

        cursor.execute("UPDATE publicaciones SET texto = %s, titulo = %s WHERE id = %s", (nuevo_texto, nuevo_titulo, publicacion_id))
        mysql.connection.commit()
        return jsonify({"message": "Publicación editada correctamente."}), 200
    except Exception as e:
        print(f"Error al editar publicación: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al editar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-publicacion/<int:publicacion_id>', methods=['DELETE'])
@jwt_required() # Requiere un access token válido
def eliminar_publicacion(publicacion_id):
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != current_user_id:
            return jsonify({"error": "No autorizado para eliminar esta publicación."}), 403

        # --- Lógica para eliminar la carpeta completa de la publicación ---
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        base_publicaciones_path = os.path.join(upload_folder, 'publicaciones')
        # La carpeta ahora se basa en el ID de la publicación
        publicacion_folder_name = f"publicacion-{publicacion_id}" 
        publicacion_folder_path = os.path.join(base_publicaciones_path, publicacion_folder_name)

        if os.path.exists(publicacion_folder_path):
            try:
                shutil.rmtree(publicacion_folder_path) # Elimina la carpeta y su contenido
                print(f"Carpeta de publicación eliminada del disco: {publicacion_folder_path}", file=sys.stderr)
            except Exception as e:
                print(f"Error al eliminar la carpeta de publicación {publicacion_folder_path}: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                # No se detiene la eliminación de la DB aunque falle la eliminación del archivo

        # Eliminar la publicación de la base de datos (esto también eliminará las entradas en imagenes_publicacion
        # y comentarios debido a ON DELETE CASCADE, si están configurados en tu SQL)
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
@jwt_required() # Requiere un access token válido
def comentar_publicacion():
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
    claims = get_jwt()
    if not claims.get('verificado', False):
        return jsonify({"error": "Usuario no verificado."}), 403

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

# Ruta para obtener comentarios de una publicación
@user_bp.route('/publicaciones/<int:publicacion_id>/comentarios', methods=['GET'])
def get_comentarios_publicacion(publicacion_id):
    # print(f"DEBUG: Solicitud recibida para /publicaciones/{publicacion_id}/comentarios", file=sys.stderr) # Eliminado debug
    try:
        conn = mysql.connection
        cursor = conn.cursor(DictCursor)

        # Verificar si la publicación existe
        cursor.execute("SELECT id FROM publicaciones WHERE id = %s", (publicacion_id,))
        publication_exists = cursor.fetchone()
        if not publication_exists:
            # print(f"DEBUG: Publicación {publicacion_id} no encontrada en la DB.", file=sys.stderr) # Eliminado debug
            return jsonify({"error": "Publicación no encontrada."}), 404

        # Si la publicación existe, proceder a obtener los comentarios
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

        # Formatear la fecha a ISO si es necesario
        for comentario in comentarios:
            if isinstance(comentario['created_at'], datetime):
                comentario['created_at'] = comentario['created_at'].isoformat()
        
        # print(f"DEBUG: Devolviendo {len(comentarios)} comentarios para publicación {publicacion_id}.", file=sys.stderr) # Eliminado debug
        return jsonify(comentarios), 200
    except Exception as e:
        print(f"Error al obtener comentarios: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Error interno del servidor al obtener comentarios."}), 500
    finally:
        cursor.close()


@user_bp.route('/editar-comentario/<int:comentario_id>', methods=['PUT'])
@jwt_required() # Requiere un access token válido
def editar_comentario(comentario_id):
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token

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
@jwt_required() # Requiere un access token válido
def eliminar_comentario(comentario_id):
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token

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
@jwt_required() # Requiere un access token válido
def upload_profile_picture():
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token

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

        # Carpeta basada en user_id para estabilidad
        base_profile_pictures_path = os.path.join(upload_folder, 'fotos_perfil')
        user_folder = os.path.join(base_profile_pictures_path, str(current_user_id))

        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        # --- CORRECCIÓN CLAVE: Generar un nombre de archivo único con timestamp ---
        # Esto asegura que cada nueva subida tenga una URL diferente, forzando al navegador a cargarla.
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f') # Añadir microsegundos para mayor unicidad
        new_filename = secure_filename(f"profile_picture_{timestamp}.{file_extension}")
        filepath = os.path.join(user_folder, new_filename)

        cursor = mysql.connection.cursor()
        try:
            # --- CORRECCIÓN CLAVE: Eliminar todas las fotos de perfil antiguas en la carpeta del usuario ---
            # Esto limpia la carpeta y asegura que solo la nueva imagen esté presente,
            # lo que es útil si las convenciones de nombres cambian o si hay archivos residuales.
            for existing_file in os.listdir(user_folder):
                # Solo eliminar archivos que sigan el patrón de nombres de fotos de perfil
                if existing_file.startswith("profile_picture_") and existing_file != new_filename:
                    existing_filepath = os.path.join(user_folder, existing_file)
                    try:
                        os.remove(existing_filepath)
                        # print(f"DEBUG: Eliminada foto de perfil antigua: {existing_filepath}", file=sys.stderr) # Eliminado debug
                    except Exception as delete_e:
                        print(f"ERROR: No se pudo eliminar la foto de perfil antigua {existing_filepath}: {delete_e}", file=sys.stderr)

            # Guardar la nueva foto de perfil
            file.save(filepath)

            # Construir la nueva URL de la imagen usando el user_id
            base_url = current_app.config.get('API_BASE_URL', request.url_root.rstrip('/'))
            image_url = f"{base_url}/uploads/fotos_perfil/{current_user_id}/{new_filename}"

            # Actualizar la URL de la foto de perfil en la base de datos
            cursor.execute("UPDATE users SET foto_perfil = %s WHERE id = %s", (image_url, current_user_id))
            mysql.connection.commit()
            return jsonify({
                'message': 'Foto de perfil actualizada exitosamente.',
                'foto_perfil_url': image_url
            }), 200
        except Exception as save_e:
            # Si falla al guardar en disco o DB, intentar limpiar el archivo si ya se había guardado
            if os.path.exists(filepath):
                os.remove(filepath)
            print(f"Error al guardar el archivo o DB para foto de perfil {current_user_id}: {save_e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return jsonify({"error": "Error interno del servidor al guardar la foto de perfil."}), 500
        finally:
            cursor.close()
    else:
        return jsonify({'error': f"Tipo de archivo no permitido o nombre de archivo inválido. Solo se permiten {', '.join(allowed_extensions)}."}), 400


@user_bp.route('/publicaciones/<int:publicacion_id>/upload_imagen', methods=['POST'])
@jwt_required() # Requiere un access token válido
def upload_publicacion_image(publicacion_id):
    current_user_id = get_jwt_identity() # Obtiene la identidad (user_id) del token
    claims = get_jwt()
    if not claims.get('verificado', False):
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor()
    try:
        # 1. Verificar si la publicación existe y pertenece al usuario actual
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        publicacion = cursor.fetchone()
        if not publicacion:
            return jsonify({"error": "Publicación no encontrada."}), 404
        if publicacion[0] != current_user_id:
            return jsonify({"error": "No tienes permiso para subir imágenes a esta publicación."}), 403

        if 'imagen_publicacion' not in request.files:
            return jsonify({'error': 'No se encontró el archivo de imagen en la solicitud. El campo esperado es "imagen_publicacion".'}), 400

        file = request.files['imagen_publicacion']

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

            # Carpeta basada en publicacion_id
            base_publicaciones_path = os.path.join(upload_folder, 'publicaciones')
            # Usamos un nombre de carpeta que incluye el ID de la publicación
            publicacion_folder_name = f"publicacion-{publicacion_id}" 
            publicacion_folder_path = os.path.join(base_publicaciones_path, publicacion_folder_name)

            if not os.path.exists(publicacion_folder_path):
                os.makedirs(publicacion_folder_path)

            # Generar un nombre de archivo único con timestamp
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f') # Añadir microsegundos para mayor unicidad
            original_filename_secure = secure_filename(file.filename.rsplit('.', 1)[0]) # Nombre original sin extensión
            new_filename = f"{original_filename_secure}_{timestamp}.{file_extension}"
            filepath = os.path.join(publicacion_folder_path, new_filename)

            try:
                file.save(filepath)

                base_url = current_app.config.get('API_BASE_URL', request.url_root.rstrip('/'))
                # Ajustar la URL para reflejar la nueva ruta de publicaciones
                image_url = f"{base_url}/uploads/publicaciones/{publicacion_folder_name}/{new_filename}"

                # Guardar la URL de la imagen en la tabla 'imagenes_publicacion'
                cursor.execute("INSERT INTO imagenes_publicacion (publicacion_id, url) VALUES (%s, %s)", (publicacion_id, image_url))
                mysql.connection.commit()

                return jsonify({
                    'message': 'Imagen de publicación subida exitosamente.',
                    'imagen_url': image_url
                }), 201
            except Exception as save_e:
                # Si falla al guardar en disco o DB, intentar limpiar el archivo si ya se había guardado
                if os.path.exists(filepath):
                    os.remove(filepath)
                print(f"Error al guardar el archivo o DB para publicación {publicacion_id}: {save_e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                return jsonify({"error": "Error interno del servidor al guardar la imagen de la publicación."}), 500
        else:
            return jsonify({'error': f"Tipo de archivo no permitido o nombre de archivo inválido. Solo se permiten {', '.join(allowed_extensions)}."}), 400
    finally:
        cursor.close()
