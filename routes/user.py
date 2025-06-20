from flask import Blueprint, request, jsonify
from extensions import mysql
from MySQLdb.cursors import DictCursor # Importa DictCursor para fetchall en publicaciones
import sys # Para depuración
import traceback # Para depuración

user_bp = Blueprint('user', __name__)

# Modificación clave aquí
def get_user_by_token(auth_header):
    """
    Extrae el token del encabezado de autorización y busca el usuario.
    Espera un string como "Bearer <token_real>".
    """
    token = None
    if auth_header and "Bearer " in auth_header:
        token = auth_header.split(" ")[1] # Extrae el token real
    else:
        # Si no tiene "Bearer ", podríamos asumir que es el token directamente
        # o devolver None si el formato es estricto. Por seguridad, es mejor esperar "Bearer ".
        # Por ahora, si no tiene Bearer, asumimos que no hay token válido en el formato esperado.
        print("Advertencia: Encabezado de autorización sin 'Bearer '", auth_header)
        return None

    if not token:
        print("Advertencia: Token real no extraído del encabezado de autorización.")
        return None

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT id, username, email, DescripUsuario, verificado FROM users WHERE token = %s", (token,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"Error en get_user_by_token: {e}")
        traceback.print_exc(file=sys.stdout) # Imprime la pila de llamadas para depuración
        return None
    finally:
        cursor.close()

@user_bp.route('/perfil', methods=['GET', 'PUT'])
def perfil():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Token requerido."}), 401

    user = get_user_by_token(auth_header)
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id, username, email, descripcion, verificado = user
    if not verificado:
        return jsonify({"error": "Usuario no verificado."}), 403

    if request.method == 'GET':
        cursor = mysql.connection.cursor()
        try:
            cursor.execute("SELECT dificultad_id, puntaje_actual FROM partidas WHERE user_id = %s", (user_id,))
            puntajes = cursor.fetchall()

            return jsonify({
                "username": username,
                "email": email,
                "descripcion": descripcion,
                "puntajes": [{"dificultad": p[0], "puntaje": p[1]} for p in puntajes]
            }), 200
        except Exception as e:
            print(f"ERROR en GET /perfil: {e}")
            traceback.print_exc(file=sys.stdout)
            return jsonify({"error": "Error interno del servidor al obtener perfil."}), 500
        finally:
            cursor.close()

    elif request.method == 'PUT':
        data = request.get_json()
        nueva_descripcion = data.get("descripcion")
        nuevo_username = data.get("username")

        if nueva_descripcion is None or nuevo_username is None:
            return jsonify({"error": "Faltan campos requeridos: descripcion y username."}), 400

        cursor = mysql.connection.cursor()
        try:
            # Verificar si el nuevo username ya existe en otro usuario
            cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (nuevo_username, user_id))
            if cursor.fetchone():
                return jsonify({"error": "El nombre de usuario ya está en uso."}), 409

            cursor.execute("UPDATE users SET DescripUsuario = %s, username = %s WHERE id = %s", (nueva_descripcion, nuevo_username, user_id))
            mysql.connection.commit()
            return jsonify({"mensaje": "Perfil actualizado correctamente."}), 200
        except Exception as e:
            print(f"ERROR en PUT /perfil: {e}")
            traceback.print_exc(file=sys.stdout)
            return jsonify({"error": "Error al actualizar el perfil."}), 500
        finally:
            cursor.close()


@user_bp.route('/publicaciones', methods=['GET']) # Cambia a GET para obtener publicaciones
def publicaciones():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Token requerido."}), 401

    user = get_user_by_token(auth_header) # Pasa el encabezado completo
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id, username, email, DescripUsuario, verificado = user
    if not verificado:
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor(DictCursor)
    try:
        # Lista publicaciones del usuario (sin texto), con cantidad de comentarios
        cursor.execute("""
            SELECT p.id AS publicacion_id, u.username AS autor, p.created_at, p.texto # Añadir p.texto
            FROM publicaciones p
            JOIN users u ON p.autor_id = u.id
            WHERE p.autor_id = %s
            ORDER BY p.created_at DESC
        """, (user_id,))
        publicaciones = cursor.fetchall()

        for pub in publicaciones:
            cursor.execute("SELECT COUNT(*) AS cantidad FROM comentarios WHERE publicacion_id = %s", (pub['publicacion_id'],))
            pub['cantidad_comentarios'] = cursor.fetchone()['cantidad']
            pub['created_at'] = pub['created_at'].isoformat() if pub['created_at'] else None

        # Lista comentarios hechos por el usuario, con texto del comentario, autor y nombre (texto) de la publicación donde comentó
        cursor.execute("""
            SELECT c.id AS comentario_id, c.texto AS comentario_texto, u.username AS autor_comentario, c.created_at, p.texto AS publicacion_texto
            FROM comentarios c
            JOIN publicaciones p ON c.publicacion_id = p.id
            JOIN users u ON c.autor_id = u.id
            WHERE c.autor_id = %s
            ORDER BY c.created_at DESC
        """, (user_id,))
        comentarios = cursor.fetchall()

        for c in comentarios:
            c['created_at'] = c['created_at'].isoformat() if c['created_at'] else None

        return jsonify({
            "publicaciones": publicaciones,
            "comentarios": comentarios
        }), 200
    except Exception as e:
        print(f"Error en /publicaciones: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al obtener publicaciones/comentarios."}), 500
    finally:
        cursor.close()

# Las rutas para crear, editar y eliminar publicaciones/comentarios necesitan el mismo ajuste:
# Cambiar token = request.headers.get('Authorization') por auth_header = request.headers.get('Authorization')
# y luego user = get_user_by_token(auth_header)

@user_bp.route('/crear-publicacion', methods=['POST'])
def crear_publicacion():
    auth_header = request.headers.get('Authorization') # Obtener encabezado completo
    texto = request.json.get('texto')
    if not auth_header or not texto: # Verificar auth_header
        return jsonify({"error": "Token y texto son requeridos."}), 400

    user = get_user_by_token(auth_header) # Pasar el encabezado completo
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id, _, _, _, verificado = user
    if not verificado:
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("INSERT INTO publicaciones (autor_id, texto) VALUES (%s, %s)", (user_id, texto))
        mysql.connection.commit()
        return jsonify({"message": "Publicación creada exitosamente."}), 201
    except Exception as e:
        print(f"Error al crear publicación: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al crear publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/editar-publicacion/<int:publicacion_id>', methods=['PUT'])
def editar_publicacion(publicacion_id):
    auth_header = request.headers.get('Authorization') # Obtener encabezado completo
    nuevo_texto = request.json.get('texto')
    if not auth_header or not nuevo_texto: # Verificar auth_header
        return jsonify({"error": "Token y nuevo texto requeridos."}), 400

    user = get_user_by_token(auth_header) # Pasar el encabezado completo
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id = user[0]

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != user_id:
            return jsonify({"error": "No autorizado para editar esta publicación."}), 403

        cursor.execute("UPDATE publicaciones SET texto = %s WHERE id = %s", (nuevo_texto, publicacion_id))
        mysql.connection.commit()
        return jsonify({"message": "Publicación editada correctamente."}), 200
    except Exception as e:
        print(f"Error al editar publicación: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al editar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-publicacion/<int:publicacion_id>', methods=['DELETE'])
def eliminar_publicacion(publicacion_id):
    auth_header = request.headers.get('Authorization') # Obtener encabezado completo
    if not auth_header: # Verificar auth_header
        return jsonify({"error": "Token requerido."}), 400

    user = get_user_by_token(auth_header) # Pasar el encabezado completo
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id = user[0]

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM publicaciones WHERE id = %s", (publicacion_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != user_id:
            return jsonify({"error": "No autorizado para eliminar esta publicación."}), 403

        cursor.execute("DELETE FROM publicaciones WHERE id = %s", (publicacion_id,))
        mysql.connection.commit()
        return jsonify({"message": "Publicación eliminada correctamente."}), 200
    except Exception as e:
        print(f"Error al eliminar publicación: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al eliminar publicación."}), 500
    finally:
        cursor.close()

@user_bp.route('/comentar-publicacion', methods=['POST'])
def comentar_publicacion():
    auth_header = request.headers.get('Authorization')  # Obtener encabezado completo
    publicacion_id = request.json.get('publicacion_id')
    comentario = request.json.get('comentario')

    if not auth_header or publicacion_id is None or not comentario:
        return jsonify({"error": "Token, ID de publicación y comentario son requeridos."}), 400

    user = get_user_by_token(auth_header)
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id, _, _, _, verificado = user
    if not verificado:
        return jsonify({"error": "Usuario no verificado."}), 403

    cursor = mysql.connection.cursor()
    try:
        # Validar que la publicación exista
        cursor.execute("SELECT id FROM publicaciones WHERE id = %s", (publicacion_id,))
        if not cursor.fetchone():
            return jsonify({"error": "La publicación no existe."}), 404

        # Insertar comentario
        cursor.execute(
            "INSERT INTO comentarios (publicacion_id, autor_id, texto) VALUES (%s, %s, %s)",
            (publicacion_id, user_id, comentario)
        )
        mysql.connection.commit()
        return jsonify({"message": "Comentario publicado exitosamente."}), 201
    except Exception as e:
        print(f"Error al comentar publicación: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al comentar."}), 500
    finally:
        cursor.close()


@user_bp.route('/editar-comentario/<int:comentario_id>', methods=['PUT'])
def editar_comentario(comentario_id):
    auth_header = request.headers.get('Authorization') # Obtener encabezado completo
    nuevo_texto = request.json.get('comentario')
    if not auth_header or not nuevo_texto: # Verificar auth_header
        return jsonify({"error": "Token y nuevo texto del comentario requeridos."}), 400

    user = get_user_by_token(auth_header) # Pasar el encabezado completo
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id = user[0]

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM comentarios WHERE id = %s", (comentario_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != user_id:
            return jsonify({"error": "No autorizado para editar este comentario."}), 403

        cursor.execute("UPDATE comentarios SET texto = %s WHERE id = %s", (nuevo_texto, comentario_id))
        mysql.connection.commit()
        return jsonify({"message": "Comentario editado correctamente."}), 200
    except Exception as e:
        print(f"Error al editar comentario: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al editar comentario."}), 500
    finally:
        cursor.close()

@user_bp.route('/eliminar-comentario/<int:comentario_id>', methods=['DELETE'])
def eliminar_comentario(comentario_id):
    auth_header = request.headers.get('Authorization') # Obtener encabezado completo
    if not auth_header: # Verificar auth_header
        return jsonify({"error": "Token requerido."}), 400

    user = get_user_by_token(auth_header) # Pasar el encabezado completo
    if not user:
        return jsonify({"error": "Token inválido."}), 403

    user_id = user[0]

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT autor_id FROM comentarios WHERE id = %s", (comentario_id,))
        resultado = cursor.fetchone()
        if not resultado or resultado[0] != user_id:
            return jsonify({"error": "No autorizado para eliminar este comentario."}), 403

        cursor.execute("DELETE FROM comentarios WHERE id = %s", (comentario_id,))
        mysql.connection.commit()
        return jsonify({"message": "Comentario eliminado correctamente."}), 200
    except Exception as e:
        print(f"Error al eliminar comentario: {e}")
        traceback.print_exc(file=sys.stdout)
        return jsonify({"error": "Error interno del servidor al eliminar comentario."}), 500
    finally:
        cursor.close()