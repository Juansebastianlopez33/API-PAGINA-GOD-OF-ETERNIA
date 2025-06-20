-- Crear la base de datos
CREATE DATABASE IF NOT EXISTS flask_api
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE flask_api;

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(64) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    DescripUsuario VARCHAR(150),
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verificado BOOLEAN DEFAULT FALSE,
    verificacion_codigo VARCHAR(6),
    verificacion_expira DATETIME DEFAULT NULL,
    foto_perfil VARCHAR(255),
    -- ¡NUEVAS COLUMNAS PARA RECUPERACIÓN DE CONTRASEÑA!
    reset_token VARCHAR(255) NULL,
    reset_token_expira DATETIME NULL
);

-- Tabla de dificultades
CREATE TABLE IF NOT EXISTS dificultades (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(15) NOT NULL UNIQUE
);

-- Insertar dificultades
INSERT IGNORE INTO dificultades (id, nombre) VALUES
(1, 'Fácil'),
(2, 'Intermedio'),
(3, 'Difícil'),
(4, 'Experto');

-- Tabla de partidas
CREATE TABLE IF NOT EXISTS partidas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    dificultad_id INT NOT NULL,
    puntaje_actual INT DEFAULT 0,
    pergaminos_comunes INT DEFAULT 0,
    pergaminos_raros INT DEFAULT 0,
    pergaminos_epicos INT DEFAULT 0,
    pergaminos_legendarios INT DEFAULT 0,
    mobs_derrotados INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, dificultad_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (dificultad_id) REFERENCES dificultades(id) ON DELETE CASCADE
);

-- Tabla de publicaciones
CREATE TABLE IF NOT EXISTS publicaciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    autor_id INT NOT NULL,
    texto TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (autor_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabla de imágenes por publicación (1-N)
CREATE TABLE IF NOT EXISTS imagenes_publicacion (
    id INT AUTO_INCREMENT PRIMARY KEY,
    publicacion_id INT NOT NULL,
    url VARCHAR(255) NOT NULL,
    orden INT DEFAULT 1,
    FOREIGN KEY (publicacion_id) REFERENCES publicaciones(id) ON DELETE CASCADE
);

-- ✅ Tabla de comentarios por publicación
CREATE TABLE IF NOT EXISTS comentarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    publicacion_id INT NOT NULL,
    autor_id INT NOT NULL,
    texto TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (publicacion_id) REFERENCES publicaciones(id) ON DELETE CASCADE,
    FOREIGN KEY (autor_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabla de leaderboard
CREATE TABLE IF NOT EXISTS leaderboard (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    dificultad_id INT NOT NULL,
    puntaje INT NOT NULL DEFAULT 0,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, dificultad_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (dificultad_id) REFERENCES dificultades(id) ON DELETE CASCADE
);


DELIMITER $$

CREATE TRIGGER verificar_publicacion_existente
BEFORE INSERT ON comentarios
FOR EACH ROW
BEGIN
    DECLARE existe INT;

    SELECT COUNT(*) INTO existe
    FROM publicaciones
    WHERE id = NEW.publicacion_id;

    IF existe = 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'No se puede crear el comentario: la publicación no existe.';
    END IF;
END$$

DELIMITER ;