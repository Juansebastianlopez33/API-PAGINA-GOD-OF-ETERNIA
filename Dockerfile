# Usa una imagen base de Python más reciente con Debian Bookworm
# 'slim' es una versión más pequeña de la imagen que incluye solo lo esencial.
# 'bookworm' es la versión actual estable de Debian.
FROM python:3.11-slim-bookworm

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Instala dependencias del sistema necesarias para MySQLdb
# build-essential: Para compilar paquetes C/C++
# default-libmysqlclient-dev: Librerías de desarrollo para MySQL (necesarias para MySQL-python o mysqlclient)
# pkg-config: Herramienta para obtener información sobre librerías
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    default-libmysqlclient-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/* # Limpiar caché de apt para reducir tamaño de imagen

# Copia el archivo de requisitos e instala las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de la aplicación
COPY . .

# Expone el puerto en el que la aplicación Flask escuchará
EXPOSE 5000

# Comando para ejecutar la aplicación cuando el contenedor se inicie
CMD ["python", "app.py"]
