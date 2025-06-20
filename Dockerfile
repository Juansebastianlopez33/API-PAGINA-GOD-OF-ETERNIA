FROM python:3.11-slim-buster 
# O python:3.11-slim-buster

WORKDIR /app

# Instalar dependencias necesarias para compilar mysqlclient
# build-essential: para compiladores como gcc
# default-libmysqlclient-dev: Librerías de desarrollo del cliente MySQL
# pkg-config: Herramienta para encontrar las librerías

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/* # Limpiar caché de apt para reducir tamaño de imagen

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .  /app/

EXPOSE 5000

CMD ["python", "app.py"]