#!/bin/bash
set -xe

echo "Configurando usuario '${MYSQL_USER}' con mysql_native_password..."

MYSQL_CONNECT_ARGS="-u root"
if [ -n "$MYSQL_ROOT_PASSWORD" ]; then
    MYSQL_CONNECT_ARGS="${MYSQL_CONNECT_ARGS} -p$MYSQL_ROOT_PASSWORD"
fi

mysql ${MYSQL_CONNECT_ARGS} <<EOSQL
CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'%' IDENTIFIED WITH mysql_native_password BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON ${MYSQL_DATABASE}.* TO '${MYSQL_USER}'@'%';
FLUSH PRIVILEGES;
EOSQL

echo "Usuario '${MYSQL_USER}' configurado."