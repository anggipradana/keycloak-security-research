#!/bin/bash
export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=Admin1234!
export KC_HOME=/home/anggi/keycloak-research/keycloak-26.5.4

cd $KC_HOME
./bin/kc.sh start-dev \
  --http-port=8080 \
  --hostname=46.101.162.187 \
  --hostname-strict=false \
  --log-level=INFO \
  > /home/anggi/keycloak-research/keycloak.log 2>&1 &

echo $! > /home/anggi/keycloak-research/keycloak.pid
echo "Keycloak started with PID $(cat /home/anggi/keycloak-research/keycloak.pid)"
