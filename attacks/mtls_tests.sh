#!/usr/bin/env bash
# Pruebas de mTLS contra moderation-service (etapa 2, parte B).
# Requiere: docker compose up, y la PKI generada en certs/ (ver CERTIFICADOS.md).
# moderation-service no está publicado en el host: se prueba desde contenedores
# conectados a la misma red de Docker.
set -u
cd "$(dirname "$0")/.."
NET="${NET:-desafio-defensa_default}"
URL=https://moderation-service:8443/moderate
OK='{"comment_id":1,"author":"alice","body":"hola"}'

curlm() {  # curl dentro de la red interna, con certs/ montado en /certs (uid 1000 = dueño de las claves)
  docker run --rm --user 1000 --network "$NET" -v "$PWD/certs:/certs:ro" curlimages/curl:8.11.1 \
    -sS --max-time 5 -H 'Content-Type: application/json' "$@"
}
caso() { printf '\n=== %s\n' "$1"; }

caso "1. Sin certificado de cliente -> el handshake falla"
curlm --cacert /certs/ca.crt -d "$OK" "$URL"; echo "exit=$?"

caso "2. Certificado de cliente firmado por OTRA CA (mismo CN comments-service) -> el handshake falla"
curlm --cacert /certs/ca.crt --cert /certs/pruebas/cliente-otra-ca.crt --key /certs/pruebas/cliente-otra-ca.key -d "$OK" "$URL"; echo "exit=$?"

caso "3. (bonus) Certificado VALIDO de la CA pero otra identidad (reporting-service) -> conexion cortada"
curlm --cacert /certs/ca.crt --cert /certs/pruebas/intruso.crt --key /certs/pruebas/intruso.key -d "$OK" "$URL"; echo "exit=$?"

caso "4. Control: certificado de comments-service -> 200"
curlm --cacert /certs/ca.crt --cert /certs/comments-client.crt --key /certs/comments-client.key -d "$OK" -w '\nHTTP %{http_code}\n' "$URL"

caso "5. Certificado valido + body con campo extra / tipo incorrecto / body largo -> 422"
for body in '{"comment_id":1,"author":"alice","body":"x","is_admin":true}' \
            '{"comment_id":"1","author":"alice","body":"x"}' \
            "{\"comment_id\":1,\"author\":\"alice\",\"body\":\"$(head -c 2001 /dev/zero | tr '\0' a)\"}"; do
  curlm --cacert /certs/ca.crt --cert /certs/comments-client.crt --key /certs/comments-client.key \
    -o /dev/null -w "HTTP %{http_code}  <- ${body:0:70}\n" -d "$body" "$URL"
done

caso "6. comments-service contra un servidor cuyo certificado NO es de la CA -> rechaza la conexion"
docker run -d --rm --name fake-moderation --network "$NET" --user 1000 -v "$PWD/certs/pruebas:/p:ro" \
  alpine/openssl s_server -accept 9443 -cert /p/server-otra-ca.crt -key /p/server-otra-ca.key -www >/dev/null
sleep 2
docker compose exec -T -e MODERATION_URL=https://fake-moderation:9443 comments-service python -c '
from app import moderation_client as m
try:
    m.moderate(1, "alice", "hola")
    print("CONECTO (mal)")
except m.ModerationUnavailable as e:
    print("RECHAZADO:", type(e.__cause__).__name__, "-", e.__cause__)'
docker stop fake-moderation >/dev/null

caso "7. moderation-service no esta expuesto: ni en el host ni por el gateway"
curl -sS --max-time 3 https://localhost:8443/moderate -k; echo "exit=$?"
curl -s -o /dev/null -w "gateway /moderate -> HTTP %{http_code}\n" -X POST localhost:8080/moderate -H 'Content-Type: application/json' -d "$OK"
