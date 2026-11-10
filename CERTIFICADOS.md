# Certificados — PKI propia para el mTLS

La PKI se arma a mano con `openssl` (probado con OpenSSL 3.x) dentro de `certs/`. Esa carpeta está en `.gitignore` salvo `.gitkeep`: **en el repo queda este procedimiento, nunca las claves ni los certificados.** Hay que generarla antes del primer `docker compose up`.

```
certs/
├── ca.key / ca.crt                         CA del proyecto ("Desafio Defensa Root CA")
├── moderation.key / moderation.crt         servidor: moderation-service  (serverAuth, SAN DNS:moderation-service)
├── comments-client.key / .crt              cliente: comments-service     (clientAuth, SAN DNS:comments-service)
├── server.ext / client.ext                 extensiones X.509 de cada perfil
└── pruebas/                                material SOLO para las pruebas negativas
    ├── otra-ca.*                           una CA que nadie configuró como confiable
    ├── cliente-otra-ca.*                   cliente "comments-service" firmado por otra-ca
    ├── server-otra-ca.*                    servidor "moderation-service" firmado por otra-ca
    └── intruso.*                           cliente VÁLIDO de nuestra CA, pero identidad reporting-service
```

Decisiones generales:

- **Curva elíptica P-256** (`prime256v1`) en vez de RSA: claves de 256 bits con seguridad equivalente a RSA-3072, handshakes más rápidos y soporte universal.
- **Vida útil corta**: CA 2 años, certificados de servicio **30 días** (ver rotación al final).
- **`umask 077`** antes de generar: las claves nacen con permisos `0600`. Los contenedores corren con UID 1000 (el mismo dueño de los archivos), así que pueden leerlas sin abrirlas a otros usuarios.
- Cada contenedor monta **solo sus archivos**, de solo lectura. `ca.key` no entra a ningún contenedor.

```bash
cd certs
umask 077
```

## 1. CA del proyecto

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key

openssl req -x509 -new -key ca.key -sha256 -days 730 \
  -subj "/O=Desafio Defensa UTN/CN=Desafio Defensa Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca.crt
```

| Opción | Para qué |
|---|---|
| `genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` | Genera la clave privada de la CA (curva P-256). Separar la generación de la clave del certificado deja claro qué archivo es el secreto |
| `req -x509 -new` | En lugar de una solicitud (CSR), emite directamente un certificado **autofirmado**: es la raíz de confianza |
| `-sha256` | Algoritmo de hash de la firma |
| `-days 730` | Validez de la CA |
| `-subj` | Nombre distinguido sin preguntas interactivas |
| `basicConstraints=critical,CA:TRUE,pathlen:0` | Es una CA, pero **no puede crear CAs intermedias** (`pathlen:0`): solo firma certificados finales. `critical` obliga a cualquier verificador a respetarlo |
| `keyUsage=critical,keyCertSign,cRLSign` | La clave solo sirve para firmar certificados y listas de revocación, no para hacer TLS |
| `subjectKeyIdentifier=hash` | Identificador de la clave; los certificados hijos lo referencian con `authorityKeyIdentifier` |

## 2. Certificado de servidor — moderation-service

```bash
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:moderation-service
authorityKeyIdentifier=keyid
subjectKeyIdentifier=hash
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out moderation.key
openssl req -new -key moderation.key -subj "/O=Desafio Defensa UTN/CN=moderation-service" -out moderation.csr
openssl x509 -req -in moderation.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 30 -sha256 -extfile server.ext -out moderation.crt
```

| Opción | Para qué |
|---|---|
| `req -new -key ... -out x.csr` | Crea la **CSR**: la clave pública + el nombre, firmados con la clave privada del servicio. En un escenario real el servicio genera su clave y solo manda la CSR a la CA: la clave privada no viaja |
| `x509 -req -in x.csr` | La CA firma la CSR y emite el certificado |
| `-CA ca.crt -CAkey ca.key` | Certificado y clave de la CA emisora |
| `-CAcreateserial` | Crea `ca.srl` con un número de serie aleatorio y lo incrementa en cada emisión (los seriales sirven para revocar) |
| `-days 30` | Vida útil corta |
| `-extfile server.ext` | Las extensiones de la CSR no se copian solas: se aplican desde este archivo |
| `subjectAltName=DNS:moderation-service` | **El nombre que verifica el cliente.** Es el hostname del servicio en la red de Docker; el cliente compara la URL `https://moderation-service:8443` contra el SAN (el CN se ignora para esto desde hace años) |
| `extendedKeyUsage=serverAuth` | Solo vale para autenticar un **servidor** TLS: no se puede usar como certificado de cliente |
| `basicConstraints=critical,CA:FALSE` | No puede firmar otros certificados |
| `keyUsage=critical,digitalSignature` | La clave firma el handshake (ECDHE + ECDSA) |
| `authorityKeyIdentifier=keyid` | Enlaza con la CA emisora (facilita armar la cadena) |

No agregué `DNS:localhost`: moderation-service no se expone fuera de Docker, así que no hay un caso legítimo para ese nombre.

## 3. Certificado de cliente — comments-service

```bash
cat > client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:comments-service
authorityKeyIdentifier=keyid
subjectKeyIdentifier=hash
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out comments-client.key
openssl req -new -key comments-client.key -subj "/O=Desafio Defensa UTN/CN=comments-service" -out comments-client.csr
openssl x509 -req -in comments-client.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl \
  -days 30 -sha256 -extfile client.ext -out comments-client.crt

chmod 644 *.crt          # los certificados son públicos; las claves quedan 0600
rm -f *.csr
```

| Diferencia con el de servidor | Por qué |
|---|---|
| `extendedKeyUsage=clientAuth` | Solo autentica a un **cliente**. Un certificado de servidor robado no sirve para hablarle a moderation como cliente, y viceversa |
| `subjectAltName=DNS:comments-service` | La **identidad** del cliente. moderation-service la usa para autorizar (bonus): no alcanza con que el certificado sea de la CA, tiene que ser *este* servicio |
| `-CAserial ca.srl` | Reusa el archivo de seriales creado en el paso 2 |

## 4. Verificar

```bash
openssl verify -CAfile ca.crt moderation.crt comments-client.crt
openssl x509 -in moderation.crt -noout -subject -issuer -enddate -ext subjectAltName,extendedKeyUsage,basicConstraints
openssl x509 -in comments-client.crt -noout -subject -issuer -enddate -ext subjectAltName,extendedKeyUsage
git check-ignore -v ca.key moderation.key comments-client.key     # las claves NO entran al repo
```

Captura: `evidencia/etapa-2/B0-pki-certificados.png`.

## 5. Material para pruebas negativas (`certs/pruebas/`)

```bash
mkdir -p pruebas && cd pruebas

# Otra CA, que nadie configuró como confiable
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out otra-ca.key
openssl req -x509 -new -key otra-ca.key -sha256 -days 30 -subj "/CN=Otra CA (no confiable)" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -out otra-ca.crt

# Cliente que DICE ser comments-service, firmado por otra-ca
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out cliente-otra-ca.key
openssl req -new -key cliente-otra-ca.key -subj "/CN=comments-service" -out c.csr
openssl x509 -req -in c.csr -CA otra-ca.crt -CAkey otra-ca.key -CAcreateserial -days 30 -sha256 \
  -extfile ../client.ext -out cliente-otra-ca.crt

# Servidor que DICE ser moderation-service, firmado por otra-ca
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:moderation-service,DNS:fake-moderation\n' > fake-server.ext
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server-otra-ca.key
openssl req -new -key server-otra-ca.key -subj "/CN=moderation-service" -out s.csr
openssl x509 -req -in s.csr -CA otra-ca.crt -CAkey otra-ca.key -CAcreateserial -days 30 -sha256 \
  -extfile fake-server.ext -out server-otra-ca.crt

# Bonus identidad: cliente legítimo de NUESTRA CA, pero con otra identidad
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:reporting-service\n' > intruso.ext
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out intruso.key
openssl req -new -key intruso.key -subj "/CN=reporting-service" -out i.csr
openssl x509 -req -in i.csr -CA ../ca.crt -CAkey ../ca.key -CAserial ../ca.srl -days 30 -sha256 \
  -extfile intruso.ext -out intruso.crt

rm -f *.csr && chmod 644 *.crt && cd ..
```

El servidor falso incluye `DNS:fake-moderation` a propósito: en la prueba 6 el nombre **coincide**, así que si comments-service rechaza la conexión es solo por la cadena de confianza (CA desconocida), no por el hostname.

## 6. Cómo se usa en cada servicio

**moderation-service** (`moderation-service/app/server.py`, arrancado con `python -m app.server`) llama a `uvicorn.run` con:

| Parámetro | Equivale a | Qué hace |
|---|---|---|
| `ssl_certfile` / `ssl_keyfile` | `--ssl-certfile` / `--ssl-keyfile` | Certificado y clave de servidor |
| `ssl_ca_certs="/certs/ca.crt"` | `--ssl-ca-certs` | La **única** CA contra la que se validan los certificados de cliente |
| `ssl_cert_reqs=ssl.CERT_REQUIRED` | `--ssl-cert-reqs 2` | Sin certificado de cliente válido no hay handshake. (`0` = `CERT_NONE`, `1` = `CERT_OPTIONAL`, `2` = `CERT_REQUIRED`) |
| `http=AuthorizedH11Protocol` | — (no existe en la CLI) | Bonus: después del handshake lee el certificado del cliente y corta la conexión si su SAN/CN no está en `ALLOWED_CLIENTS` |

**comments-service** (`comments-service/app/moderation_client.py`):

```python
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=MODERATION_CA)  # solo nuestra CA
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(certfile=MODERATION_CERT, keyfile=MODERATION_KEY)          # se presenta como cliente
httpx.Client(verify=context, timeout=3.0)
```

`create_default_context` deja `verify_mode = CERT_REQUIRED` y `check_hostname = True`; con `cafile` las CAs públicas del sistema **no** se cargan, así que ni siquiera un certificado legítimo de Let's Encrypt para `moderation-service` sería aceptado. No hay `verify=False` en ningún lado.

## 7. Pruebas de handshake

Script: `attacks/mtls_tests.sh` (con el compose levantado). moderation-service no está publicado en el host, así que las pruebas corren desde contenedores en la misma red. Resultado en `evidencia/etapa-2/B1-pruebas-mtls.png`:

| # | Caso | Resultado obtenido |
|---|---|---|
| 1 | Sin certificado de cliente | `curl: (56) Connection reset by peer`: el servidor corta el handshake |
| 2 | Cliente firmado por **otra CA** (con CN `comments-service`) | `curl: (56)`: el nombre no importa si la firma no es de nuestra CA |
| 3 | *(bonus)* Cliente de **nuestra CA** pero identidad `reporting-service` | `curl: (56)`; en el log: `mTLS: cliente no autorizado ['reporting-service']` |
| 4 | Certificado válido de comments-service (control) | `200 {"status":"approved","reason":"ok"}` |
| 5 | Certificado válido + `is_admin` extra / `comment_id` como string / body de 2001 caracteres | `422` en los tres |
| 6 | comments-service (su cliente real) contra un servidor con certificado de **otra CA** | `ConnectError - [SSL: CERTIFICATE_VERIFY_FAILED] ... unable to get local issuer certificate` |
| 7 | Acceso desde el host / por el gateway | `Could not connect` en `localhost:8443`; `404` en `localhost:8080/moderate` |

Los casos de respuesta inválida, moderation caído y timeout están en `comments-service/tests/test_moderation.py`, y el caso "moderation caído" además se probó de punta a punta con `docker compose stop moderation-service` (`evidencia/etapa-2/B2-flujo-completo-y-falla-cerrado.png`).

## 8. Rotación (bonus)

Ver `BONUS.md`. Resumen: certificados de 30 días; el **cliente** se rota en caliente (comments-service arma el contexto TLS en cada request); el **servidor** con un reinicio de segundos de moderation-service, durante el cual comments-service falla cerrado (los comentarios quedan pendientes, no se publican sin moderar).
