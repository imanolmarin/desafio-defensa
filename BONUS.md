# Bonus

## Etapa 1

### B1. Confianza cero entre servicios — `handle_comment_event`

**Qué se pedía:** una función `handle_comment_event(raw: bytes)` que reciba un evento JSON "de una cola", lo valide con un schema Pydantic estricto y rechace campos extra o tipos incorrectos, con tests.

**Qué hice:**

- `comments-service/app/events.py`
  - `CommentCreatedEvent`: hereda de `StrictModel` (`extra="forbid"`, `strict=True`). Campos: `event_type: Literal["comment.created"]`, `event_id` con patrón de UUID, `schema_version: Literal[1]` (un productor con otra versión del contrato se rechaza en vez de interpretarse "como se pueda") y `comment: CommentIn`, **el mismo schema del endpoint público**, así hay una sola definición de "comentario válido".
  - `handle_comment_event(raw)`: corta antes de parsear si no son `bytes` o superan 8 KB; decodifica UTF-8 en modo estricto; valida con `model_validate_json`. Cualquier falla levanta `InvalidEvent("invalid event")` (mensaje genérico) y se registra un `event_rejected` en el log JSON con el **tipo** de error, nunca el contenido.
- `comments-service/tests/test_events.py`: 21 casos — evento válido; campo extra arriba y anidado (`is_admin`); `schema_version` como string (strict no coerciona) y versión desconocida; tipo de evento, UUID, autor y body inválidos; caracteres de control; campo faltante; bytes que no son JSON, JSON truncado, UTF-8 inválido; evento de más de 8 KB; `str` en lugar de `bytes`.

### B2. WAF real — ModSecurity + OWASP CRS

**Qué se pedía:** reemplazar el gateway por `owasp/modsecurity-crs:nginx`, repetir los payloads de `attacks/requests.http` y anotar cuáles bloquea.

**Qué hice:** `gateway/waf.compose.yml`, un override de compose que cambia la imagen del gateway por `owasp/modsecurity-crs:nginx-alpine` (CRS 4.30.0, paranoia 1, umbral de anomalía 5, motor en modo bloqueo) apuntando a `comments-service`:

```bash
docker compose -f docker-compose.yml -f gateway/waf.compose.yml up -d
```

Para la medición lo levanté en paralelo (`:8090`) en la misma red y mandé cada payload. Resultado (`evidencia/etapa-1/bonus-waf-modsecurity-crs.png`):

| Payload | Respuesta | ¿Llega al servicio? |
|---|---|---|
| SQLi `UNION SELECT` (`/vuln/comments/search`) | 403 | No |
| XSS `<script>` en el author | 403 | No |
| Path traversal `../secret.txt` | 403 | No |
| Command injection `; echo PWNED` | 403 | No |
| SSRF a `http://127.0.0.1:8000/internal/config` | 403 | No |
| **Log injection** con `\r\n` en el JSON | 200 | **Sí** |
| **Mass assignment** `is_admin: 1` | 201 | **Sí** |
| Reto 1 `CASE WHEN (SELECT ...)` (y la variante con `/**/`) | 403 | No |
| Reto 1 `sort=-id` (sin palabras clave) | 200 | **Sí**: el punto de inyección sigue abierto |
| **Reto 2** `=HYPERLINK(...)` y `=1+1` | 201 | **Sí** |
| **Reto 3** `next=https://evil.example/login`, `next=//evil.example` | 302 | **Sí** |

Lectura: el CRS frena bien los ataques con **firma sintáctica** conocida (SQL, HTML, rutas, metacaracteres de shell, IPs internas). Lo que pasa son ataques **semánticos**: el campo extra `is_admin` es JSON válido, `\r\n` dentro de un string JSON llega escapado, una fórmula de planilla es texto común y una URL externa es un valor normal. Esos dependen de reglas de la aplicación o del contexto de salida, y solo se resuelven en el servicio. No dejé el WAF como gateway por defecto (ver `ARQUITECTURA.md`).

### B3. ReDoS

**Qué se pedía:** investigar qué es un *Regular expression Denial of Service* y revisar si alguna regex del proyecto es vulnerable.

**Qué es:** los motores de regex con *backtracking* (el `re` de Python, PCRE, el de JavaScript) prueban alternativas y, si fallan, vuelven atrás. Cuando un patrón tiene cuantificadores **anidados o solapados** sobre los mismos caracteres (el clásico `(a+)+$`, o `(a|aa)*`, o `\w+\w+$`), una entrada que *casi* matchea obliga a probar un número exponencial (o polinómico alto) de formas de repartir los caracteres. Unos pocos KB de entrada alcanzan para tener un proceso al 100 % de CPU durante minutos: un DoS con un solo request.

**Revisión de las regex del proyecto:**

| Regex | Dónde | Motor | ¿Vulnerable? | Por qué |
|---|---|---|---|---|
| `^[A-Za-z0-9_-]{1,64}\.(txt\|png\|pdf)$` (`SAFE_FILENAME`) | `validation.py` | `re` | No | Un solo cuantificador, acotado a 64, seguido de un literal `.`: no hay dos formas de repartir la entrada |
| `HOSTNAME` | `validation.py` | `re` | No | Las etiquetas están separadas por un `\.` literal obligatorio (cada repetición del grupo arranca en un punto, sin ambigüedad), los cuantificadores internos están acotados (`{0,61}`) y el lookahead `(?=.{1,253}$)` limita el largo total. Además `Query(max_length=253)` corta antes |
| `^[a-z0-9_]{3,20}$` (`USERNAME_PATTERN`) | `schemas.py` | Rust (`regex`) | No | Trivial, acotada |
| `^[^@\s]+@[^@\s]+\.[a-z]{2,}$` (email) | `schemas.py` | Rust (`regex`) | No (y en `re` sería lineal) | Hay solapamiento entre `[^@\s]+` y `\.[a-z]{2,}` (ambos aceptan letras y el primero aceptaría puntos), lo que en un motor con backtracking produce más intentos, pero como está anclado y `[a-z]{2,}` solo puede ir hasta el final, el costo crece linealmente. Y Pydantic v2 valida `pattern` con el crate `regex` de Rust, que es de **tiempo lineal garantizado** (autómata, sin backtracking). Además `max_length=254` |
| `safe_redirect_target` (reto 3) | `validation.py` | — | No | No usa regex: `urlsplit`, `unquote` y comparaciones de prefijo |
| `~^(POST\|PUT\|PATCH):(?!application/json)` | `nginx.conf` | PCRE | No | Alternancia de literales y un lookahead fijo |

**Medición** (`attacks/redos_check.py`, captura `evidencia/etapa-1/bonus-redos.png`): con entradas armadas para forzar backtracking (`a@` + `a.`×8000 + `!`, etiquetas de 61 caracteres con guiones, nombres de 10 000 caracteres), todas las regex responden en **menos de 1 ms** con `re` y el tiempo crece linealmente con el largo. Pydantic con un email de 200 000 caracteres tarda ~20 ms (dominado por el parseo, no por la regex).

**Conclusión:** ninguna regex del proyecto es vulnerable a ReDoS. Las buenas prácticas que lo explican: anclar (`^...$`), acotar cuantificadores, que las repeticiones estén separadas por literales obligatorios, limitar el largo de la entrada **antes** de aplicar la regex, y preferir motores lineales (Rust `regex`, RE2) para validar entrada no confiable.

## Etapa 2

### B4. Autorización por identidad en moderation-service

**Qué se pedía:** que moderation no se conforme con "certificado de la CA", sino que verifique que el cliente sea específicamente `comments-service` (por CN o SAN).

**Qué hice:**

- `moderation-service/app/server.py`
  - `client_identities(peercert)`: devuelve los SAN de tipo DNS del certificado del cliente y, solo si no tiene SAN, el CN (mismo criterio que usan los navegadores para servidores).
  - `is_authorized(peercert)`: la identidad tiene que estar en `ALLOWED_CLIENTS` (variable de entorno, por defecto `comments-service`).
  - `AuthorizedH11Protocol`: subclase del protocolo HTTP de uvicorn. `connection_made` se ejecuta cuando el handshake TLS ya terminó y la cadena ya fue verificada contra la CA (`CERT_REQUIRED`), así que el certificado se puede leer con `transport.get_extra_info("peercert")`. Si la identidad no está autorizada, se loguea (`mTLS: cliente no autorizado ['reporting-service']`) y se corta la conexión **antes de leer un solo byte del request**. `connection_lost` ignora esas conexiones para no ensuciar los logs.
  - Se arranca con `python -m app.server` (que llama a `uvicorn.run(..., http=AuthorizedH11Protocol, ssl_cert_reqs=CERT_REQUIRED, ...)`).
- `certs/pruebas/intruso.*`: un certificado **válido de nuestra CA**, con `clientAuth`, pero identidad `reporting-service` (procedimiento en `CERTIFICADOS.md` §5).
- Tests: `moderation-service/tests/test_moderation.py` (`test_identidad_*`: SAN correcto, CN sin SAN, y rechazo de sin certificado, otro CN, SAN distinto aunque el CN coincida, `comments-service-evil`). Prueba real: caso 3 de `attacks/mtls_tests.sh` (`evidencia/etapa-2/B1-pruebas-mtls.png`).

Por qué no un sidecar nginx: ver `ARQUITECTURA.md`, "Componentes elegidos en la etapa 2".

### B5. Rotación con vida útil corta

**Qué se pedía:** certificados de vida corta y un procedimiento documentado para renovarlos sin cortar el servicio.

**Qué hice:**

- Certificados de servicio de **30 días** (`-days 30`), CA de 2 años.
- `comments-service/app/moderation_client.py` arma el `SSLContext` **en cada request** (`_tls_context()` dentro de `_post`), así que lee el certificado y la clave del disco cada vez: rotar el cliente no requiere reiniciar nada.
- Lo probé con el stack levantado (`evidencia/etapa-2/B4-bonus-rotacion-en-caliente.png`): emití un certificado nuevo (serial `...8FB6` → `...8FB8`), lo escribí en el lugar, el contenedor vio el serial nuevo y el siguiente comentario se moderó por mTLS con el certificado nuevo, sin reiniciar ningún servicio.

**Procedimiento de renovación:**

Cliente (comments-service), sin corte:

```bash
cd certs && umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out comments-client.new.key
openssl req -new -key comments-client.new.key -subj "/O=Desafio Defensa UTN/CN=comments-service" -out c.csr
openssl x509 -req -in c.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl -days 30 -sha256 -extfile client.ext -out comments-client.new.crt
openssl verify -CAfile ca.crt comments-client.new.crt                 # validar ANTES de instalar
# compose monta archivos sueltos: hay que escribir EN EL LUGAR (mismo inode); un mv no se vería dentro del contenedor
cat comments-client.new.key > comments-client.key && cat comments-client.new.crt > comments-client.crt
rm -f c.csr comments-client.new.*
```

Entre la escritura de la clave y la del certificado hay un instante en que no coinciden: una moderación que caiga justo ahí falla y el comentario queda `pending` (falla cerrado, no se publica nada sin moderar). Para eliminar ese instante, la mejora es montar un **directorio** y cambiar un symlink `current → v2/` de forma atómica.

Servidor (moderation-service): uvicorn carga el certificado al arrancar, así que la renovación es emitir el par nuevo igual que arriba (con `server.ext`) y `docker compose restart moderation-service` (un par de segundos). Durante ese lapso comments-service falla cerrado. Para cero corte habría que tener dos réplicas detrás de un balanceador y reiniciarlas de a una.

CA: al rotarla, conviene un período de transición con **ambas CAs** en `ca.crt` (bundle) en clientes y servidores, reemitir todos los certificados con la CA nueva y recién después sacar la vieja del bundle.

Automatizar: un cron/systemd timer que corra este procedimiento cuando falten menos de 10 días (`openssl x509 -checkend 864000`), o directamente una CA con ACME (step-ca) y certificados de horas.
