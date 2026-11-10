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
