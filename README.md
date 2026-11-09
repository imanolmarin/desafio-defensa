# Manejo de entradas y mitigación defensiva en un microservicio

Un microservicio de comentarios detrás de un API gateway. Cada vulnerabilidad tiene una
ruta vulnerable a propósito (`/vuln/...`) y una mitigada (`/secure/...`), para comparar
el mismo payload lado a lado.

> Las rutas `/vuln` son explotables a propósito. Correlas solo en local (el compose expone en `127.0.0.1`).

**Marco teórico interactivo:** [`docs/marco-teorico.html`](docs/marco-teorico.html) (abrir en el navegador). Incluye conceptos, capas de la arquitectura, laboratorios de validación y encoders, catálogo de ataques y autoevaluación.

**Desafío:** [`DESAFIO.md`](DESAFIO.md). Etapa 1: tres vulnerabilidades nuevas para explotar, corregir y testear. Etapa 2: front (en `front/`, servido en `/app/`) y un segundo microservicio con mTLS.

## Regla central

**Validar en la entrada, codificar en la salida según el contexto, parametrizar en el sink** (consulta SQL, comando, path).
Sanitizar solo cuando hay que aceptar contenido enriquecido (por ejemplo HTML), y siempre con una allowlist.

| Técnica | Qué hace | Cuándo |
|---|---|---|
| Validación | Acepta o rechaza según una allowlist (tipo, longitud, rango, formato, enum). Nunca "arregla" la entrada. | En cada frontera de confianza |
| Canonicalización | Normaliza (Unicode NFKC, decodificar una sola vez) **antes** de validar. | Antes de validar |
| Filtrado | Bloqueo grueso (tamaño, rate limit, content type, reglas de WAF). | En el borde |
| Saneamiento | Elimina lo no permitido del contenido enriquecido (nh3, DOMPurify). | Solo texto enriquecido |
| Output encoding | Codifica según el contexto de destino: HTML, atributo, JS, URL, log. | Donde el dato se renderiza o se escribe |
| Parametrización | Mantiene los datos fuera del canal de código: parámetros SQL, listas de argv. | Base de datos, SO, intérpretes |

## Dónde va en la arquitectura

```
cliente ──► API gateway / WAF ──► microservicio ─────────────────────────────────► sinks
            tamaño, rate limit,   controller/DTO: canonicalizar + schema              SQL (parámetros)
            content type,         dominio: reglas de negocio                          shell (argv, sin shell)
            headers de seguridad, salida: encoding contextual, sanitizer, CSP         filesystem (path confinado)
            bloquear /internal                                                        HTTP saliente (allowlist anti-SSRF)
                                                                                      logs (JSON, CR/LF escapados)
otros servicios / colas ──► misma validación por schema (confianza cero entre servicios)
```

| Capa | Responsabilidad | En este repo |
|---|---|---|
| Borde (gateway / WAF) | Filtrado grueso y barato. No reemplaza la validación del servicio. | `gateway/nginx.conf` |
| Frontera del servicio | Schemas estrictos, `extra="forbid"`, canonicalización, mensajes de error genéricos. | `app/schemas.py`, `app/validation.py` |
| Dominio | Reglas de negocio (ownership; el privilegio nunca sale de la entrada). | `UserCreate` no tiene `is_admin` |
| Sinks | SQL parametrizado, sin shell, paths confinados, allowlist de salida. | `app/routes_secure.py`, `app/validation.py` |
| Salida | Encoders contextuales, templates con autoescape, sanitizer, CSP con nonce. | `app/encoding.py`, `app/sanitize.py`, `app/main.py`, `app/templates/` |
| Observabilidad | Logs estructurados, CR/LF neutralizados. | `app/logging_conf.py` |
| Entre servicios | Los mensajes de otros servicios o de colas también son entrada no confiable: se validan con los mismos schemas compartidos. | (nota de diseño) |
| Transversal | Librería o middleware de validación compartido, contratos OpenAPI, tests de payloads, fuzzing, SAST/DAST en CI. | `tests/test_payloads.py` |

## Casos

| Caso | `/vuln` | `/secure` |
|---|---|---|
| SQL injection (`GET /comments/search`) | SQL armado con f-string | query param validado con patrón + consulta parametrizada |
| XSS almacenado (`POST`/`GET /comments`) | sin autoescape | autoescape + nh3 para texto enriquecido + CSP con nonce |
| Inyección en contexto JS (`?filter=`) | `'{{ filter }}'` | `{{ filter \| tojson }}` |
| Mass assignment (`POST /users`) | cada clave se vuelve una columna | DTO con `extra="forbid"` |
| Path traversal (`GET /files`) | `os.path.join(base, name)` | allowlist de nombre + el path resuelto debe quedar dentro de base |
| Command injection (`GET /ping`) | `shell=True` | validación del host + lista de argv, sin shell |
| SSRF (`POST /avatar`) | pide cualquier URL, sigue redirects | solo https, allowlist de hosts, solo IPs públicas, sin redirects, solo metadatos |
| Log injection (`POST /login`) | entrada cruda en un log de texto | línea de log JSON, CR/LF escapados |
| Encoders (`GET /secure/encode`) | — | el mismo valor codificado para html, js, url, log |

## Ejecutar

```bash
docker compose up --build
# abrir http://localhost:8080/docs, http://localhost:8080/vuln/comments, http://localhost:8080/secure/comments
docker compose down   # al terminar
```

Payloads listos para enviar: `attacks/requests.http`.

## Tests

```bash
cd comments-service
uv venv -p 3.12 .venv && uv pip install -p .venv -r requirements-dev.txt
.venv/bin/pytest -q
```

Cada test muestra el ataque funcionando contra `/vuln` y bloqueado o neutralizado por `/secure`.
