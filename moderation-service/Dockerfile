FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Usuario no root con UID fijo: coincide con el dueño de las claves montadas
# (permisos 0600), así no hace falta abrirlas a todo el mundo.
RUN useradd --uid 1000 --create-home appuser
USER appuser

ENV TLS_CERT=/certs/moderation.crt \
    TLS_KEY=/certs/moderation.key \
    TLS_CA=/certs/ca.crt \
    ALLOWED_CLIENTS=comments-service

EXPOSE 8443
CMD ["python", "-m", "app.server"]
