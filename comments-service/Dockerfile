FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY data ./data

# Corre como usuario no root; la base vive en una ubicación temporal con escritura.
# UID fijo: coincide con el dueño de la clave de cliente montada (0600).
RUN useradd --uid 1000 --create-home appuser
USER appuser
ENV DB_PATH=/tmp/app.db

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
