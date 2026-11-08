# Pentest Workspace: one image for the API and the static frontend.
# See "Running with Docker" in the README; docker-compose.yml starts both services.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend/ backend/
COPY data/ data/

# The frontend is served from its own folder, so the static server can never
# expose the backend code, the database or uploaded evidence.
COPY index.html /srv/web/
COPY css/ /srv/web/css/
COPY js/ /srv/web/js/
COPY data/ /srv/web/data/

RUN useradd --system --uid 10001 --no-create-home --home-dir /app wstg \
 && mkdir -p /data /app/backend/uploads /app/backend/database \
 && chown -R wstg:wstg /data /app/backend/uploads /app/backend/database

USER wstg

# The database and the generated secret key live in /data (a volume), evidence
# files in /app/backend/uploads (another volume). The API listens on all
# interfaces inside the container; docker-compose.yml publishes it on the
# host's 127.0.0.1 only.
ENV DATABASE_URL=sqlite:////data/wstg.db \
    WSTG_SECRET_KEY_FILE=/data/secret_key \
    WSTG_HOST=0.0.0.0 \
    WSTG_PORT=5000

WORKDIR /app/backend
EXPOSE 5000 8000
CMD ["python", "app.py"]
