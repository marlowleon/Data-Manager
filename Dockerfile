FROM python:3.12-slim

ARG DATA_MANAGER_VERSION=1.7.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_MANAGER_DB=/data/data-manager.db

LABEL org.opencontainers.image.title="Data Manager" \
      org.opencontainers.image.version="${DATA_MANAGER_VERSION}" \
      org.opencontainers.image.description="Dockerized media import, rename, malware scan, duplicate check, and library management app"

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg clamav clamav-freshclam \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /watch /movies /tv /quarantine

COPY app.py /app/app.py
COPY data_manager_*.py /app/
COPY pyproject.toml /app/pyproject.toml

EXPOSE 8080
CMD ["python", "/app/app.py"]
