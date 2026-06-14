FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_MANAGER_DB=/data/data-manager.db

WORKDIR /app
COPY app.py /app/app.py
COPY data_manager_inventory.py /app/data_manager_inventory.py

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg clamav clamav-freshclam \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /watch /movies /tv /quarantine

EXPOSE 8080
CMD ["python", "/app/app.py"]
