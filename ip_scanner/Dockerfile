FROM python:3.13-slim-bookworm

ARG BUILD_VERSION=0.1.0
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}" \
      org.opencontainers.image.title="IP Scanner"

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app
WORKDIR /app
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
