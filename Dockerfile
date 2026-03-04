FROM python:3.12-slim

# Install real unrar (non-free) + gcc for tgcrypto
RUN echo "deb http://deb.debian.org/debian bookworm non-free" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y unrar gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir pyrogram tgcrypto rarfile

CMD ["python", "main.py"]
