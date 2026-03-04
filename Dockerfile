FROM python:3.12-slim

# Install unrar (required for RAR support)
RUN apt-get update && apt-get install -y unrar-free gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir pyrogram tgcrypto rarfile

CMD ["python", "main.py"]
