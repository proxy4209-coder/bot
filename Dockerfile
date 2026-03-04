FROM python:3.12-slim

# Install GCC + build tools for TgCrypto
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first (cache optimization)
COPY requirements.txt .

# Upgrade pip + install packages
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy bot code
COPY main.py .

# Run bot
CMD ["python", "main.py"]
