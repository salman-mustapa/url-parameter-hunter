FROM python:3.12-slim

RUN useradd -m appuser
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY frontend ./frontend
COPY wordlists ./wordlists
COPY configs ./configs 2>/dev/null || true

RUN mkdir -p /app/storage /app/logs /app/data && chown -R appuser:appuser /app
USER appuser

EXPOSE 9001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9001"]