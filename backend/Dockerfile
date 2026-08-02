FROM python:3.12-slim

WORKDIR /app

# reportlab/Pillow need a couple of system libs to build wheels on slim images
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root for least-privilege container security
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

ENV PORT=8000
EXPOSE 8000

# Shell form (not exec form) so $PORT is actually expanded at container
# startup — Render/Railway/etc inject their own PORT value per deploy, and
# exec-form CMD ["uvicorn", ..., "--port", "8000"] would ignore it entirely.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
