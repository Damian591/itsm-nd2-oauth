FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

RUN useradd --create-home --uid 10001 appuser \
    && mkdir /data \
    && chown appuser:appuser /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER appuser
EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", \
     "--access-logfile", "-", \
     "--access-logformat", "%(h)s \"%(m)s %(U)s\" %(s)s %(b)s", \
     "app:app"]