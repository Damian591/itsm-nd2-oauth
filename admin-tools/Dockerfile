FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

RUN useradd --create-home --uid 10002 tooluser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY revoke.py .
USER tooluser

ENTRYPOINT ["python", "revoke.py"]
