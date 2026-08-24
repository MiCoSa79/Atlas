FROM python:3.11-slim
WORKDIR /app

# Build-Argumente aus GitHub Actions: Versionsnummer (v0.0.1, ...) und Build-Datum -> werden auf der Hello-World-Seite angezeigt
ARG APP_VERSION=unbekannt
ARG BUILD_DATE=unbekannt
ENV APP_VERSION=${APP_VERSION} BUILD_DATE=${BUILD_DATE}

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--ws-max-size", "402653184"]