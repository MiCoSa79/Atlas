FROM python:3.11-slim
WORKDIR /app

# Build-Argument: Versionsnummer (v0.0.1, ...) aus GitHub Actions -> wird auf der Hello-World-Seite angezeigt
ARG APP_VERSION=unbekannt
ENV APP_VERSION=${APP_VERSION}

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]