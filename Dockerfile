FROM python:3.11-slim
WORKDIR /app

# Build-Argument: Commit-SHA aus GitHub Actions -> wird auf der Hello-World-Seite angezeigt
ARG GIT_COMMIT=unbekannt
ENV GIT_COMMIT=${GIT_COMMIT}

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]