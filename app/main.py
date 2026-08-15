import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Atlas Hello World")

# Wird beim Docker-Build gesetzt (GitHub Actions) - zeigt die exakte Version (v0.0.1, ...) und das Build-Datum
VERSION = os.environ.get("APP_VERSION", "lokal")
BUILD_DATE = os.environ.get("BUILD_DATE", "unbekannt")

@app.get("/", response_class=HTMLResponse)
async def root():
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Atlas - Hello World</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #111; color: #eee;
           display: flex; flex-direction: column; align-items: center;
           justify-content: center; min-height: 100vh; margin: 0; }}
    h1 {{ font-size: 3rem; margin: 0; }}
    p {{ color: #888; }}
    .version {{ margin-top: 2rem; padding: .5rem 1rem; background: #222;
                border-radius: .5rem; font-family: monospace; color: #4ade80; }}
  </style>
</head>
<body>
  <h1>Hello World!</h1>
  <p>Atlas-Container läuft einwandfrei.</p>
  <div class="version">Version: {VERSION} &middot; Build vom {BUILD_DATE}</div>
</body>
</html>"""
