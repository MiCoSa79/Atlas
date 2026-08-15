import httpx
import websockets
import asyncio
import os
import json
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import FileResponse

app = FastAPI()

# CORS for PWA access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
HERMES_URL = os.environ.get("HERMES_URL", "http://host.docker.internal:9119")
HERMES_USER = os.environ.get("HERMES_USER", "")
HERMES_PASS = os.environ.get("HERMES_PASS", "")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/setup")
def setup_page():
    return HTMLResponse("""
    <html><body>
        <h1>Atlas Initial Setup</h1>
        <p>Bitte gib die Daten deines Hermes-Containers ein.</p>
        <form method="post" action="/api/setup">
            <label>Dashboard URL</label><br>
            <input type="text" name="hermes_url" required value="http://10.0.25.60:9119"><br><br>
            
            <label>Username (Basic Auth)</label><br>
            <input type="text" name="username" required><br><br>
            
            <label>Password (Basic Auth)</label><br>
            <input type="password" name="password" required><br><br>
            
            <label>Setup-Token (für die Erstkonfiguration)</label><br>
            <input type="password" name="token" required><br><br>
            
            <button type="submit">Speichern & Starten</button>
        </form>
    </body></html>
    """)

class SetupData(BaseModel):
    hermes_url: str
    username: str
    password: str
    token: str

@app.post("/api/setup")
async def save_config(data: SetupData):
    # Check if config exists to prevent overwriting without token
    if os.path.exists("config.json"):
        raise HTTPException(status_code=403, detail="Atlas ist bereits konfiguriert.")
    
    config = {
        "hermes_url": data.hermes_url,
        "username": data.username,
        "password": data.password
    }
    with open("config.json", "w") as f:
        json.dump(config, f)
    
    return {"message": "Konfiguration gespeichert! Bitte lade die Seite neu."}

# Proxy Route
@app.websocket("/ws")
async def websocket_proxy(websocket: WebSocket):
    await websocket.accept()
    
    try:
        with open("config.json") as f:
            config = json.load(f)
    except:
        await websocket.close(code=4000, reason="No config found")
        return

    hermes_url = config["hermes_url"]
    auth = httpx.BasicAuth(config["username"], config["password"])

    try:
        # 1. Fetch WS Ticket from Dashboard
        async with httpx.AsyncClient() as client:
            res = await client.post(f"{hermes_url}/api/auth/ws-ticket", auth=auth, timeout=10)
            if res.status_code != 200:
                await websocket.close(code=4001, reason="Failed to get WS ticket")
                return
            
            ticket = res.json().get("ticket")

        # 2. Connect to Hermes WebSocket
        ws_url = f"wss://{hermes_url.replace('http', 'ws')}/api/ws?ticket={ticket}"
        async with websockets.connect(ws_url) as ws:
            # Relay Hermes -> Browser
            while True:
                try:
                    data = await ws.recv()
                    await websocket.send_text(data)
                except websockets.exceptions.ConnectionClosed:
                    break
            
    except Exception as e:
        await websocket.close(code=4002, reason=str(e))

@app.get("/")
def root():
    return FileResponse("app/static/index.html")