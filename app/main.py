import os
import sqlite3
import secrets
import bcrypt
import asyncio
import aiohttp
from fastapi import FastAPI, Request, WebSocket, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware
import secrets
from aiohttp import ClientTimeout

DB_PATH = "/data/atlas.db"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            hermes_url TEXT,
            hermes_auth TEXT,
            hermes_profile TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

async def check_user_exists():
    try:
        conn = get_db()
        user = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        conn.close()
        return user is not None
    except:
        return False

def create_user(username, password, is_admin=0, hermes_url=None, hermes_auth=None, hermes_profile=None):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, hermes_url, hermes_auth, hermes_profile) VALUES (?, ?, ?, ?, ?, ?)",
            (username, hashed, is_admin, hermes_url, hermes_auth, hermes_profile)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
    return True

def verify_user(username, password):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user:
        return None
    if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return dict(user)
    return None

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Atlas", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# In-Memory Session Store (für mehrere Instanzen Redis nutzen)
app.state.user_sessions = {}

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    exists = await check_user_exists()
    return templates.TemplateResponse("index.html", {"request": request, "setup_mode": not exists})

@app.post("/api/setup")
async def setup_admin(request: Request, username: str = Form(...), password: str = Form(...)):
    if await check_user_exists():
        return JSONResponse({"status": "error", "message": "Setup schon abgeschlossen"}, status_code=400)
    if create_user(username, password, is_admin=1):
        request.session["user_id"] = 1  # Einfach: nur ein Admin pro Installation
        return JSONResponse({"status": "ok"})
    return JSONResponse({"status": "error", "message": "Fehler beim Erstellen"}, status_code=500)

@app.post("/api/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = verify_user(username, password)
    if user:
        request.session["user_id"] = user["id"]
        request.session["hermes_url"] = user["hermes_url"]
        request.session["hermes_auth"] = user["hermes_auth"]
        request.session["hermes_profile"] = user["hermes_profile"]
        return RedirectResponse(url="/chat")
    return JSONResponse({"status": "error", "message": "Falsche Zugangsdaten"}, status_code=401)

@app.get("/chat")
async def chat_page(request: Request):
    if "user_id" not in request.session:
        return RedirectResponse(url="/")
    return templates.TemplateResponse("index.html", {"request": request, "setup_mode": False})

@app.get("/api/session")
async def get_session(request: Request):
    if "user_id" in request.session:
        return JSONResponse({"logged_in": True, "hermes_url": request.session.get("hermes_url")})
    return JSONResponse({"logged_in": False})

@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return JSONResponse({"status": "ok"})

@app.websocket("/ws")
async def websocket_proxy(websocket: WebSocket):
    await websocket.accept()
    
    session = request.app.state.sessions
    # Für einzelne Instanz: Session direkt aus dem Session-Cookie lesen
    user_id = None
    for k, v in session.items():
        if v.get("ws") is websocket:
            user_id = v.get("user_id")
            break
    
    if not user_id:
        await websocket.close(code=4001)
        return

    hermes_url = session.get(user_id, {}).get("hermes_url")
    hermes_auth = session.get(user_id, {}).get("hermes_auth")
    hermes_profile = session.get(user_id, {}).get("hermes_profile")

    if not hermes_url or not hermes_auth:
        await websocket.close(code=4001)
        return

    auth_parts = hermes_auth.split(":")
    if len(auth_parts) != 2:
        await websocket.close(code=4001)
        return

    async with aiohttp.ClientSession() as session_http:
        auth = aiohttp.BasicAuth(auth_parts[0], auth_parts[1])
        try:
            timeout = ClientTimeout(total=15)
            async with session_http.post(f"{hermes_url}/api/auth/ws-ticket", auth=auth, timeout=timeout) as resp:
                if resp.status != 200:
                    await websocket.close(code=4001, reason="Ticket fehlgeschlagen")
                    return
                ticket_data = await resp.json()
                ticket = ticket_data.get("ticket")
                if not ticket:
                    await websocket.close(code=4002, reason="Kein Ticket")
                    return
        except Exception as e:
            await websocket.close(code=4001, reason=str(e))
            return

        url = f"{hermes_url}/api/ws?ticket={ticket}"
        if hermes_profile:
            url += f"&profile={hermes_profile}"
            
        try:
            async with aiohttp.ClientSession() as client_ws:
                async with client_ws.ws_connect(url) as hermes_ws:
                    async def forward(src, dst):
                        try:
                            async for msg in src:
                                await dst.send_str(msg.data)
                        except Exception:
                            pass

                    t1 = asyncio.create_task(forward(hermes_ws, websocket))
                    t2 = asyncio.create_task(forward(websocket, hermes_ws))
                    
                    done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
                    for task in pending:
                        task.cancel()
        except Exception as e:
            await websocket.close(code=4002, reason=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)