"""Atlas — Multi-User-Chat-Gateway zu Hermes.

Eigenständiger FastAPI-Container:
- Initial-Setup-Wizard (legt Admin an und bindet eine Hermes-Instanz an)
- Login/Logout mit eigenem Session-Token (Cookie, KEIN itsdangerous nötig)
- WebSocket-Proxy zum Hermes-Gateway (ws-ticket -> JSON-RPC 2.0)

Läuft im Container unter /app, Datenbank in /data/atlas.db (Volume).
"""
import asyncio
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie

import aiohttp
import bcrypt
from aiohttp import ClientSession, ClientTimeout, WSMsgType
from fastapi import FastAPI, Form, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("ATLAS_DB", "/data/atlas.db")
SESSION_COOKIE = "atlas_session"


# ---------------------------------------------------------------- Datenbank

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
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


def user_count():
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return n


def create_user(username, password, is_admin, hermes_url=None, hermes_user=None, hermes_pass=None):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    hermes_auth = f"{hermes_user}:{hermes_pass}" if hermes_user else None
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, hermes_url, hermes_auth, hermes_profile)"
            " VALUES (?, ?, ?, ?, ?, NULL)",
            (username, hashed, is_admin, hermes_url, hermes_auth),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def verify_user(username, password):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user:
        return None
    if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return dict(user)
    return None


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------- App-Setup

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Atlas", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Server-seitiger Session-Store: token -> user-dict
app.state.user_sessions = {}


def start_session(user: dict) -> str:
    token = secrets.token_urlsafe(32)
    app.state.user_sessions[token] = {"user_id": user["id"], "username": user["username"]}
    return token


def session_from_request(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return app.state.user_sessions.get(token) if token else None


def session_from_ws(ws: WebSocket):
    token = ws.cookies.get(SESSION_COOKIE)
    return app.state.user_sessions.get(token) if token else None


# ---------------------------------------------------------------- Routen

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "setup_mode": user_count() == 0}
    )


@app.post("/api/setup")
async def setup_admin(
    username: str = Form(...),
    password: str = Form(...),
):
    if user_count() > 0:
        return JSONResponse({"status": "error", "message": "Setup bereits abgeschlossen"}, status_code=400)
    if len(username) < 3 or len(password) < 6:
        return JSONResponse({"status": "error", "message": "Benutzername (min. 3) und Passwort (min. 6 Zeichen) prüfen"}, status_code=400)
    if not create_user(username, password, is_admin=1):
        return JSONResponse({"status": "error", "message": "Benutzername bereits vergeben"}, status_code=500)
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"status": "error", "message": "Interner Fehler beim Anlegen"}, status_code=500)
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie(SESSION_COOKIE, start_session(user), httponly=True, samesite="lax")
    return resp


@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"status": "error", "message": "Falsche Zugangsdaten"}, status_code=401)
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie(SESSION_COOKIE, start_session(user), httponly=True, samesite="lax")
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        app.state.user_sessions.pop(token, None)
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/session")
async def api_session(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"logged_in": False})
    db_user = get_user_by_id(user["user_id"]) or {}
    return JSONResponse({
        "logged_in": True,
        "username": user.get("username"),
        "hermes_url": db_user.get("hermes_url"),
        "hermes_profile": db_user.get("hermes_profile"),
        "hermes_configured": bool(db_user.get("hermes_url") and db_user.get("hermes_auth")),
    })


@app.get("/api/profile")
async def api_profile(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_user = db_user.get("hermes_auth", "").partition(":")[0] if db_user.get("hermes_auth") else ""
    return JSONResponse({
        "status": "ok",
        "hermes_url": db_user.get("hermes_url") or "",
        "hermes_user": hermes_user,
        "hermes_configured": bool(db_user.get("hermes_url") and db_user.get("hermes_auth")),
    })


@app.post("/api/profile")
async def api_profile_save(request: Request,
                           hermes_url: str = Form(""),
                           hermes_user: str = Form(""),
                           hermes_pass: str = Form("")):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    hermes_url = hermes_url.strip().rstrip("/")
    if hermes_url and not hermes_url.startswith(("http://", "https://")):
        return JSONResponse({"status": "error", "message": "Hermes-URL muss mit http(s):// beginnen"}, status_code=400)
    if bool(hermes_user) != bool(hermes_pass):
        return JSONResponse({"status": "error", "message": "Hermes-Benutzer und -Passwort immer zusammen angeben"}, status_code=400)

    conn = get_db()
    db_user = conn.execute("SELECT * FROM users WHERE id = ?", (user["user_id"],)).fetchone()
    if not db_user:
        conn.close()
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden"}, status_code=404)

    if hermes_user and hermes_pass:
        new_auth = f"{hermes_user}:{hermes_pass}"
    else:
        new_auth = db_user["hermes_auth"] if hermes_url else None
    if not hermes_url:
        new_auth = None

    conn.execute("UPDATE users SET hermes_url = ?, hermes_auth = ? WHERE id = ?",
                 (hermes_url or None, new_auth, user["user_id"]))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------- Chat-Proxy

@app.websocket("/ws")
async def websocket_proxy(ws: WebSocket):
    await ws.accept()
    session = session_from_ws(ws)
    if not session:
        await ws.close(code=4001, reason="Nicht angemeldet")
        return

    # Hermes-Zugang immer frisch aus der DB laden (Profiländerungen wirken sofort)
    db_user = get_user_by_id(session["user_id"]) or {}
    hermes_url = db_user.get("hermes_url")
    hermes_auth = db_user.get("hermes_auth")
    if not hermes_url or not hermes_auth:
        await ws.close(code=4001, reason="Kein Hermes-Zugang hinterlegt")
        return

    auth_user, _, auth_pass = hermes_auth.partition(":")
    if not auth_user:
        await ws.close(code=4001, reason="Hermes-Zugang unvollständig")
        return

    # 1) Am Hermes-Gateway einloggen (Session-Cookie wird manuell übernommen,
    #    weil aiohttp 3.9.x die Set-Cookie-Header nicht zuverlässig im Jar speichert)
    try:
        async with ClientSession() as http:
            async with http.post(
                f"{hermes_url}/auth/password-login",
                json={"provider": "basic", "username": auth_user, "password": auth_pass, "next": ""},
                timeout=ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    await ws.close(code=4001, reason=f"Hermes-Login-Status {resp.status}")
                    return
                parts = []
                for header in resp.headers.getall("Set-Cookie", []):
                    sc = SimpleCookie()
                    sc.load(header)
                    for m in sc.values():
                        parts.append(f"{m.key}={m.value}")
            cookie_header = "; ".join(parts)

            # 2) Einmaliges WS-Ticket mit der frischen Session holen
            async with http.post(
                f"{hermes_url}/api/auth/ws-ticket",
                headers={"Cookie": cookie_header} if cookie_header else {},
                timeout=ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    await ws.close(code=4001, reason=f"Ticket-Status {resp.status}")
                    return
                data = await resp.json()
                ticket = (data or {}).get("ticket")
    except Exception as e:
        await ws.close(code=4001, reason=f"Ticket-Fehler: {e}")
        return

    if not ticket:
        await ws.close(code=4002, reason="Kein Ticket erhalten")
        return

    # 3) Zum Hermes-Gateway durchschalten (JSON-RPC läuft transparent durch)
    try:
        async with ClientSession() as http:
            async with http.ws_connect(
                f"{hermes_url}/api/ws?ticket={ticket}", max_msg_size=0
            ) as hws:

                async def fwd_hermes_to_client():
                    try:
                        async for msg in hws:
                            if msg.type == WSMsgType.TEXT:
                                await ws.send_text(msg.data)
                            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR, WSMsgType.CLOSED):
                                break
                    except Exception:
                        pass
                    try:
                        await ws.close()
                    except Exception:
                        pass

                async def fwd_client_to_hermes():
                    try:
                        while True:
                            raw = await ws.receive_text()
                            await hws.send_str(raw)
                    except Exception:
                        pass
                    try:
                        await hws.close()
                    except Exception:
                        pass

                t1 = asyncio.create_task(fwd_hermes_to_client())
                t2 = asyncio.create_task(fwd_client_to_hermes())
                done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
    except Exception as e:
        await ws.close(code=4002, reason=str(e))
