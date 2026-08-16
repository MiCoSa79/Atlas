"""Atlas — Multi-User-Chat-Gateway zu Hermes.

Eigenständiger FastAPI-Container:
- Initial-Setup-Wizard (legt Admin an und bindet eine Hermes-Instanz an)
- Login/Logout mit eigenem Session-Token (Cookie, KEIN itsdangerous nötig)
- WebSocket-Proxy zum Hermes-Gateway (ws-ticket -> JSON-RPC 2.0)

Läuft im Container unter /app, Datenbank in /data/atlas.db (Volume).
"""
import asyncio
import base64
import aiohttp
import bcrypt
import json
import os
import secrets
import shutil
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from urllib.parse import quote

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from aiohttp import ClientSession, ClientTimeout, WSMsgType
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("ATLAS_DB", "/data/atlas.db")
UPLOAD_DIR = os.path.join(os.path.dirname(DB_PATH) or ".", "uploads")
SESSION_COOKIE = "atlas_session"

# Upload-Verzeichnis nur erstellen, wenn es noch nicht existiert (verhindert PermissionErrors bei nicht-root)
try:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
except Exception:
    pass


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
            is_active INTEGER DEFAULT 1,
            hermes_url TEXT,
            hermes_auth TEXT,
            hermes_profile TEXT,
            allow_registration INTEGER
        )
    """)
    conn.execute("""CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)""")
    # Alte DBs: fehlende Spalten nachträglich hinzufügen (ignoriert Fehler, wenn schon da)
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN allow_registration INTEGER")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN show_reasoning INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN show_status INTEGER DEFAULT 1")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN otp_confirmed INTEGER DEFAULT 0")
    except Exception:
        pass
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


def get_setting(key, default=None):
    """Liest einen Wert aus der Settings-Tabelle (key/value)."""
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def user_has_2fa(user: dict) -> bool:
    return bool(user.get("otp_secret") and user.get("otp_confirmed"))


def create_user(username, password, is_admin, hermes_url=None, hermes_user=None, hermes_pass=None, allow_registration=None):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    hermes_auth = f"{hermes_user}:{hermes_pass}" if hermes_user else None
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, hermes_url, hermes_auth, hermes_profile, allow_registration)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, hashed, is_admin, hermes_url, hermes_auth, None, allow_registration),
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


def user_hermes_info(user: dict) -> dict:
    """Hermes-Status eines Benutzers (URL getrennt von Auth, damit das Frontend
    genau sagen kann, was fehlt)."""
    auth = user.get("hermes_auth") or ""
    auth_user = auth.partition(":")[0] if auth else ""
    return {
        "hermes_url": user.get("hermes_url") or "",
        "hermes_user": auth_user,
        "hermes_url_set": bool(user.get("hermes_url")),
        "hermes_auth_set": bool(auth),
        "hermes_configured": bool(user.get("hermes_url") and auth),
        "hermes_profile": user.get("hermes_profile") or "",
        "show_reasoning": user.get("show_reasoning") if user.get("show_reasoning") is not None else 1,
        "show_status": user.get("show_status") if user.get("show_status") is not None else 1,
    }


# ---------------------------------------------------------------- Backend-Helper

async def hermes_ws_request(hermes_url: str, auth: str, method: str, params: dict = None, profile: str = None) -> dict:
    """Allgemeine Funktion für WS-JSON-RPC-Anfragen an Hermes über Ticket-Auth.
    Ruft login → ticket → session.create + request parallel → erste passende Antwort zurück."""
    if not hermes_url or not auth:
        return {}
    auth_user, _, auth_pass = auth.partition(":")
    if not auth_user:
        return {}
    try:
        async with ClientSession() as http:
            # 1) Login
            async with http.post(f"{hermes_url}/auth/password-login",
                json={"provider": "basic", "username": auth_user, "password": auth_pass, "next": ""},
                timeout=ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return {}
                parts = []
                for h in resp.headers.getall("Set-Cookie", []):
                    sc = SimpleCookie(); sc.load(h)
                    parts.extend(f"{m.key}={m.value}" for m in sc.values())
            cookie = "; ".join(parts)

            # 2) WS-Ticket
            async with http.post(f"{hermes_url}/api/auth/ws-ticket",
                headers={"Cookie": cookie} if cookie else {},
                timeout=ClientTimeout(total=10)) as resp:
                data = await resp.json()
            ticket = (data or {}).get("ticket")
            if not ticket:
                return {}

            # 3) WS-Verbindung
            uri = f"{hermes_url}/api/ws?ticket={ticket}"
            async with http.ws_connect(uri, max_msg_size=0) as hws:
                profile = profile or ""
                # session.create mit Profil
                await hws.send_str(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "session.create",
                    "params": {"close_on_disconnect": True, "source": "webui", "profile": profile}}))
                # Gewünschte Methode
                msg_id = 2
                await hws.send_str(json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}))

                # Antworten sammeln
                results = {}
                deadline = asyncio.get_event_loop().time() + 10
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        raw = await asyncio.wait_for(hws.receive_str(), timeout=2)
                        frame = json.loads(raw)
                        rid = frame.get("id")
                        if rid and frame.get("result"):
                            results[rid] = frame["result"]
                        if msg_id in results:
                            break
                    except asyncio.TimeoutError:
                        continue
            return results.get(msg_id) or {}
    except Exception:
        return {}


# ---------------------------------------------------------------- Profile-Helper


async def test_hermes_connection(hermes_url: str, auth: str) -> tuple:
    """Probiert den Login am Hermes-Gateway aus. Gibt (status, detail) zurück:
    status in ("connected", "missing", "failed")."""
    if not hermes_url or not auth:
        return ("missing", "")
    auth_user, _, auth_pass = auth.partition(":")
    if not auth_user:
        return ("missing", "")
    try:
        async with ClientSession() as http:
            async with http.post(
                f"{hermes_url}/auth/password-login",
                json={"provider": "basic", "username": auth_user, "password": auth_pass, "next": ""},
                timeout=ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    return ("connected", "")
                return ("failed", f"Login abgelehnt (Status {resp.status}) – Zugangsdaten prüfen")
    except asyncio.TimeoutError:
        return ("failed", "Zeitüberschreitung – URL nicht erreichbar")
    except aiohttp.ClientConnectorError as e:
        return ("failed", f"URL nicht erreichbar: {e}")
    except Exception as e:
        return ("failed", f"Unerwarteter Fehler: {type(e).__name__}")


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
# 2FA-Zwischenzustand nach Passwort-Login: token -> {user_id, username, expires}
app.state.pending_2fa = {}

# TOTP: 30s-Fenster, 1 Intervall Toleranz (vor/nach) gegen Tippzeit-Versatz
OTP_WINDOW = 1
# Pending-2FA-Token nur 5 Minuten gültig, max. 5 Prüfversuche
PENDING_2FA_TTL = 300
PENDING_2FA_MAX_ATTEMPTS = 5


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
        "index.html",
        {"request": request, "setup_mode": user_count() == 0,
         "BUILD_VERSION": os.environ.get("APP_VERSION", "unknown"),
         "BUILD_DATE": os.environ.get("BUILD_DATE", "unknown")}
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
    if not user.get("is_active"):
        return JSONResponse({"status": "error", "message": "Dein Konto ist deaktiviert"}, status_code=403)
    # 2FA-Stufe 1: Passwort korrekt, aber TOTP aktiv -> noch KEINE Session, erst Code prüfen
    if user.get("otp_secret") and user.get("otp_confirmed"):
        pending_token = secrets.token_urlsafe(32)
        app.state.pending_2fa[pending_token] = {
            "user_id": user["id"],
            "username": user["username"],
            "expires": time.time() + PENDING_2FA_TTL,
            "attempts": 0,
        }
        return JSONResponse({"status": "2fa_required", "pending_token": pending_token})
    resp = JSONResponse({"status": "ok", "is_admin": bool(user.get("is_admin"))})
    resp.set_cookie(SESSION_COOKIE, start_session(user), httponly=True, samesite="lax")
    return resp


@app.post("/api/2fa/verify")
async def otp_verify(pending_token: str = Form(...), code: str = Form(...)):
    """2FA-Stufe 2: prüft den TOTP-Code und startet erst dann die Session."""
    pending = app.state.pending_2fa.get(pending_token)
    if not pending or pending.get("expires", 0) < time.time():
        app.state.pending_2fa.pop(pending_token, None)
        return JSONResponse({"status": "error", "message": "Anmeldung abgelaufen – bitte erneut einloggen"}, status_code=401)
    db_user = get_user_by_id(pending["user_id"]) or {}
    secret = db_user.get("otp_secret")
    if not secret or not db_user.get("otp_confirmed"):
        app.state.pending_2fa.pop(pending_token, None)
        return JSONResponse({"status": "error", "message": "2FA ist nicht mehr aktiv"}, status_code=401)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=OTP_WINDOW):
        pending["attempts"] += 1
        if pending["attempts"] >= PENDING_2FA_MAX_ATTEMPTS:
            app.state.pending_2fa.pop(pending_token, None)
            return JSONResponse({"status": "error", "message": "Zu viele Fehlversuche – bitte erneut einloggen"}, status_code=401)
        return JSONResponse({"status": "error", "message": "Code ungültig"}, status_code=401)
    app.state.pending_2fa.pop(pending_token, None)
    resp = JSONResponse({"status": "ok", "is_admin": bool(db_user.get("is_admin"))})
    resp.set_cookie(SESSION_COOKIE, start_session(db_user), httponly=True, samesite="lax")
    return resp


@app.get("/api/2fa/status")
async def otp_status(request: Request):
    """2FA-Status für die Einstellungen (eingeloggt)."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    return JSONResponse({
        "status": "ok",
        "enabled": bool(db_user.get("otp_secret") and db_user.get("otp_confirmed")),
        "pending": bool(db_user.get("otp_secret") and not db_user.get("otp_confirmed")),
    })


def otp_qr_data_url(provisioning_uri: str) -> str:
    """Erzeugt ein QR-Code-SVG (data-URL) für die Authenticator-App."""
    try:
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(image_factory=SvgPathImage)
        buf = img.to_string()  # SVG-XML als bytes
        b64 = base64.b64encode(buf).decode("ascii")
        return f"data:image/svg+xml;base64,{b64}"
    except Exception:
        return ""


@app.post("/api/2fa/setup")
async def otp_setup(request: Request):
    """Startet die 2FA-Einrichtung: erzeugt Secret + QR-Code, speichert Secret
    (noch nicht aktiv — erst nach erfolgreicher Code-Bestätigung)."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    secret = pyotp.random_base32()
    db_user = get_user_by_id(user["user_id"]) or {}
    username = db_user.get("username", user.get("username", ""))
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Atlas")
    conn = get_db()
    conn.execute("UPDATE users SET otp_secret = ?, otp_confirmed = 0 WHERE id = ?", (secret, user["user_id"]))
    conn.commit()
    conn.close()
    return JSONResponse({
        "status": "ok",
        "secret": secret,
        "otpauth_uri": uri,
        "qr_data_url": otp_qr_data_url(uri),
    })


@app.post("/api/2fa/confirm")
async def otp_confirm(request: Request, code: str = Form(...)):
    """Bestätigt die Einrichtung mit einem gültigen TOTP-Code -> 2FA wird aktiv."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    secret = db_user.get("otp_secret")
    if not secret:
        return JSONResponse({"status": "error", "message": "Kein 2FA-Secret vorhanden"}, status_code=400)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=OTP_WINDOW):
        return JSONResponse({"status": "error", "message": "Code ungültig – bitte prüfen und erneut versuchen"}, status_code=401)
    conn = get_db()
    conn.execute("UPDATE users SET otp_confirmed = 1 WHERE id = ?", (user["user_id"],))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "message": "2FA aktiviert ✓"})


@app.post("/api/2fa/disable")
async def otp_disable(request: Request, password: str = Form(...)):
    """Deaktiviert 2FA — Passwort-Bestätigung nötig, damit niemand fremd
    den Schutz einfach entfernen kann."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    if not db_user.get("otp_secret"):
        return JSONResponse({"status": "error", "message": "2FA ist gar nicht aktiv"}, status_code=400)
    if not db_user.get("password_hash") or not bcrypt.checkpw(
        password.encode("utf-8"), db_user["password_hash"].encode("utf-8")
    ):
        return JSONResponse({"status": "error", "message": "Passwort falsch"}, status_code=401)
    conn = get_db()
    conn.execute("UPDATE users SET otp_secret = NULL, otp_confirmed = 0 WHERE id = ?", (user["user_id"],))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "message": "2FA deaktiviert"})


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
    info = user_hermes_info(db_user)
    has_2fa = user_has_2fa(db_user)
    require_2fa = get_setting("require_2fa", "0") == "1"
    return JSONResponse({
        "logged_in": True,
        "username": user.get("username"),
        "is_admin": bool(db_user.get("is_admin")),
        "hermes_url": info["hermes_url"],
        "hermes_profile": info.get("hermes_profile"),
        "hermes_configured": info["hermes_configured"],
        "otp_enabled": has_2fa,
        "otp_required": bool(require_2fa and not has_2fa),
    })


@app.get("/api/config")
async def api_config():
    """Öffentliche Konfiguration für die Login-Seite (kein Login nötig)."""
    conn = get_db()
    reg_row = conn.execute("SELECT value FROM settings WHERE key = 'allow_registration'").fetchone()
    conn.close()
    allow_reg = reg_row["value"] == "1" if reg_row else True  # Default: offen
    return JSONResponse({
        "setup": user_count() == 0,
        "allow_registration": allow_reg,
    })


@app.get("/api/profiles")
async def api_profiles(request: Request):
    """Listet Profile der hinterlegten Hermes-Instanz."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_auth = db_user.get("hermes_auth")
    hermes_url = db_user.get("hermes_url") or ""
    if not hermes_url or not hermes_auth:
        return JSONResponse({"status": "ok", "profiles": []})
    profiles = await hermes_ws_request(hermes_url, hermes_auth, "profiles.list",
                                     {"include_sessions": False}, db_user.get("hermes_profile") or "")
    profile_list = (profiles or {}).get("profiles", [])
    return JSONResponse({"status": "ok", "profiles": profile_list})


@app.get("/api/profile")
async def api_profile(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    info = user_hermes_info(db_user)
    return JSONResponse({"status": "ok", **info})


@app.post("/api/profile")
async def api_profile_save(request: Request,
                           hermes_url: str = Form(""),
                           hermes_user: str = Form(""),
                           hermes_pass: str = Form(""),
                           hermes_profile: str = Form(""),
                           show_reasoning: str = Form(""),
                           show_status: str = Form("")):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    hermes_url = hermes_url.strip().rstrip("/")
    if hermes_url and not hermes_url.startswith(("http://", "https://")):
        return JSONResponse({"status": "error", "message": "Hermes-URL muss mit http(s):// beginnen"}, status_code=400)

    conn = get_db()
    db_user = conn.execute("SELECT * FROM users WHERE id = ?", (user["user_id"],)).fetchone()
    if not db_user:
        conn.close()
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden"}, status_code=404)

    if hermes_user and not hermes_pass:
        conn.close()
        return JSONResponse({"status": "error", "message": "Bei Hermes-Benutzer muss auch das Passwort angegeben werden"}, status_code=400)
    if hermes_pass and not hermes_user:
        conn.close()
        return JSONResponse({"status": "error", "message": "Bei Hermes-Passwort muss auch der Benutzer angegeben werden"}, status_code=400)

    if hermes_user and hermes_pass:
        new_auth = f"{hermes_user}:{hermes_pass}"
    else:
        new_auth = db_user["hermes_auth"] if hermes_url else None
    if not hermes_url:
        new_auth = None

    # Nur übergebene Felder aktualisieren
    sets = []
    values = []
    if hermes_url != "":
        sets.append("hermes_url = ?")
        values.append(hermes_url or None)
    if hermes_user or hermes_pass:
        sets.append("hermes_auth = ?")
        values.append(new_auth)
    if hermes_profile != "":
        sets.append("hermes_profile = ?")
        values.append(hermes_profile.strip() if hermes_profile else None)
    if show_reasoning != "":
        sets.append("show_reasoning = ?")
        values.append(1 if show_reasoning == "1" else 0)
    if show_status != "":
        sets.append("show_status = ?")
        values.append(1 if show_status == "1" else 0)

    if sets:
        sql = f"UPDATE users SET {', '.join(sets)} WHERE id = ?"
        values.append(user["user_id"])
        conn.execute(sql, values)
        conn.commit()
    conn.close()

    # Nach dem Speichern: Verbindung sofort testen, damit der Nutzer weiß, ob es klappt
    if hermes_url and new_auth:
        test, detail = await test_hermes_connection(hermes_url, new_auth)
    else:
        test, detail = ("missing", "Benutzer und Passwort fehlen")
    return JSONResponse({"status": "ok", "test": test, "test_error": detail})


# ---------------------------------------------------------------- Registrierung

@app.post("/api/register")
async def register(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    reg_allowed = conn.execute("SELECT value FROM settings WHERE key = 'allow_registration'").fetchone()
    conn.close()
    allow_reg = reg_allowed["value"] == "1" if reg_allowed else True  # Default: offen
    if not allow_reg:
        return JSONResponse({"status": "error", "message": "Registrierung ist aktuell nicht möglich"}, status_code=403)
    if len(username) < 3 or len(password) < 6:
        return JSONResponse({"status": "error", "message": "Benutzername (min. 3) und Passwort (min. 6 Zeichen) prüfen"}, status_code=400)
    if not create_user(username, password, is_admin=0, allow_registration=0):
        return JSONResponse({"status": "error", "message": "Benutzername bereits vergeben"}, status_code=500)
    user = verify_user(username, password)
    if not user:
        return JSONResponse({"status": "error", "message": "Interner Fehler beim Anlegen"}, status_code=500)
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie(SESSION_COOKIE, start_session(user), httponly=True, samesite="lax")
    return resp


# ---------------------------------------------------------------- Admin

def is_admin_request(request: Request) -> bool:
    """Admin-Check immer gegen die FRISCHE DB (Session speichert bewusst nur
    user_id/username, damit Profiländerungen sofort wirken)."""
    user = session_from_request(request)
    if not user:
        return False
    db_user = get_user_by_id(user["user_id"]) or {}
    return bool(db_user.get("is_admin"))


@app.get("/api/admin/settings")
async def admin_settings(request: Request):
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    allow_reg = get_setting("allow_registration", "1") == "1"
    require_2fa = get_setting("require_2fa", "0") == "1"
    return JSONResponse({"status": "ok", "allow_registration": allow_reg, "require_2fa": require_2fa})


@app.post("/api/admin/settings")
async def admin_settings_save(request: Request,
                              allow_registration: str = Form("0"),
                              require_2fa: str = Form("0")):
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('allow_registration', ?)", (allow_registration,))
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('require_2fa', ?)", (require_2fa,))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok"})


@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    conn = get_db()
    rows = conn.execute("SELECT id, username, is_admin, is_active FROM users ORDER BY id").fetchall()
    conn.close()
    return JSONResponse({"status": "ok", "users": [dict(r) for r in rows]})


@app.post("/api/admin/users")
async def admin_create_user(request: Request,
                            username: str = Form(...),
                            password: str = Form(...)):
    """Admin legt manuell einen neuen Benutzer an (ohne Adminrechte)."""
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    username = username.strip()
    if len(username) < 3 or len(password) < 6:
        return JSONResponse({"status": "error", "message": "Benutzername (min. 3) und Passwort (min. 6 Zeichen) prüfen"}, status_code=400)
    if not create_user(username, password, is_admin=0):
        return JSONResponse({"status": "error", "message": "Benutzername bereits vergeben"}, status_code=500)
    return JSONResponse({"status": "ok"})


@app.put("/api/admin/users/{user_id}/toggle")
async def admin_toggle_user(user_id: int, request: Request, is_active: str = Form("0")):
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    want_active = 1 if is_active == "1" else 0
    conn = get_db()
    row = conn.execute("SELECT id, is_admin, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden"}, status_code=404)
    if want_active == 0 and row["is_admin"]:
        # Schutz: Es muss immer mindestens ein AKTIVER Admin geben
        active_admins = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND is_active = 1").fetchone()[0]
        if active_admins <= 1:
            conn.close()
            return JSONResponse({"status": "error",
                                 "message": "Es muss immer mindestens ein aktiver Admin geben — letzten aktiven Admin kann man nicht deaktivieren."},
                                status_code=400)
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (want_active, user_id))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok"})


@app.put("/api/admin/users/{user_id}/role")
async def admin_set_role(user_id: int, request: Request, is_admin: str = Form("0")):
    """Adminrechte vergeben/entziehen. Der letzte verbleibende Admin kann nie entlassen werden."""
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    want_admin = 1 if is_admin == "1" else 0
    conn = get_db()
    row = conn.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden"}, status_code=404)
    current = row["is_admin"]
    if want_admin == current:
        conn.close()
        return JSONResponse({"status": "ok", "changed": False})
    if want_admin == 0:
        # Schutz: mindestens 1 Admin muss übrig bleiben
        admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return JSONResponse({"status": "error",
                                 "message": "Es muss immer mindestens ein Admin geben — letzten Admin kann man nicht entlassen."},
                                status_code=400)
    conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (want_admin, user_id))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "changed": True})


@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: int, request: Request):
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    user = session_from_request(request) or {}
    if user_id == user.get("user_id"):
        return JSONResponse({"status": "error", "message": "Du kannst dein eigenes Konto nicht löschen"}, status_code=400)
    conn = get_db()
    row = conn.execute("SELECT id, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden"}, status_code=404)
    if row["is_admin"]:
        admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return JSONResponse({"status": "error",
                                 "message": "Es muss immer mindestens ein Admin geben — letzten Admin kann man nicht löschen."},
                                status_code=400)
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------- Datei-Upload

@app.post("/api/upload")
async def api_upload(request: Request, file: UploadFile):
    """Speichert eine Datei lokal und gibt eine interne ID zurück."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    if file.filename is None or file.filename == "":
        return JSONResponse({"status": "error", "message": "Kein Dateiname"}, status_code=400)
    
    # Datei-ID generieren
    file_id = uuid.uuid4().hex
    ext = os.path.splitext(file.filename)[1] or ".bin"
    save_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")
    
    try:
        # Datei schreiben
        with open(save_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        return JSONResponse({
            "status": "ok",
            "file_id": file_id,
            "filename": file.filename,
            "path": save_path
        })
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


# ---------------------------------------------------------------- Session-REST-Endpoints

@app.get("/api/sessions")
async def api_sessions(request: Request):
    """Listet alle Sessions des eingestellten Hermes-Profils (session.list via WS)."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_url = db_user.get("hermes_url")
    hermes_auth = db_user.get("hermes_auth")
    if not hermes_url or not hermes_auth:
        return JSONResponse({"status": "ok", "sessions": []})
    profile = db_user.get("hermes_profile") or ""
    result = await hermes_ws_request(hermes_url, hermes_auth, "session.list",
                                     {"limit": 100, "profile": profile}, profile)
    sessions = result.get("sessions", [])
    clean = [{
        "id": s.get("id", ""),
        "title": s.get("title", "") or "Ohne Titel",
        "preview": (s.get("preview", "") or "")[:120],
        "started_at": s.get("started_at", 0),
        "message_count": s.get("message_count", 0),
    } for s in sessions]
    return JSONResponse({"status": "ok", "sessions": clean})


# ---------------------------------------------------------------- Chat-Proxy

# Hermes drosselt Logins (10 pro 60s pro IP, Brute-Force-Schutz). Atlas würde bei
# JEDER WS-Verbindung (Session-Wechsel, Reconnect, mehreren Tabs) frisch einloggen
# → 429. Deshalb: Login-Cookie pro (hermes_url, user) cachen und wiederverwenden.
_HERMES_LOGIN_LOCK = None  # wird beim ersten Gebrauch erzeugt (asyncio.Lock)
_HERMES_LOGIN_CACHE = {}   # (hermes_url, auth_user) -> (cookie_header, timestamp)
_HERMES_LOGIN_TTL = 600.0  # 10 Min — Hermes-Session-Cookie hält ~15+ Min


def _hermes_login_lock():
    global _HERMES_LOGIN_LOCK
    if _HERMES_LOGIN_LOCK is None:
        _HERMES_LOGIN_LOCK = asyncio.Lock()
    return _HERMES_LOGIN_LOCK


async def hermes_login_cookie(hermes_url: str, auth_user: str, auth_pass: str) -> str:
    """Liefert einen gültigen Hermes-Login-Cookie-Header — aus dem Cache oder
    frisch eingeloggt. Beim 429 (Rate-Limit) wird kurz gewartet und erneut
    versucht. Rückgabe: Cookie-Header oder '' bei Fehlschlag.
    """
    async with _hermes_login_lock():
        now = time.time()
        cached = _HERMES_LOGIN_CACHE.get((hermes_url, auth_user))
        if cached and (now - cached[1]) < _HERMES_LOGIN_TTL:
            print("[WS-Proxy] Login-Cookie aus Cache verwendet")
            return cached[0]

        for attempt in range(3):
            try:
                async with ClientSession() as http:
                    async with http.post(
                        f"{hermes_url}/auth/password-login",
                        json={"provider": "basic", "username": auth_user, "password": auth_pass, "next": ""},
                        timeout=ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 429:
                            # Rate-Limit: warten und erneut versuchen (5s, 10s)
                            if attempt < 2:
                                wait = 5 * (attempt + 1)
                                print(f"[WS-Proxy] Login 429 — warte {wait}s und versuche erneut")
                                await asyncio.sleep(wait)
                                continue
                            print("[WS-Proxy] Login 429 nach 3 Versuchen — aufgegeben")
                            return ""
                        if resp.status != 200:
                            print(f"[WS-Proxy] Login-Status {resp.status}")
                            return ""
                        parts = []
                        for header in resp.headers.getall("Set-Cookie", []):
                            sc = SimpleCookie()
                            sc.load(header)
                            for m in sc.values():
                                parts.append(f"{m.key}={m.value}")
                        cookie_header = "; ".join(parts)
                        _HERMES_LOGIN_CACHE[(hermes_url, auth_user)] = (cookie_header, time.time())
                        print("[WS-Proxy] Frisch eingeloggt (Cookie gecacht)")
                        return cookie_header
            except Exception as e:
                print(f"[WS-Proxy] Login-Exception: {e}")
                if attempt < 2:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
        return ""


# ---------------------------------------------------------------- File-Download-Proxy

async def file_generator(http, url, headers):
    """Streamt Bytes von der Hermes-Proxy-URL an den Client.

    Gibt (status, content_type, chunk-generator) zurück — der Status wird
    geprüft, damit Fehler von Hermes nicht als „erfolgreicher“ 200-Download
    mit kaputtem Body beim Nutzer ankommen.
    """
    try:
        async with http.get(url, headers=headers, timeout=ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                print(f"[FileProxy] Hermes-Status {resp.status} für {url}")
                return resp.status, "text/plain", _empty_chunks()
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            return resp.status, content_type, _stream_chunks(resp)
    except Exception as e:
        print(f"[FileProxy] Download error: {e}")
        return 502, "text/plain", _empty_chunks()


async def _stream_chunks(resp):
    async for chunk in resp.content.iter_chunked(8192):
        yield chunk


async def _empty_chunks():
    yield b""


@app.get("/api/files/download")
async def proxy_file_download(request: Request):
    """Streamt eine Datei aus dem Hermes-Workspace direkt an den Atlas-Nutzer.

    Generischer Weg OHNE gemeinsames Volume-Mount: Atlas fragt die Datei per
    HTTP beim Hermes-Backend an (gleicher Mechanismus wie die Hermes-Desktop-App:
    das Frontend sendet ``MEDIA:/absoluter/pfad``-Tags, Atlas reicht den Pfad
    an ``{hermes_url}/api/files/download?path=...`` weiter).
    """
    user = session_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Nicht angemeldet")
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_url = db_user.get("hermes_url") or ""
    hermes_auth = db_user.get("hermes_auth") or ""
    if not hermes_url or not hermes_auth:
        raise HTTPException(status_code=400, detail="Kein Hermes-Zugang konfiguriert")
    auth_user, _, auth_pass = hermes_auth.partition(":")
    path = request.query_params.get("path", "")
    if not path:
        raise HTTPException(status_code=400, detail="Kein Dateipfad angegeben")
    cookie_header = await hermes_login_cookie(hermes_url, auth_user, auth_pass)
    if not cookie_header:
        raise HTTPException(status_code=502, detail="Hermes-Login fehlgeschlagen")
    hermes_url = hermes_url.rstrip("/")
    proxy_url = f"{hermes_url}/api/files/download?path={quote(path, safe='/')}"
    headers = {"Cookie": cookie_header}
    async with ClientSession() as http:
        status, content_type, gen = await file_generator(http, proxy_url, headers)
        if status != 200:
            raise HTTPException(status_code=status, detail="Hermes-Download fehlgeschlagen")
        return StreamingResponse(
            gen,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="{path.split("/")[-1]}"'},
        )


# ---------------------------------------------------------------- Lokale Datei-Download (nur Atlas-eigene Uploads)
# Generierte Agenten-Dateien (PDFs etc.) liefert ausschließlich /api/files/download
# per Hermes-Proxy — KEIN gemeinsames Volume-Mount (generisch, öffentlich-tauglich).

@app.get("/api/local-files/download")
async def local_file_download(request: Request):
    """Streamt eine lokal im Atlas-Upload-Verzeichnis gespeicherte Datei."""
    user = session_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Nicht angemeldet")
    filename = request.query_params.get("filename", "")
    if not filename:
        raise HTTPException(status_code=400, detail="Kein Dateiname angegeben")
    # Sicherheitscheck: nur Dateinamen ohne Path-Traversal
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Datei nicht gefunden")

    # MIME-Type ermitteln
    import mimetypes
    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type is None:
        mime_type = "application/octet-stream"
    from fastapi.responses import FileResponse
    return FileResponse(file_path, filename=safe_filename, media_type=mime_type)


@app.websocket("/ws")
async def websocket_proxy(ws: WebSocket):
    await ws.accept()
    session = session_from_ws(ws)
    print(f"[WS-Proxy] accept, session={session}")
    if not session:
        print("[WS-Proxy] Kein User → close")
        await ws.close(code=4001, reason="Nicht angemeldet")
        return

    # Hermes-Zugang immer frisch aus der DB laden (Profiländerungen wirken sofort)
    db_user = get_user_by_id(session["user_id"]) or {}
    hermes_url = db_user.get("hermes_url")
    hermes_auth = db_user.get("hermes_auth")
    hermes_profile = db_user.get("hermes_profile") or ""
    if not hermes_url or not hermes_auth:
        await ws.close(code=4001, reason="Kein Hermes-Zugang hinterlegt")
        return

    auth_user, _, auth_pass = hermes_auth.partition(":")
    if not auth_user:
        await ws.close(code=4001, reason="Hermes-Zugang unvollständig")
        return

    # 1) Login-Cookie holen. Hermes drosselt Logins (10 pro 60s pro IP) —
    #    ohne Cache kollidiert Atlas bei Session-Wechseln/Reconnects damit.
    cookie_header = await hermes_login_cookie(hermes_url, auth_user, auth_pass)
    if not cookie_header:
        await ws.close(code=4001, reason="Hermes-Login-Status 429 (Rate-Limit) — bitte kurz warten und Seite neu laden")
        return

    # 2) Einmaliges WS-Ticket holen (bei abgelaufenem Cookie: automatisch neu einloggen)
    try:
        ticket = None
        for _attempt in range(2):
            async with ClientSession() as http:
                async with http.post(
                    f"{hermes_url}/api/auth/ws-ticket",
                    headers={"Cookie": cookie_header} if cookie_header else {},
                    timeout=ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ticket = (data or {}).get("ticket")
                        break
                    if resp.status in (401, 403):
                        # Session-Cookie abgelaufen → Cache verwerfen, frisch einloggen
                        _HERMES_LOGIN_CACHE.pop((hermes_url, auth_user), None)
                        cookie_header = await hermes_login_cookie(hermes_url, auth_user, auth_pass)
                        if not cookie_header:
                            break
                        continue
                    await ws.close(code=4001, reason=f"Ticket-Status {resp.status}")
                    return
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
                                print(f"[WS-Proxy] gateway closed/error: type={msg.type}")
                                break
                    except Exception as e:
                        print(f"[WS-Proxy] fwd_hermes_to_client exception: {e}")
                    try:
                        await ws.close()
                    except Exception:
                        pass

                async def fwd_client_to_hermes():
                    try:
                        while True:
                            raw = await ws.receive_text()
                            await hws.send_str(raw)
                    except Exception as e:
                        print(f"[WS-Proxy] fwd_client_to_hermes exception: {e}")
                    try:
                        await hws.close()
                    except Exception:
                        pass

                t1 = asyncio.create_task(fwd_hermes_to_client())
                t2 = asyncio.create_task(fwd_client_to_hermes())
                done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
                print(f"[WS-Proxy] finished: done={len(done)} pending={len(pending)}")
                for t in pending:
                    t.cancel()
    except Exception as e:
        await ws.close(code=4002, reason=str(e))
