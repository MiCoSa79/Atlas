"""Atlas — Multi-User-Chat-Gateway zu Hermes.

Eigenständiger FastAPI-Container:
- Initial-Setup-Wizard (legt Admin an und bindet eine Hermes-Instanz an)
- Login/Logout mit eigenem Session-Token (Cookie, KEIN itsdangerous nötig)
- WebSocket-Proxy zum Hermes-Gateway (ws-ticket -> JSON-RPC 2.0)

Läuft im Container unter /app, Datenbank in /data/atlas.db (Volume).
"""
import asyncio
from datetime import datetime
import base64
import aiohttp
import bcrypt
import json
import os
import re
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
from cryptography.fernet import Fernet
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
import cbor2  # noqa: E402
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

DB_PATH = os.environ.get("ATLAS_DB", "/data/atlas.db")
UPLOAD_DIR = os.path.join(os.path.dirname(DB_PATH) or ".", "uploads")
SESSION_COOKIE = "atlas_session"
# ------------------------------------------------ Passkeys / WebAuthn (v0.0.228 — Port aus Starface-F58)
# Konfiguration: Admin-Settings (DB) haben Vorrang, ENV ist Fallback (Docker-Compose).
# Ohne RP_ID/ORIGIN sind Passkeys deaktiviert (Routen 503, Login-Button ausgeblendet) —
# Container-Start bleibt sicher.
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "")
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Atlas")
WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "")
PENDING_PASSKEY_TTL = 300
PENDING_PASSKEY: dict = {}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _raw_to_der_b64(sig_b64u: str) -> str:
    """WebAuthn-ES256-Signatur -> DER (normalisiert). Chrome/Windows/FIDO liefern RAW
    (r||s, 64 B), Bitwarden/Keepass liefern bereits ASN.1-DER. fido2 2.2 erwartet DER."""
    from cryptography.hazmat.primitives.asymmetric import utils
    raw = _b64u_decode(sig_b64u)
    if len(raw) == 64:
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
    else:
        try:
            r, s = utils.decode_dss_signature(raw)
        except Exception:
            raise ValueError(f"ES256-Signatur muss 64 Bytes (r||s) oder DER sein, war: {len(raw)}")
    return _b64u(utils.encode_dss_signature(r, s))


def _webauthn_config() -> dict:
    """Aktive WebAuthn-Konfig: Admin-Settings (DB) > ENV-Fallback."""
    rp_id = get_setting("webauthn_rp_id", "") or WEBAUTHN_RP_ID
    origin = get_setting("webauthn_origin", "") or WEBAUTHN_ORIGIN
    return {"rp_id": rp_id, "origin": origin, "rp_name": WEBAUTHN_RP_NAME}


def _passkey_enabled() -> bool:
    cfg = _webauthn_config()
    return bool(cfg["rp_id"] and cfg["origin"])


def _fido2_server():
    cfg = _webauthn_config()
    return Fido2Server(
        PublicKeyCredentialRpEntity(id=cfg["rp_id"], name=cfg["rp_name"]),
        attestation="none",
        verify_origin=lambda origin, _cfg=cfg: origin == _cfg["origin"],
    )


def _clean_pending_passkey():
    now = time.time()
    for key in [k for k, v in PENDING_PASSKEY.items() if v["expires"] < now]:
        PENDING_PASSKEY.pop(key, None)
# ---------------------------------------------------------------- Zugangsdaten-Verschlüsselung (v0.0.73)
# Hermes-Zugangsdaten (hermes_auth = "user:pass") werden mit Fernet (AES-128-CBC)
# verschlüsselt in der DB gespeichert. Der Schlüssel liegt NEBEN der DB
# (/data/.atlas_key, chmod 600) — schützt gegen unbefugtes Lesen der DB-Datei
# (Volume-Klau, Backup-Restore), gleiches Schutzlevel wie die DB selbst.
# Präfix "enc:" markiert verschlüsselte Werte → idempotent: Werte werden nie
# doppelt verschlüsselt, Alt-Klartext wird von decrypt_secret() weiterhin gelesen
# und von migrate_hermes_auth_encryption() beim Start einmalig konvertiert.

def _load_or_create_key():
    key_path = os.path.join(os.path.dirname(DB_PATH) or ".", ".atlas_key")
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as f:
                return f.read()
        except Exception:
            pass
    key = Fernet.generate_key()
    try:
        with open(key_path, "wb") as f:
            f.write(key)
        os.chmod(key_path, 0o600)  # nur Besitzer lesbar
        print(f"[Crypto] Neuer Schlüssel erzeugt: {key_path}")
    except Exception as e:
        print(f"[Crypto] Schlüssel-Speicherung fehlgeschlagen: {e}")
    return key


_ATLAS_KEY = _load_or_create_key()
_ATLAS_FERNET = Fernet(_ATLAS_KEY) if _ATLAS_KEY else None


def encrypt_secret(plain):
    """Verschlüsselt einen Klartext-Wert. Idempotent: bereits "enc:"-Werte
    werden unverändert zurückgegeben."""
    if not plain or _ATLAS_FERNET is None:
        return plain
    if plain.startswith("enc:"):
        return plain
    try:
        return "enc:" + _ATLAS_FERNET.encrypt(plain.encode("utf-8")).decode("utf-8")
    except Exception as e:
        print(f"[Crypto] encrypt error: {e}")
        return plain


def decrypt_secret(stored):
    """Entschlüsselt einen gespeicherten Wert. Klartext-Altbestand wird
    unverändert zurückgegeben (Migration konvertiert ihn beim Start)."""
    if not stored or _ATLAS_FERNET is None:
        return stored
    if not stored.startswith("enc:"):
        return stored
    try:
        return _ATLAS_FERNET.decrypt(stored[4:].encode("utf-8")).decode("utf-8")
    except Exception as e:
        print(f"[Crypto] decrypt error: {e}")
        return ""  # Schlüssel weg / Daten korrupt → nicht benutzbar


def migrate_hermes_auth_encryption():
    """Einmalige Migration: Klartext-hermes_auth → verschlüsselt (idempotent)."""
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT id, hermes_auth FROM users WHERE hermes_auth IS NOT NULL AND hermes_auth != ''"
        ).fetchall()
        migrated = 0
        for row in rows:
            if not (row["hermes_auth"] or "").startswith("enc:"):
                enc = encrypt_secret(row["hermes_auth"])
                conn.execute("UPDATE users SET hermes_auth = ? WHERE id = ?", (enc, row["id"]))
                migrated += 1
        conn.commit()
        conn.close()
        if migrated:
            print(f"[Crypto] Migration: {migrated} Zugangsdatensätze verschlüsselt")
    except Exception as e:
        print(f"[Crypto] Migration fehlgeschlagen: {e}")


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
    # Usage-Tracking: session.usage Events (Hermes → Atlas)
    conn.execute("""CREATE TABLE IF NOT EXISTS usage_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_id TEXT NOT NULL,
        model TEXT,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        total_tokens INTEGER DEFAULT 0,
        cost REAL DEFAULT 0.0,
        recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    # Letzter bekannter Usage-Stand pro Session (Delta-Basis, überlebt Neustarts).
    # total/input/output sind KUMULATIV über die Session-Lebensdauer — nur der
    # Unterschied zum letzten Stand ist echter Verbrauch.
    conn.execute("""CREATE TABLE IF NOT EXISTS usage_last (
        session_id TEXT PRIMARY KEY,
        total INTEGER DEFAULT 0,
        input INTEGER DEFAULT 0,
        output INTEGER DEFAULT 0,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
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
    # v0.0.234: Modell & Reasoning (pro Benutzer; session.create-Overrides)
    for col, ddl in (
        ("model TEXT DEFAULT ''", "model"),
        ("provider TEXT DEFAULT ''", "provider"),
        ("reasoning_effort TEXT DEFAULT ''", "reasoning_effort"),
        ("fast_mode TEXT DEFAULT ''", "fast_mode"),
        ("aux_models TEXT DEFAULT '{}'", "aux_models"),
    ):
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col}")
        except Exception:
            _ = ddl  # Spalte existiert bereits
    # Passkeys (WebAuthn, v0.0.228)
    conn.execute("""CREATE TABLE IF NOT EXISTS passkeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_id TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER DEFAULT 0,
        device_name TEXT,
        transports TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_used_at TEXT
    )""")
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
    hermes_auth = encrypt_secret(f"{hermes_user}:{hermes_pass}") if hermes_user else None
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


def _safe_json(raw):
    """Kaputtes/invalides JSON in der DB -> {} statt 500."""
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else {}
    except Exception:
        return {}


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def user_hermes_info(user: dict) -> dict:
    """Hermes-Status eines Benutzers (URL getrennt von Auth, damit das Frontend
    genau sagen kann, was fehlt)."""
    auth = decrypt_secret(user.get("hermes_auth") or "")
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
        # v0.0.234: Modell & Reasoning (pro Benutzer, session.create-Overrides)
        "model": user.get("model") or "",
        "provider": user.get("provider") or "",
        "reasoning_effort": user.get("reasoning_effort") or "",
        "fast_mode": user.get("fast_mode") or "",
        "aux_models": _safe_json(user.get("aux_models") or "{}"),
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
    # Zugangsdaten-Verschlüsselung: Altbestand automatisch konvertieren
    migrate_hermes_auth_encryption()
    yield

app = FastAPI(title="Atlas", lifespan=lifespan)


def get_today_usage(user_id):
    """Summierte Token-Werte des heutigen Tages für einen User."""
    today = datetime.now().strftime('%Y-%m-%d')
    db_conn = get_db()
    row = db_conn.execute(
        'SELECT SUM(input_tokens), SUM(output_tokens), SUM(total_tokens), SUM(cost) FROM usage_records WHERE user_id = ? AND date(recorded_at) = ?',
        (user_id, today)
    ).fetchone()
    db_conn.close()
    return {
        'input_tokens': row[0] or 0,
        'output_tokens': row[1] or 0,
        'total_tokens': row[2] or 0,
        'cost': (row[3] if row else 0) or 0,
        'date': today,
    }


# ---------------------------------------------------------------- Usage-Tracking API (v0.0.77)
@app.get('/api/usage/today')
async def api_usage_today(request: Request):
    """Kumulierte Token-Kosten der letzten 24h."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({'status': 'error'}, status_code=401)
    usage = get_today_usage(user['user_id'])
    return JSONResponse({'status': 'ok', **usage})


@app.post('/api/usage/reset')
async def api_usage_reset(request: Request):
    """Setzt Usage-Counter zurück (nur Admin).

    Löscht die heutigen usage_records UND sämtliche usage_last-Baselines.
    Nach einem Update mit geänderter Delta-Semantik (z. B. v0.0.87:
    prompt/completion statt input/output) müssen die Baselines weg,
    sonst werden falsche Deltas gegen Altwerte gerechnet.
    """
    user = session_from_request(request)
    if not user:
        return JSONResponse({'status': 'error', 'message': 'Nicht angemeldet'}, status_code=401)
    db_user = get_user_by_id(user['user_id'])
    if not db_user or not db_user['is_admin']:
        return JSONResponse({'status': 'error', 'message': 'Nicht autorisiert'}, status_code=403)
    conn = get_db()
    conn.execute("DELETE FROM usage_records WHERE date(recorded_at) = date('now', 'localtime')")
    conn.execute("DELETE FROM usage_last")
    conn.commit()
    conn.close()
    return JSONResponse({'status': 'ok'})


def get_today_usage_by_model(user_id):
    """Summierte Token-Werte pro Modell des heutigen Tages für einen User."""
    today = datetime.now().strftime('%Y-%m-%d')
    db_conn = get_db()
    rows = db_conn.execute(
        'SELECT model, '
        '       SUM(input_tokens), SUM(output_tokens), SUM(total_tokens), SUM(cost) '
        'FROM usage_records '
        'WHERE user_id = ? AND date(recorded_at) = ? '
        'GROUP BY model '
        'ORDER BY SUM(total_tokens) DESC',
        (user_id, today)
    ).fetchall()
    models = []
    for row in rows:
        model = row[0] or 'unbekannt'
        models.append({
            'model': model,
            'model_short': model.split('/')[-1] if '/' in model else model,
            'input_tokens': row[1] or 0,
            'output_tokens': row[2] or 0,
            'total_tokens': row[3] or 0,
            'cost': (row[4] if row[4] else 0) or 0,
        })
    # Gesamtsumme
    totals = db_conn.execute(
        'SELECT SUM(input_tokens), SUM(output_tokens), SUM(total_tokens), SUM(cost) '
        'FROM usage_records WHERE user_id = ? AND date(recorded_at) = ?',
        (user_id, today)
    ).fetchone()
    db_conn.close()
    return {
        'models': models,
        'total_tokens': totals[2] or 0,
        'total_input': totals[0] or 0,
        'total_output': totals[1] or 0,
        'total_cost': (totals[3] if totals[3] else 0) or 0,
        'date': today,
    }


def get_last_model(user_id):
    """Aktuellstes Modell des heutigen Tages."""
    today = datetime.now().strftime('%Y-%m-%d')
    db_conn = get_db()
    row = db_conn.execute(
        'SELECT model FROM usage_records '
        'WHERE user_id = ? AND date(recorded_at) = ? '
        'ORDER BY id DESC LIMIT 1',
        (user_id, today)
    ).fetchone()
    db_conn.close()
    return (row[0] or '') if row else ''


# ---------------------------------------------------------------- Model-aware usage API (v0.0.90)
@app.get('/api/usage/today/all')
async def api_usage_today_all(request: Request):
    """Modellgetrennte Token-Anzeige des heutigen Tages."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({'status': 'error'}, status_code=401)
    data = get_today_usage_by_model(user['user_id'])
    return JSONResponse({'status': 'ok', **data})


@app.get('/api/usage/current-model')
async def api_usage_current_model(request: Request):
    """Aktuellstes Modell des heutigen Tages."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({'status': 'error'}, status_code=401)
    model = get_last_model(user['user_id'])
    return JSONResponse({'status': 'ok', 'model': model})


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
    resp = templates.TemplateResponse(
        "index.html",
        {"request": request, "setup_mode": user_count() == 0,
         "BUILD_VERSION": os.environ.get("APP_VERSION", "unknown"),
         "BUILD_DATE": os.environ.get("BUILD_DATE", "unknown")}
    )
    # v0.0.167: index.html NIE aus dem Browser-Cache ausliefern — fehlende
    # Cache-Header führten zu heuristischem Caching (iOS-PWA: alte Version
    # nach Deploy, Nutzer-Befund „Tools verschwinden + Reasoning als normale
    # Messages“ trotz aktuellem Server-Code).
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


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
        "passkey_enabled": _passkey_enabled(),
    })


@app.get("/api/profiles")
async def api_profiles(request: Request):
    """Listet Profile der hinterlegten Hermes-Instanz."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_auth = decrypt_secret(db_user.get("hermes_auth") or "")
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
        new_auth = f"{hermes_user}:{hermes_pass}"  # Klartext vom User → wird gleich encrypted
    else:
        new_auth = db_user["hermes_auth"] if hermes_url else None
    new_auth = encrypt_secret(new_auth) if new_auth else None
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
    # v0.0.236: Modell-Felder (model/provider/reasoning_effort/fast_mode) liegen NICHT mehr in der DB —
    # die Profil-Config (config.yaml) ist die Wahrheit, siehe POST /api/profile/models.

    if sets:
        sql = f"UPDATE users SET {', '.join(sets)} WHERE id = ?"
        values.append(user["user_id"])
        conn.execute(sql, values)
        conn.commit()
    conn.close()

    # Nach dem Speichern: Verbindung sofort testen, damit der Nutzer weiß, ob es klappt
    if hermes_url and new_auth:
        test, detail = await test_hermes_connection(hermes_url, decrypt_secret(new_auth))
    else:
        test, detail = ("missing", "Benutzer und Passwort fehlen")
    return JSONResponse({"status": "ok", "test": test, "test_error": detail})


# ---------------------------------------------------------------- Modell & Reasoning (v0.0.234)

AUX_TASKS = ("vision", "web_extract", "compression", "skills_hub", "approval", "mcp", "title_generation", "triage_specifier", "kanban_decomposer", "profile_describer", "curator")
AUX_LABELS = {"vision": "Vision (Bilder)", "web_extract": "Web-Extraktion", "compression": "Komprimierung",
              "skills_hub": "Skills-Hub", "approval": "Genehmigungen", "mcp": "MCP",
              "title_generation": "Titel-Generierung", "triage_specifier": "Triage",
              "kanban_decomposer": "Kanban-Zerlegung", "profile_describer": "Profil-Beschreibung",
              "curator": "Curator"}


def _hermes_aux_config_path(profile: str = ""):
    """Pfad zur Hermes-config.yaml des PROFILS (pro Profil konfigurierbar, wie Desktop-App).

    Priorität: ATLAS_HERMES_CONFIG_PATH (fester Pfad) > ATLAS_HERMES_CONFIG_DIR/<profil>/config.yaml.
    """
    fixed = os.environ.get("ATLAS_HERMES_CONFIG_PATH", "").strip()
    if fixed:
        return fixed or None
    base = os.environ.get("ATLAS_HERMES_CONFIG_DIR", "").strip()
    if not base or not profile:
        return None
    prof = profile.strip()
    if not prof or re.search(r"[/\\]|\.\.", prof):
        return None
    return os.path.join(base, prof, "config.yaml")


def _yq(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _write_hermes_aux(aux: dict, profile: str = ""):
    """Schreibt auxiliary.* in die Hermes-config.yaml des Profils (Text-Patch, Kommentare bleiben).

    aux: {task: model} — nur AUX_TASKS-Keys; leerer String entfernt das Override (provider: auto).
    Rückgabe: (ok, message)
    """
    path = _hermes_aux_config_path(profile)
    if not path:
        return False, "Kein Hermes-Config-Zugriff konfiguriert (ATLAS_HERMES_CONFIG_PATH oder ATLAS_HERMES_CONFIG_DIR + Hermes-Profil nötig)"
    if not os.path.exists(path):
        return False, f"Hermes-Config nicht gefunden: {path}"
    clean = {}
    for k, v in aux.items():
        if k not in AUX_TASKS:
            continue
        if isinstance(v, dict):
            clean[k] = {"provider": str(v.get("provider") or "auto").strip() or "auto",
                        "model": str(v.get("model") or "").strip()}
        else:
            clean[k] = {"provider": "custom", "model": str(v).strip() if v is not None else ""}
    # Migration: altes 'title_gen'-Override -> title_generation übernehmen
    if "title_gen" in aux and clean.get("title_generation", {}).get("model", None) == "":
        old = aux["title_gen"]
        clean["title_generation"] = {"provider": "custom", "model": str(old or "").strip()}
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    block = ["auxiliary:"]
    for task in AUX_TASKS:
        entry = clean.get(task)
        if entry and entry["model"]:
            block.append(f"  {task}: {{provider: {_yq(entry['provider'])}, model: {_yq(entry['model'])}}}")
        else:
            block.append(f"  {task}: {{provider: auto, model: ''}}")
    idx = None
    for i, ln in enumerate(lines):
        if ln.strip() == "auxiliary:" and not ln[:1].isspace():
            idx = i
            break
    if idx is not None:
        end = idx + 1
        while end < len(lines) and (lines[end].strip() == "" or lines[end][:1].isspace()):
            end += 1
        out = lines[:idx] + block + lines[end:]
    else:
        out = lines + [""] + block
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out).rstrip() + "\n")
    return True, f"Hermes-Config aktualisiert ({', '.join(AUX_LABELS[k] for k in clean if clean[k]) or 'alle auf auto'})"


@app.post("/api/profile/aux")
async def api_profile_aux(request: Request, aux: str = Form("{}")):
    """Admin-only: Auxiliary-Models für das EIGENE Hermes-Profil setzen (wie Desktop-App).

    Hermes konfiguriert Auxiliary-Models PRO PROFIL (config.yaml des Profils). Atlas
    schreibt in die Config des Hermes-Profils, das in den Benutzer-Einstellungen steht.
    Erfordert ATLAS_HERMES_CONFIG_PATH oder ATLAS_HERMES_CONFIG_DIR + gesetztes Profil.
    """
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    # is_admin kommt NICHT aus der Session (nur user_id/username) — aus der DB laden
    db_user = get_user_by_id(user["user_id"]) or {}
    if not db_user.get("is_admin"):
        return JSONResponse({"status": "error", "message": "Nur Admins dürfen Auxiliary-Models ändern"}, status_code=403)
    try:
        parsed = json.loads(aux or "{}")
    except Exception:
        return JSONResponse({"status": "error", "message": "aux muss ein JSON-Objekt sein"}, status_code=400)
    if not isinstance(parsed, dict):
        return JSONResponse({"status": "error", "message": "aux muss ein JSON-Objekt sein"}, status_code=400)
    # v0.0.235: Werte dürfen {provider, model}-Paare sein (Dropdown-Auswahl) ODER Strings (alt)
    normalized = {}
    for k, v in parsed.items():
        if k not in AUX_TASKS:
            continue
        if isinstance(v, dict):
            normalized[k] = {"provider": str(v.get("provider") or "auto").strip() or "auto",
                             "model": str(v.get("model") or "").strip()}
        else:
            normalized[k] = str(v).strip()
    parsed = normalized
    profile = (db_user.get("hermes_profile") or "")
    ok, msg = _write_hermes_aux(parsed, profile)
    conn = get_db()
    conn.execute("UPDATE users SET aux_models = ? WHERE id = ?", (json.dumps(parsed), user["user_id"]))
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "profile": profile, "config_written": ok, "config_message": msg, "aux": parsed})


# ---------------------------------------------------------------- Modell-Katalog (v0.0.235) + Profil-Modelle (v0.0.236)

MAIN_FIELDS = ("model", "provider", "reasoning_effort", "fast_mode")


def _parse_config_main(path):
    """Liest Hauptmodell/Provider/Reasoning/Schnellmodus + auxiliary aus der HERMES-Profil-config (Text).

    Die config.yaml des Hermes-Profils ist die Quelle (wie Desktop-App): das
    top-level 'model:'-MAPPING (eingerückte provider/default) bzw. ältere
    Flach-Formen (top-level 'model:' als String + 'provider:') UND ein
    'auxiliary:'-Block mit 11 Tasks.
    v0.0.241: NUR Top-Level-Zeilen zählen als Konfigurationswerte — eingerückte
    (untergeordnete, z. B. 'memory: ... provider: holographic') Zeilen werden
    niemals als Hauptmodell gelesen (vorher überschrieb der Gedächtnis-Provider
    'holographic' das echte Hauptmodell; letzter Treffer gewann).
    Rückgabe: (main-dict mit leeren Defaults, aux-dict {task: {provider, model}}).
    """
    main = {"model": "", "provider": "", "reasoning_effort": "", "fast_mode": ""}
    aux = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return main, aux
    in_model_block = False
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            if not s:
                in_model_block = False
            continue
        if ln[:1].isspace():
            # Nur die Kinder eines top-level 'model:'-Blocks (provider/default) zählen.
            if in_model_block:
                m = re.match(r'^(provider|default):\s*(.*?)\s*$', s)
                if m:
                    v = m.group(2).strip().strip('"').strip("'")
                    main["provider" if m.group(1) == "provider" else "model"] = v
            continue
        in_model_block = False
        m = re.match(r'^(model|provider|reasoning_effort|fast_mode):\s*(.*?)\s*$', s)
        if m:
            v = m.group(2).strip().strip('"').strip("'")
            main[m.group(1)] = v
            if m.group(1) == "model" and v == "":
                in_model_block = True
            continue
        m2 = re.match(r'^([a-z_0-9]+):\s*\{provider:\s*(.+?),\s*model:\s*(.*?)\s*\}\s*$', s)
        if m2 and m2.group(1) in AUX_TASKS:
            pv = m2.group(2).strip().strip('"').strip("'")
            mv = m2.group(3).strip().strip('"').strip("'")
            aux[m2.group(1)] = {"provider": pv or "auto", "model": mv}
    return main, aux


def _write_hermes_main(main: dict, profile: str = ""):
    """Schreibt Hauptmodell/Provider/Reasoning/Schnellmodus in die config.yaml des Profils.

    v0.0.241: model/provider wandern in den top-level 'model:'-BLOCK (eingerückt als
    'provider:' + 'default:') — das native Hermes-Format, das auch die Profil-config.yaml
    und die Desktop-App verwenden. Vorher schrieb Atlas top-level 'model:'/'provider:'
    als Flach-Strings: Der bestehende 'model:'-Block wurde dabei zerstört (seine
    eingerückten Zeilen blieben als YAML-Waisen hängen — Muster in
    config.yaml.corrupt.20260830-163119.bak) und das top-level 'provider:' liest Hermes
    nicht als Hauptmodell-Provider. Ein vorhandener kaputter Alt-Bestand wird dabei
    geheilt. reasoning_effort/fast_mode bleiben top-level (Hermes-Format).
    Leere Werte LÖSCHEN die Zeilen („Standard" = Hermes-Default); Reset entfernt den
    ganzen model:-Block. Rückgabe: (ok, message)
    """
    path = _hermes_aux_config_path(profile)
    if not path:
        return False, "Kein Hermes-Config-Zugriff konfiguriert (ATLAS_HERMES_CONFIG_PATH oder ATLAS_HERMES_CONFIG_DIR + Hermes-Profil nötig)"
    if not os.path.exists(path):
        return False, f"Hermes-Config nicht gefunden: {path}"
    clean = {k: str(main.get(k) or "").strip() for k in MAIN_FIELDS if k in main}
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    idx = None
    for i, ln in enumerate(lines):
        if ln.strip() == "auxiliary:" and not ln[:1].isspace():
            idx = i
            break
    head = lines[:idx] if idx is not None else lines
    tail = lines[idx:] if idx is not None else []

    kept = head
    new_block = None
    block_start = None
    if "provider" in clean or "model" in clean:
        # Alten model:-Block lokalisieren (Header MIT evtl. Alt-String + eingerückte Zeilen)
        block_start = None
        block_end = None
        for i, ln in enumerate(head):
            stripped = ln.strip()
            if not stripped or ln[:1].isspace():
                continue
            if re.match(r'^model:', ln):
                block_start = i
                break
        if block_start is not None:
            block_end = block_start + 1
            while block_end < len(head) and (head[block_end].strip() == "" or head[block_end][:1].isspace()):
                block_end += 1
        # Alle top-level model:/provider:-Zeilen + den alten Block entfernen
        drop = set()
        for i, ln in enumerate(head):
            if ln.strip() and not ln[:1].isspace() and re.match(r'^(model|provider):', ln):
                drop.add(i)
        if block_start is not None and block_end is not None:
            drop.update(range(block_start, block_end))
        kept = [ln for i, ln in enumerate(head) if i not in drop]
        kids = []
        if clean.get("provider"):
            kids.append(f"  provider: {_yq(clean['provider'])}")
        if clean.get("model"):
            kids.append(f"  default: {_yq(clean['model'])}")
        if block_start is not None and not kids:
            new_block = None  # Reset: Block komplett entfernen (Hermes-Default)
        elif block_start is not None or kids:
            new_block = ["model:"] + kids

    out = []
    replaced_top = set()
    for ln in kept:
        m = re.match(r'^(reasoning_effort|fast_mode):\s*(.*)$', ln)
        if m and m.group(1) in clean:
            if clean[m.group(1)]:
                out.append(f"{m.group(1)}: {_yq(clean[m.group(1)])}")
            replaced_top.add(m.group(1))
        else:
            out.append(ln)
    if new_block:
        out += new_block
    for k in ("reasoning_effort", "fast_mode"):
        if k in clean and k not in replaced_top and clean[k]:
            out.append(f"{k}: {_yq(clean[k])}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out + tail).rstrip() + "\n")
    done = ", ".join(f"{k}={v or 'Standard'}" for k, v in clean.items())
    return True, f"Hermes-Config aktualisiert ({done})"


@app.get("/api/profile/models")
async def api_profile_models_get(request: Request):
    """Ist-Zustand der Modell-Einstellungen des USER-Hermes-Profils (config.yaml), wie Desktop-App."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    profile = db_user.get("hermes_profile") or ""
    path = _hermes_aux_config_path(profile)
    if not path or not os.path.exists(path):
        # v0.0.237: DB-Fallback, wenn der Container keinen Hermes-Config-Zugriff hat
        # (ATLAS_HERMES_CONFIG_PATH/DIR nicht gesetzt) — zuletzt gespeicherte Werte
        # aus der Atlas-DB zurueckgeben, damit die UI die Auswahl nicht zuruecksetzt.
        # v0.0.239: auch wenn der Pfad GESETZT ist, die Datei aber nicht existiert
        # (fehlender Mount im Container) — sonst liest GET eine leere Config und das
        # Hauptmodell wirkt "nicht gespeichert".
        dbv = get_user_by_id(user["user_id"]) or {}
        main = {
            "model": dbv.get("model") or "",
            "provider": dbv.get("provider") or "",
            "reasoning_effort": dbv.get("reasoning_effort") or "",
            "fast_mode": dbv.get("fast_mode") or "",
        }
        aux = {}
        try:
            aux = json.loads(dbv.get("aux_models") or "{}")
        except Exception:
            aux = {}
        if not isinstance(aux, dict):
            aux = {}
        return JSONResponse({"status": "ok", "profile": profile, "config_access": False,
                             "fallback": "db", "main": main, "aux": aux})
    main, aux = _parse_config_main(path)
    return JSONResponse({"status": "ok", "profile": profile, "config_access": True, "main": main, "aux": aux})


@app.post("/api/profile/models")
async def api_profile_models_save(request: Request,
                                  main_provider: str = Form(None),
                                  main_model: str = Form(None),
                                  reasoning_effort: str = Form(None),
                                  fast_mode: str = Form(None),
                                  aux: str = Form(None),
                                  scope: str = Form("main")):
    """Modell-Einstellungen fuer das EIGENE Hermes-Profil setzen (jeder eingeloggte User, wie Desktop-App).

    Jeder Bereich (Hauptmodell, Reasoning, Schnellmodus, Auxiliary) hat seinen eigenen
    Speichern-Button -> der POST traegt `scope` (main|reasoning|fast|aux) und schreibt NUR
    seinen Bereich in die config.yaml des Hermes-Profils (Text-Patch). Leere Werte = Standard
    (Zeile entfernen / auxiliary auf auto). Alte Benutzer-Overrides (DB, v0.0.234) werden geleert.
    """
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    profile = db_user.get("hermes_profile") or ""
    scope = (scope or "").strip()
    if scope not in ("main", "reasoning", "fast", "aux"):
        return JSONResponse({"status": "error", "message": "Ungültiger scope"}, status_code=400)
    partial = {}
    parsed_aux = None
    if scope == "main":
        partial["provider"] = (main_provider or "").strip()
        partial["model"] = (main_model or "").strip()
    elif scope == "reasoning":
        v = (reasoning_effort or "").strip()
        if v not in ("", "none", "low", "medium", "high"):
            return JSONResponse({"status": "error", "message": "Ungültiger Reasoning-Effort"}, status_code=400)
        partial["reasoning_effort"] = v
    elif scope == "fast":
        v = (fast_mode or "").strip()
        if v not in ("", "normal", "fast"):
            return JSONResponse({"status": "error", "message": "Ungültiger Schnellmodus"}, status_code=400)
        partial["fast_mode"] = v
    elif scope == "aux":
        try:
            parsed_aux = json.loads(aux or "{}")
        except Exception:
            return JSONResponse({"status": "error", "message": "aux muss ein JSON-Objekt sein"}, status_code=400)
        if not isinstance(parsed_aux, dict):
            return JSONResponse({"status": "error", "message": "aux muss ein JSON-Objekt sein"}, status_code=400)
        normalized = {}
        for k, v in parsed_aux.items():
            if k not in AUX_TASKS:
                continue
            if isinstance(v, dict):
                normalized[k] = {"provider": str(v.get("provider") or "auto").strip() or "auto",
                                 "model": str(v.get("model") or "").strip()}
            else:
                normalized[k] = str(v).strip()
        parsed_aux = normalized
    if not partial and parsed_aux is None:
        return JSONResponse({"status": "error", "message": "Nichts zu speichern"}, status_code=400)
    path = _hermes_aux_config_path(profile)
    if not path:
        # v0.0.237: Kein Hermes-Config-Zugriff -> Atlas-DB als Fallback-Speicher.
        # So bleibt der Save persistent (UI setzt die Auswahl nicht zurueck) und die
        # Warnung macht transparent, dass die echte config.yaml nicht erreicht wurde.
        conn = get_db()
        if parsed_aux is not None:
            conn.execute("UPDATE users SET aux_models = ? WHERE id = ?",
                         (json.dumps(parsed_aux, ensure_ascii=False), user["user_id"]))
            hidden = {"model": "", "provider": "", "reasoning_effort": "", "fast_mode": ""}
        else:
            hidden = {}
            if "provider" in partial:
                hidden["provider"] = partial["provider"]
            if "model" in partial:
                hidden["model"] = partial["model"]
            if "reasoning_effort" in partial:
                hidden["reasoning_effort"] = partial["reasoning_effort"]
            if "fast_mode" in partial:
                hidden["fast_mode"] = partial["fast_mode"]
            conn.execute(
                "UPDATE users SET provider=?, model=?, reasoning_effort=?, fast_mode=? WHERE id = ?",
                (hidden.get("provider", ""), hidden.get("model", ""),
                 hidden.get("reasoning_effort", ""), hidden.get("fast_mode", ""),
                 user["user_id"]))
        conn.commit()
        conn.close()
        return JSONResponse({"status": "ok", "profile": profile, "main": partial, "aux": parsed_aux,
                             "config_written": False, "fallback": "db",
                             "config_message": "In Atlas-DB gespeichert (Fallback) — Hermes-config.yaml nicht erreichbar (ATLAS_HERMES_CONFIG_PATH oder ATLAS_HERMES_CONFIG_DIR + Profil setzen)"})
    ok1 = ok2 = True
    msg1 = msg2 = ""
    if partial:
        ok1, msg1 = _write_hermes_main(partial, profile)
    if parsed_aux is not None:
        ok2, msg2 = _write_hermes_aux(parsed_aux, profile)
    conn = get_db()
    if ok1 and ok2:
        # v0.0.236: Die Profil-Config ist die Wahrheit — alte Benutzer-Overrides leeren
        conn.execute("UPDATE users SET model='', provider='', reasoning_effort='', fast_mode='' WHERE id = ?",
                     (user["user_id"],))
        conn.commit()
        conn.close()
        return JSONResponse({"status": "ok", "profile": profile, "main": partial, "aux": parsed_aux,
                             "config_written": True,
                             "config_message": " | ".join(m for m in (msg1, msg2) if m)})
    # v0.0.239: Config-Schreiben fehlgeschlagen (z. B. ATLAS_HERMES_CONFIG_PATH gesetzt,
    # aber Datei existiert im Container nicht) -> DB-Fallback, damit der GET die
    # gespeicherten Werte zurueckliefert und die UI die Auswahl nicht zuruecksetzt.
    if parsed_aux is not None:
        conn.execute("UPDATE users SET aux_models = ? WHERE id = ?",
                     (json.dumps(parsed_aux, ensure_ascii=False), user["user_id"]))
        hidden = {"model": "", "provider": "", "reasoning_effort": "", "fast_mode": ""}
    else:
        hidden = {}
        if "provider" in partial:
            hidden["provider"] = partial["provider"]
        if "model" in partial:
            hidden["model"] = partial["model"]
        if "reasoning_effort" in partial:
            hidden["reasoning_effort"] = partial["reasoning_effort"]
        if "fast_mode" in partial:
            hidden["fast_mode"] = partial["fast_mode"]
    conn.execute(
        "UPDATE users SET provider=?, model=?, reasoning_effort=?, fast_mode=? WHERE id = ?",
        (hidden.get("provider", ""), hidden.get("model", ""),
         hidden.get("reasoning_effort", ""), hidden.get("fast_mode", ""),
         user["user_id"]))
    conn.commit()
    conn.close()
    cfg_msg = " | ".join(m for m in (msg1, msg2) if m)
    return JSONResponse({"status": "ok", "profile": profile, "main": partial, "aux": parsed_aux,
                         "config_written": False, "fallback": "db",
                         "config_message": f"In Atlas-DB gespeichert (Fallback — {cfg_msg})"})

# ---------------------------------------------------------------- Modell-Katalog (v0.0.235)

_catalog_cache = {}  # user_id -> (ts, {"providers": [...], "model": ..., "provider": ...})

def _catalog_cache_clear(all: bool = True):
    if all:
        _catalog_cache.clear()

@app.get("/api/model-catalog")
async def api_model_catalog(request: Request):
    """Verfügbare Provider+Modelle vom Hermes-Dashboard des eingeloggten Users (wie Desktop-App).

    Quelle: GET {hermes}/api/model/options?profile=<profil>&include_unconfigured=true.
    Bereinigt: nur slug/name/models/is_current/authenticated — KEINE URLs/Keys/Credentials.
    """
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    auth = decrypt_secret(db_user.get("hermes_auth") or "")
    auth_user, _, auth_pass = auth.partition(":") if auth else ("", "", "")
    info = user_hermes_info(db_user)
    if not info or not info.get("hermes_user"):
        return JSONResponse({"status": "error", "message": "Kein Hermes-Zugang konfiguriert"}, status_code=502)
    now = time.time()
    cached = _catalog_cache.get(user["user_id"])
    if cached and now - cached[0] < 180:
        return JSONResponse(cached[1])
    cookie = await hermes_login_cookie(info["hermes_url"], auth_user, auth_pass)
    if not cookie:
        return JSONResponse({"status": "error", "message": "Hermes-Anmeldung fehlgeschlagen"}, status_code=502)
    url = f"{info['hermes_url']}/api/model/options?profile={quote(info.get('hermes_profile') or '')}&include_unconfigured=true"
    try:
        async with ClientSession() as http:
            async with http.get(url, headers={"Cookie": cookie}, timeout=ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return JSONResponse({"status": "error", "message": f"Hermes-Katalog nicht erreichbar (HTTP {resp.status})"}, status_code=502)
                data = await resp.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Hermes-Katalog nicht erreichbar (Verbindungsfehler)"}, status_code=502)
    providers = []
    for row in data.get("providers") or []:
        models = [str(m) for m in (row.get("models") or [])]
        if not models and not row.get("is_current"):
            continue
        providers.append({
            "slug": str(row.get("slug") or ""),
            "name": str(row.get("name") or row.get("slug") or ""),
            "models": models,
            "is_current": bool(row.get("is_current")),
            "authenticated": bool(row.get("authenticated")),
        })
    payload = {"status": "ok", "providers": providers,
               "model": str(data.get("model") or ""), "provider": str(data.get("provider") or "")}
    _catalog_cache[user["user_id"]] = (now, payload)
    return JSONResponse(payload)


@app.get("/api/model-catalog/aux")
async def api_model_catalog_aux(request: Request):
    """Aktuelle Auxiliary-Zuweisungen des Hermes-Profils (Slots + Werte), wie Desktop-App."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    auth = decrypt_secret(db_user.get("hermes_auth") or "")
    auth_user, _, auth_pass = auth.partition(":") if auth else ("", "", "")
    info = user_hermes_info(db_user)
    if not info or not info.get("hermes_user"):
        return JSONResponse({"status": "error", "message": "Kein Hermes-Zugang konfiguriert"}, status_code=502)
    cookie = await hermes_login_cookie(info["hermes_url"], auth_user, auth_pass)
    if not cookie:
        return JSONResponse({"status": "error", "message": "Hermes-Anmeldung fehlgeschlagen"}, status_code=502)
    url = f"{info['hermes_url']}/api/model/auxiliary?profile={quote(info.get('hermes_profile') or '')}"
    try:
        async with ClientSession() as http:
            async with http.get(url, headers={"Cookie": cookie}, timeout=ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return JSONResponse({"status": "error", "message": f"Hermes-Aux nicht erreichbar (HTTP {resp.status})"}, status_code=502)
                data = await resp.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Hermes-Aux nicht erreichbar (Verbindungsfehler)"}, status_code=502)
    tasks = []
    seen = set()
    for t in (data.get("tasks") or []):
        task = str(t.get("task") or "")
        if not task or task in seen:
            continue
        seen.add(task)
        tasks.append({"task": task, "provider": str(t.get("provider") or ""), "model": str(t.get("model") or "")})
    main = data.get("main") or {}
    return JSONResponse({"status": "ok", "tasks": tasks,
                         "main": {"provider": str(main.get("provider") or ""), "model": str(main.get("model") or "")}})


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
    wa = _webauthn_config()
    return JSONResponse({"status": "ok", "allow_registration": allow_reg, "require_2fa": require_2fa,
                         "webauthn_rp_id": wa["rp_id"], "webauthn_origin": wa["origin"]})


@app.post("/api/admin/settings")
async def admin_settings_save(request: Request,
                              allow_registration: str = Form("0"),
                              require_2fa: str = Form("0"),
                              webauthn_rp_id: str = Form(""),
                              webauthn_origin: str = Form("")):
    if not is_admin_request(request):
        return JSONResponse({"status": "error", "message": "Nur für Admins"}, status_code=403)
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('allow_registration', ?)", (allow_registration,))
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('require_2fa', ?)", (require_2fa,))
    for key, val in (("webauthn_rp_id", webauthn_rp_id.strip()),
                     ("webauthn_origin", webauthn_origin.strip())):
        if val:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, val))
        else:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))
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

@app.delete("/api/sessions/{stored_session_id}")
async def api_delete_session(stored_session_id: str, request: Request):
    """Löscht eine Session in Hermes (session.delete RPC) — nur wenn die aktuelle Session NICHT gelöscht wird."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_url = db_user.get("hermes_url")
    hermes_auth = decrypt_secret(db_user.get("hermes_auth"))
    if not hermes_url or not hermes_auth:
        return JSONResponse({"status": "error", "message": "Keine Hermes-Verbindung konfiguriert"}, status_code=400)

    profile = db_user.get("hermes_profile") or ""
    # v0.0.151-FIX: session.delete braucht profile — OHNE sucht Hermes im
    # Default-Profil und antwortet 4007 'session not found' (live per WS-Probe
    # verifiziert: mit profile + Ziel-Session inaktiv → {"deleted": ...}).
    # hermes_ws_request's Zwischen-Session (close_on_disconnect=True) ist hier
    # harmlos — sie blockiert nur ihr eigenes Löschen, nicht das der Ziel-Session.
    result = await hermes_ws_request(hermes_url, hermes_auth, "session.delete",
                                     {"session_id": stored_session_id, "profile": profile}, profile)
    deleted = result.get("deleted")
    if not deleted:
        # v0.0.213: Hermes blockt session.delete (4023 „cannot delete an active
        # session“) ~20 s, solange die Session noch im Gateway-Cache steht — live
        # gemessen am 29.08.: selbst nach session.interrupt + Verbindungsende
        # (Frontend macht beides vor dem DELETE) dauert der Orphan-Reap ~20 s.
        # Deshalb hier geduldig pollen (1,5-s-Takt, max. 30 s) statt 1-s-Retry.
        deadline = time.monotonic() + 30
        while not deleted and time.monotonic() < deadline:
            await asyncio.sleep(1.5)
            result = await hermes_ws_request(hermes_url, hermes_auth, "session.delete",
                                             {"session_id": stored_session_id, "profile": profile}, profile)
            deleted = result.get("deleted")
    if not deleted:
        # hermes_ws_request liefert {} wenn der Antwort-Frame ein error war (nur
        # 'result'-Frames werden gespeichert). Genauer Grund unbekannt → generisch melden.
        return JSONResponse({"status": "error", "message": "session.delete fehlgeschlagen — Session existiert nicht oder ist gerade aktiv (live im Chat)"}, status_code=404)
    return JSONResponse({"status": "ok", "message": "Session gelöscht", "deleted": deleted})


@app.get("/api/sessions")
async def api_sessions(request: Request):
    """Listet alle Sessions des eingestellten Hermes-Profils (session.list via WS)."""
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet"}, status_code=401)
    db_user = get_user_by_id(user["user_id"]) or {}
    hermes_url = db_user.get("hermes_url")
    hermes_auth = decrypt_secret(db_user.get("hermes_auth"))
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
    """Lädt die Datei VOLLSTÄNDIG von der Hermes-Proxy-URL.

    Gibt (status, content_type, bytes) zurück — der Status wird geprüft,
    damit Fehler von Hermes nicht als „erfolgreicher“ 200-Download mit
    kaputtem Body beim Nutzer ankommen.

    WICHTIG (v0.0.67-Fix): Vorher wurde ein LAZY Chunk-Generator zurückgegeben,
    dessen `async with http.get(...)`-Kontext bereits geschlossen war, sobald
    file_generator() zurückkehrte. StreamingResponse konsumierte den Generator
    erst danach → die Hermes-Verbindung war zu, der Stream brach mitten in der
    Datei ab (IncompleteRead) → Downloads ankamen abgeschnitten/korrupt
    („Acrobat Reader: Datei ist fehlerhaft“). Jetzt wird die Datei komplett
    in den Speicher geladen und als fertige Bytes zurückgegeben — für
    Agenten-Dateien (PDFs, Bilder, Dokumente) völlig ausreichend.
    """
    try:
        async with http.get(url, headers=headers, timeout=ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                print(f"[FileProxy] Hermes-Status {resp.status} für {url}")
                return resp.status, "text/plain", b""
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            data = await resp.read()
            print(f"[FileProxy] OK: {len(data)} Bytes ({url})")
            return resp.status, content_type, data
    except Exception as e:
        print(f"[FileProxy] Download error: {e}")
        return 502, "text/plain", b""


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
    hermes_auth = decrypt_secret(db_user.get("hermes_auth") or "")
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
        status, content_type, data = await file_generator(http, proxy_url, headers)
        if status != 200:
            raise HTTPException(status_code=status, detail="Hermes-Download fehlgeschlagen")
        # v0.0.191 (F46): inline=1 → Content-Disposition:inline statt attachment,
        # damit Bilder (<img>) und PDFs (<iframe>) INLINE im App-Overlay angezeigt
        # werden können (iPhone: keinen neuen Tab öffnen, sonst lässt sich der
        # geöffnete Download-Tab in der PWA/Standalone nicht schließen).
        inline = request.query_params.get("inline", "") == "1"
        disposition_kind = "inline" if inline else "attachment"
        return Response(
            content=data,
            media_type=content_type,
            headers={"Content-Disposition": f'{disposition_kind}; filename="{path.split("/")[-1]}"'},
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


def _save_usage_snapshot(db_conn, user_id, session_id, model, usage_resp):
    """Speichert message.complete-Delta in usage_records (Einzelpfad v0.0.87).

    usage_resp kommt aus message.complete.payload.usage. WICHTIG: total, prompt
    und completion sind KUMULATIV über die Session-Lebensdauer; total =
    prompt + completion. Die Felder input/output sind dagegen TURN-Werte
    (nur der neue Anteil des letzten Turns) — sie dürfen NICHT als
    Delta-Basis verwendet werden, sonst gilt total != input + output.

    Delta-Basis: usage_last-Tabelle der Session (überlebt Neustarts).
    Falls kein Eintrag in usage_last existiert → kein Phantom-Delta,
    nur Baseline setzen (ansonsten würde ein Neustart mit alter Session
    den kumulierten Altstand als Verbrauch verbuchen).
    """
    if not usage_resp:
        return
    total = int(usage_resp.get('total', 0) or 0)
    if total <= 0:
        return
    out = int(usage_resp.get('completion', 0) or 0)
    inp = int(usage_resp.get('prompt', 0) or 0)
    if inp <= 0:
        inp = max(0, total - out)

    # Letzten gemeldeten Stand aus usage_last holen
    row = db_conn.execute(
        'SELECT total, input, output FROM usage_last WHERE session_id = ?',
        (session_id,)
    ).fetchone()
    if row:
        last_total, last_inp, last_out = row
        delta_total = max(0, total - last_total)
        delta_in = max(0, inp - last_inp)
        delta_out = max(0, out - last_out)
    else:
        # Erster Eintrag: nur Baseline setzen, kein Verbrauch buchen
        # (alte Session mit vielen Turns vor dem Update würde sonst
        # 100+ Mio Tokens als "Tagesverbrauch" verbuchen)
        delta_total = delta_in = delta_out = 0

    if delta_total > 0:
        db_conn.execute(
            'INSERT INTO usage_records (user_id, session_id, model, input_tokens, output_tokens, total_tokens, cost) VALUES (?, ?, ?, ?, ?, ?, 0)',
            (user_id, session_id, model or '', delta_in, delta_out, delta_total)
        )
        db_conn.commit()

    # Baseline aktualisieren (wird vom nächsten Turn als Delta-Basis verwendet)
    db_conn.execute(
        'INSERT OR REPLACE INTO usage_last (session_id, total, input, output) VALUES (?, ?, ?, ?)',
        (session_id, total, inp, out)
    )
    db_conn.commit()


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
    hermes_auth = decrypt_secret(db_user.get("hermes_auth"))
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
                    """Forward Hermes-Events + Usage-Delta nach message.complete speichern.
                    Delta-Basis ist die DB (letzte Buchung der Session), NICHT RAM —
                    nach Neustart/Reconnect zählt kein kumulierter Altbestand doppelt."""
                    try:
                        async for msg in hws:
                            if msg.type == WSMsgType.TEXT:
                                data = msg.data
                                # 1) Event immer an Client forwarden
                                await ws.send_text(data)
                                # 2) message.complete -> usage aus payload speichern
                                #    Struktur: {method: "event", params: {type: "message.complete",
                                #               session_id: ..., payload: {usage: {...}}}}
                                try:
                                    d = json.loads(data)
                                    if d.get('method') == 'event':
                                        params = d.get('params') or {}
                                        if params.get('type') == 'message.complete':
                                            sid = params.get('session_id', '')
                                            usage = (params.get('payload') or {}).get('usage') or {}
                                            if sid and usage:
                                                model = usage.get('model', '') or ''
                                                _save_usage_snapshot(
                                                    get_db(), session['user_id'],
                                                    sid, model, usage
                                                )
                                                print(f"[WS-Proxy] usage saved: {sid[:12]}... delta-total laut DB (model: {model})")
                                except json.JSONDecodeError:
                                    pass
                                except Exception as e:
                                    print(f"[WS-Proxy] usage parse error: {e}")
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

# ---------------------------------------------------------------- Passkeys / WebAuthn (v0.0.228)
# Port aus Starface-WebApp (F58): Keepass/KeepassXC, Bitwarden, Windows Hello, iCloud-Keychain,
# iOS Face ID — identische Kompatibilitäts-Fixes (DER/RAW-Signaturen, resident+UV required).


@app.post("/api/passkey/login/options")
async def passkey_login_options():
    if not _passkey_enabled():
        return JSONResponse({"status": "error", "message": "Passkeys sind nicht konfiguriert."}, status_code=503)
    _clean_pending_passkey()
    server = _fido2_server()
    challenge = secrets.token_bytes(32)
    _options, state = server.authenticate_begin(user_verification="required", challenge=challenge)
    PENDING_PASSKEY[state["challenge"]] = {
        "state": state,
        "user_id": None,
        "expires": time.time() + PENDING_PASSKEY_TTL,
    }
    return JSONResponse({
        "challenge": state["challenge"],
        "rpId": _webauthn_config()["rp_id"],
        "userVerification": "required",
        "timeout": 180000,
    })


@app.post("/api/passkey/login/verify")
async def passkey_login_verify(request: Request):
    if not _passkey_enabled():
        return JSONResponse({"status": "error", "message": "Passkeys sind nicht konfiguriert."}, status_code=503)
    try:
        body = await request.json()
        credential = body.get("credential") or {}
        response = credential.get("response") or {}
        if not isinstance(response, dict) or not response.get("clientDataJSON"):
            print(f"[Passkey] Login: response ohne clientDataJSON — response-Keys: {list(response.keys()) if isinstance(response, dict) else type(response).__name__}, credential-Keys: {list(credential.keys())}")
    except Exception:
        return JSONResponse({"status": "error", "message": "Ungültige Anfrage."}, status_code=400)

    try:
        challenge = json.loads(_b64u_decode(str(response.get("clientDataJSON", ""))))["challenge"]
        pend = PENDING_PASSKEY.get(challenge)
        if not pend or pend["expires"] < time.time():
            print("[Passkey] Login: challenge abgelaufen/unbekannt")
            return JSONResponse({"status": "error", "message": "Challenge abgelaufen oder unbekannt."}, status_code=401)
        PENDING_PASSKEY.pop(challenge, None)
        credential["response"]["signature"] = _raw_to_der_b64(response.get("signature", ""))

        db = get_db()
        try:
            row = db.execute(
                "SELECT user_id, public_key, sign_count FROM passkeys WHERE credential_id = ?",
                (_b64u(_b64u_decode(str(credential.get("rawId", "")))),),
            ).fetchone()
        finally:
            db.close()
        if not row:
            print("[Passkey] Login: row nicht gefunden (credential_id nicht registriert)")
            return JSONResponse({"status": "error", "message": "Kein Passkey für dieses Gerät registriert."}, status_code=401)
        cred_id = _b64u_decode(str(credential.get("rawId", "")))
        # Signatur RAW(r||s) → DER normalisieren (Chrome/Windows raw, Bitwarden/Keepass DER)
        credential["response"]["signature"] = _raw_to_der_b64(response.get("signature", ""))
        pk_cbor = _b64u_decode(row["public_key"])
        acd = AttestedCredentialData(b"\x00" * 16 + len(cred_id).to_bytes(2, "big") + cred_id + pk_cbor)

        server = _fido2_server()
        server.authenticate_complete(pend["state"], [acd], credential)

        from fido2.webauthn import AuthenticationResponse
        new_count = AuthenticationResponse.from_dict(credential).response.authenticator_data.counter
        if new_count > 0 and row["sign_count"] > 0 and new_count <= row["sign_count"]:
            return JSONResponse({"status": "error", "message": "Passkey-Wiederverwendung erkannt."}, status_code=401)

        db_user = get_user_by_id(row["user_id"])
        if not db_user:
            return JSONResponse({"status": "error", "message": "Benutzer existiert nicht mehr."}, status_code=401)
        if not db_user.get("is_active"):
            return JSONResponse({"status": "error", "message": "Dein Konto ist deaktiviert"}, status_code=403)
        conn = get_db()
        try:
            conn.execute(
                "UPDATE passkeys SET sign_count = ?, last_used_at = datetime('now') WHERE credential_id = ?",
                (new_count, _b64u(cred_id)),
            )
            conn.commit()
        finally:
            conn.close()
        sid = start_session(db_user)
        resp = JSONResponse({"status": "ok", "is_admin": bool(db_user.get("is_admin"))})
        resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="lax")
        return resp
    except ValueError:
        print("[Passkey] Login-Verify: ValueError")
        return JSONResponse({"status": "error", "message": "Passkey-Überprüfung fehlgeschlagen."}, status_code=401)
    except Exception:
        print("[Passkey] Login-Verify fehlgeschlagen")
        return JSONResponse({"status": "error", "message": "Passkey-Überprüfung fehlgeschlagen."}, status_code=401)


@app.post("/api/passkey/register/options")
async def passkey_register_options(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet."}, status_code=401)
    if not _passkey_enabled():
        return JSONResponse({"status": "error", "message": "Passkeys sind nicht konfiguriert."}, status_code=503)
    _clean_pending_passkey()
    server = _fido2_server()
    user_id_bytes = f"u{user['user_id']}".encode()
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id_bytes, name=user["username"], display_name=user["username"]
    )
    challenge = secrets.token_bytes(32)
    _options, state = server.register_begin(
        user_entity, challenge=challenge, resident_key_requirement="required",
        user_verification="required",
    )
    PENDING_PASSKEY[state["challenge"]] = {
        "state": state,
        "user_id": user["user_id"],
        "expires": time.time() + PENDING_PASSKEY_TTL,
    }
    return JSONResponse({
        "challenge": state["challenge"],
        "rp": {"id": _webauthn_config()["rp_id"], "name": _webauthn_config()["rp_name"]},
        "user": {
            "id": _b64u(user_id_bytes),
            "name": user["username"],
            "displayName": user["username"],
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
        "attestation": "none",
        "timeout": 180000,
    })


@app.post("/api/passkey/register/verify")
async def passkey_register_verify(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet."}, status_code=401)
    if not _passkey_enabled():
        return JSONResponse({"status": "error", "message": "Passkeys sind nicht konfiguriert."}, status_code=503)
    try:
        body = await request.json()
        credential = body.get("credential") or {}
        response = credential.get("response") or {}
        if not isinstance(response, dict) or not response.get("clientDataJSON"):
            print(f"[Passkey] Registrierung: response ohne clientDataJSON — response-Keys: {list(response.keys()) if isinstance(response, dict) else type(response).__name__}, credential-Keys: {list(credential.keys())}")
        device_name = (body.get("device_name") or "Unbenanntes Gerät").strip()[:60]
        challenge = json.loads(_b64u_decode(str(response.get("clientDataJSON", ""))))["challenge"]
        pend = PENDING_PASSKEY.get(challenge)
        if not pend or pend["expires"] < time.time() or pend["user_id"] != user["user_id"]:
            return JSONResponse({"status": "error", "message": "Challenge abgelaufen oder unbekannt."}, status_code=401)
        PENDING_PASSKEY.pop(challenge, None)

        server = _fido2_server()
        auth_data = server.register_complete(pend["state"], credential)
        cred_data = auth_data.credential_data
        try:
            pk_cbor = cred_data.public_key.cbor
        except AttributeError:
            pk_cbor = cbor2.dumps(cred_data.public_key)
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, device_name, transports) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user["user_id"], _b64u(cred_data.credential_id), _b64u(pk_cbor), auth_data.counter,
                 device_name, json.dumps(credential.get("transports") or [])),
            )
            conn.commit()
        finally:
            conn.close()
        return JSONResponse({"status": "ok", "credential_id": _b64u(cred_data.credential_id)})
    except ValueError:
        print("[Passkey] Registrierung abgelehnt (ValueError)")
        return JSONResponse({"status": "error", "message": "Registrierung fehlgeschlagen."}, status_code=400)
    except sqlite3.IntegrityError:
        print("[Passkey] Registrierung: Duplikat (IntegrityError)")
        return JSONResponse({"status": "error", "message": "Dieser Passkey ist bereits registriert."}, status_code=409)
    except Exception:
        print("[Passkey] Registrierung fehlgeschlagen")
        return JSONResponse({"status": "error", "message": "Registrierung fehlgeschlagen."}, status_code=400)


@app.get("/api/passkey/list")
async def passkey_list(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet."}, status_code=401)
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, device_name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY id",
            (user["user_id"],),
        ).fetchall()
    finally:
        db.close()
    return JSONResponse({"passkeys": [dict(r) for r in rows]})


@app.post("/api/passkey/delete")
async def passkey_delete(request: Request):
    user = session_from_request(request)
    if not user:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet."}, status_code=401)
    try:
        body = await request.json()
        pk_id = int(body.get("id") or 0)
    except Exception:
        return JSONResponse({"status": "error", "message": "Ungültige Anfrage."}, status_code=400)
    db = get_db()
    try:
        cur = db.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (pk_id, user["user_id"]))
        db.commit()
    finally:
        db.close()
    if cur.rowcount == 0:
        return JSONResponse({"status": "error", "message": "Passkey nicht gefunden."}, status_code=404)
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------- Admin-API (v0.0.228)
# Profil-Dropdown -> Administration: Benutzerverwaltung (nur is_admin).


def _require_admin(request: Request):
    """Gibt (db_user, 200) oder (None, 401/403) zurück."""
    user = session_from_request(request)
    if not user:
        return None, 401
    db_user = get_user_by_id(user["user_id"])
    if not db_user or not db_user.get("is_admin"):
        return None, 403
    return db_user, 200


# GET/POST /api/admin/users existieren bereits vor v0.0.228 (adminUsersModal, Z ~981)
# → hier nur die Mutations-Endpunkte role/active/password (neu in v0.0.228).


@app.post("/api/admin/users/{user_id}/role")
async def admin_user_role(user_id: int, request: Request):
    admin, err = _require_admin(request)
    if err != 200 or admin is None:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet oder keine Admin-Rechte."}, status_code=err)
    try:
        body = await request.json()
        is_admin = bool(body.get("is_admin"))
    except Exception:
        return JSONResponse({"status": "error", "message": "Ungültige Anfrage."}, status_code=400)
    if user_id == admin["id"] and not is_admin:
        return JSONResponse({"status": "error", "message": "Du kannst dir selbst die Admin-Rechte nicht entziehen."}, status_code=400)
    db = get_db()
    try:
        cur = db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if is_admin else 0, user_id))
        db.commit()
    finally:
        db.close()
    if cur.rowcount == 0:
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden."}, status_code=404)
    return JSONResponse({"status": "ok"})


@app.post("/api/admin/users/{user_id}/active")
async def admin_user_active(user_id: int, request: Request):
    admin, err = _require_admin(request)
    if err != 200 or admin is None:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet oder keine Admin-Rechte."}, status_code=err)
    try:
        body = await request.json()
        is_active = bool(body.get("is_active"))
    except Exception:
        return JSONResponse({"status": "error", "message": "Ungültige Anfrage."}, status_code=400)
    if user_id == admin["id"] and not is_active:
        return JSONResponse({"status": "error", "message": "Du kannst dich nicht selbst deaktivieren."}, status_code=400)
    db = get_db()
    try:
        cur = db.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
        db.commit()
    finally:
        db.close()
    if cur.rowcount == 0:
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden."}, status_code=404)
    return JSONResponse({"status": "ok"})


@app.post("/api/admin/users/{user_id}/password")
async def admin_user_password(user_id: int, request: Request):
    admin, err = _require_admin(request)
    if err != 200 or admin is None:
        return JSONResponse({"status": "error", "message": "Nicht angemeldet oder keine Admin-Rechte."}, status_code=err)
    try:
        body = await request.json()
        password = str(body.get("password") or "")
    except Exception:
        return JSONResponse({"status": "error", "message": "Ungültige Anfrage."}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"status": "error", "message": "Passwort braucht mindestens 6 Zeichen."}, status_code=400)
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    db = get_db()
    try:
        cur = db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))
        db.commit()
    finally:
        db.close()
    if cur.rowcount == 0:
        return JSONResponse({"status": "error", "message": "Benutzer nicht gefunden."}, status_code=404)
    return JSONResponse({"status": "ok", "message": "Passwort zurückgesetzt."})
