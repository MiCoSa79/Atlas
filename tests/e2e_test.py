#!/usr/bin/env python3
"""E2E-Test der Atlas-App (lokale Instanz auf Port 8899).

Simuliert den kompletten Nutzerfluss gegen die LOKALE App:
  GET /                 -> Setup-Modus?
  POST /api/setup       -> Admin + Hermes-Anbindung anlegen (echte Credentials aus env)
  GET /api/session      -> eingeloggt?
  WS /ws                -> session.create -> prompt.submit -> Events bis complete
  POST /api/logout      -> Session beendet
"""
import asyncio
import http.cookiejar
import json
import os
import sys
import urllib.request

import websockets

BASE = "http://127.0.0.1:8899"
WS_BASE = "ws://127.0.0.1:8899"
PROMPT = os.environ.get("ATLAS_TEST_PROMPT", "Hallo Atlas! Bist du da? Antworte mit einem einzigen kurzen Satz.")

HERMES_URL = os.environ.get("ATLAS_TEST_HERMES_URL", "http://127.0.0.1:9119")
HERMES_USER = os.environ["HERMES_DASHBOARD_BASIC_AUTH_USERNAME"]
HERMES_PASS = os.environ["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"]

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"


def post_form(path, fields, jar):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read() or b"{}"
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"message": body[:200].decode(errors="replace")}


def get_json(path, jar):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    with opener.open(f"{BASE}{path}", timeout=20) as r:
        return r.status, json.loads(r.read() or b"{}")


def main():
    failures = []
    jar = http.cookiejar.CookieJar()

    # 0) Leere DB -> Setup-Modus
    try:
        with urllib.request.urlopen(f"{BASE}/", timeout=20) as r:
            html = r.read().decode()
        ok = "setupForm" in html
        print("0) GET / zeigt Setup-Wizard:", "OK" if ok else "FEHLER")
        if not ok:
            failures.append("setup seite")
    except Exception as e:
        print("0) GET / FEHLER:", e)
        failures.append("setup seite")

    # 1) Setup: NUR Admin-Zugang (Hermes wird später im Profil eingerichtet)
    st, j = post_form("/api/setup", {
        "username": ADMIN_USER, "password": ADMIN_PASS,
    }, jar)
    print("1) POST /api/setup (nur Admin):", st, j.get("status"))
    if st != 200:
        failures.append("setup")

    # 2) Session-Cookie gesetzt?
    cookies = {c.name: c.value for c in jar}
    print("2) Session-Cookie:", "OK" if "atlas_session" in cookies else "FEHLER -> " + str(cookies))
    if "atlas_session" not in cookies:
        failures.append("cookie")

    # 3) Profil: Hermes-Instanz in den Einstellungen hinterlegen
    st, j = post_form("/api/profile", {
        "hermes_url": HERMES_URL, "hermes_user": HERMES_USER, "hermes_pass": HERMES_PASS,
    }, jar)
    print("3) POST /api/profile:", st, j.get("status"))
    if st != 200:
        failures.append("profile")

    # 4) /api/session -> eingeloggt + Hermes konfiguriert
    try:
        st, j = get_json("/api/session", jar)
        ok = j.get("logged_in") is True and j.get("hermes_configured") is True
        print("4) GET /api/session:", "OK" if ok else f"FEHLER -> {j}")
        if not ok:
            failures.append("session")
    except Exception as e:
        print("4) GET /api/session FEHLER:", e)
        failures.append("session")

    # 4) Websocket-Chat (der eigentliche Kern)
    async def chat():
        cookie_str = "; ".join(f"{c.name}={c.value}" for c in jar)
        headers = {"Cookie": cookie_str}
        async with websockets.connect(f"{WS_BASE}/ws", extra_headers=headers,
                                      max_size=None, open_timeout=15) as ws:
            rid = 0
            async def rpc(method, params):
                nonlocal rid
                rid += 1
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
                return rid
            await rpc("session.create", {"close_on_disconnect": True, "source": "e2e-test"})
            bubble, session_id, done = "", None, False
            events = []
            deadline = asyncio.get_event_loop().time() + 120
            while not done and asyncio.get_event_loop().time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=5)
                except asyncio.TimeoutError:
                    continue
                frame = json.loads(raw)
                if frame.get("id") == 1 and (frame.get("result") or {}).get("session_id"):
                    session_id = frame["result"]["session_id"]
                    print("5) session.create -> session_id ok")
                    await rpc("prompt.submit", {"session_id": session_id, "text": PROMPT})
                    continue
                if frame.get("method") != "event":
                    continue
                ev = frame.get("params") or {}
                etype, payload = ev.get("type"), ev.get("payload") or {}
                events.append(etype)
                if etype == "message.delta" and payload.get("text"):
                    bubble += payload["text"]
                elif etype == "message.complete":
                    done = True
                elif etype == "error":
                    print("5) HERMES-FEHLER:", payload.get("message"))
                    done, bubble = True, "FEHLER: " + payload.get("message", "")
            return session_id, bubble, events

    try:
        sid, answer, events = asyncio.run(chat())
        has_deltas = any(e == "message.delta" for e in events)
        has_complete = "message.complete" in events
        print("5) Events:", events[:12])
        print("6) Agent-Antwort:", (answer or "")[:200].replace("\n", " ⏎ "))
        if not (sid and has_deltas and has_complete and answer):
            failures.append("chat")
    except Exception as e:
        print("5) WS-Chat FEHLER:", type(e).__name__, e)
        failures.append("chat")

    # 7) Logout
    st, j = post_form("/api/logout", {}, jar)
    st, j = get_json("/api/session", jar)
    ok = j.get("logged_in") is False
    print("7) POST /api/logout -> session:", "OK" if ok else f"FEHLER -> {j}")
    if not ok:
        failures.append("logout")

    print("-" * 50)
    if failures:
        print("ERGEBNIS: FEHLGESCHLAGEN ->", ", ".join(failures))
        sys.exit(1)
    print("ERGEBNIS: ALLE TESTS BESTANDEN ✅")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402
    main()
