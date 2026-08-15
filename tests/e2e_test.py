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
HERMES_PROFILE = os.environ.get("ATLAS_TEST_HERMES_PROFILE", "")

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

    # 3) Profil: Hermes-Instanz in den Einstellungen hinterlegen (mit Verbindungstest)
    st, j = post_form("/api/profile", {
        "hermes_url": HERMES_URL, "hermes_user": HERMES_USER, "hermes_pass": HERMES_PASS,
    }, jar)
    ok = st == 200 and j.get("test") == "connected"
    print("3) POST /api/profile:", st, j.get("status"), "| Test:", j.get("test"), j.get("test_error") or "")
    if not ok:
        failures.append("profile")

    # 4) Profil als ausgewählt speichern
    if HERMES_PROFILE:
        st, j = post_form("/api/profile", {
            "hermes_url": HERMES_URL, "hermes_user": HERMES_USER, "hermes_pass": HERMES_PASS,
            "hermes_profile": HERMES_PROFILE,
        }, jar)
        ok = st == 200 and j.get("test") == "connected"
        print("4) POST /api/profile mit Profil:", st, j.get("status"), "| Test:", j.get("test"), j.get("test_error") or "")
        if not ok:
            failures.append("profile")
    else:
        print("4) Kein Profil-Test (ATLAS_TEST_HERMES_PROFILE leer)")

    # 5) /api/session -> eingeloggt + Hermes konfiguriert
    try:
        st, j = get_json("/api/session", jar)
        ok = j.get("logged_in") is True and j.get("hermes_configured") is True
        print("5) GET /api/session:", "OK" if ok else f"FEHLER -> {j}")
        if not ok:
            failures.append("session")
    except Exception as e:
        print("5) GET /api/session FEHLER:", e)
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
            await rpc("session.create", {"close_on_disconnect": True, "source": "e2e-test", "profile": "default"})
            print("5) session.create mit profile=default ok")
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

    # 7b) Admin wieder einloggen (für Admin-Tests)
    login_d = urllib.parse.urlencode({"username": "admin", "password": "admin123"}).encode()
    login_req = urllib.request.Request(f"{BASE}/api/login", data=login_d, method="POST")
    login_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    with login_opener.open(login_req, timeout=20) as lr:
        lj = json.loads(lr.read() or b"{}")
    print("7b) Admin wieder eingeloggt:", lj)

    # 8) Neuer User registrieren (falls erlaubt)
    reg_cfg = json.loads(urllib.request.urlopen(f"{BASE}/api/config").read())
    print("8) GET /api/config:", reg_cfg)
    if reg_cfg.get("allow_registration"):
        try:
            reg_jar = http.cookiejar.CookieJar()
            reg_data = urllib.parse.urlencode({"username": "testuser1", "password": "test123"}).encode()
            reg_req = urllib.request.Request(f"{BASE}/api/register", data=reg_data, method="POST")
            reg_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(reg_jar))
            with reg_opener.open(reg_req, timeout=20) as r:
                reg_status, reg_j = r.status, json.loads(r.read() or b"{}")
            print("8a) POST /api/register:", reg_status, reg_j)
            if reg_status == 200:
                print("8a) Registration OK")
                # Session-Check: sollte is_admin=False haben
                s_req = urllib.request.Request(f"{BASE}/api/session")
                s_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(reg_jar))
                with s_opener.open(s_req, timeout=10) as r2:
                    s_j2 = json.loads(r2.read() or b"{}")
                ok = s_j2.get("logged_in") and s_j2.get("is_admin") is False
                print("8b) Session als neu User (is_admin=False):", "OK" if ok else f"FEHLER -> {s_j2}")
                if not ok:
                    failures.append("reg_session")
            else:
                print("8a) Registration fehlgeschlagen:", reg_j)
                failures.append("register")
        except Exception as e:
            print("8) Registrierung FEHLER:", e)
            failures.append("register")
    else:
        print("8) Registrierung übersprungen (nicht erlaubt)")

    # 9) Admin: settings speichern und lesen
    print("9) Admin: POST /api/admin/settings (allow_registration=true)")
    st, j = post_form("/api/admin/settings", {"allow_registration": "1"}, jar)
    print("9) Admin settings speichern:", st, j)
    if st == 200:
        st2, j2 = get_json("/api/admin/settings", jar)
        print("9) Admin settings lesen:", j2)
        if j2.get("allow_registration") is not True:
            failures.append("admin_settings")
    else:
        failures.append("admin_settings")

    # 10) Admin: Benutzer-Liste (sollte 2 User enthalten)
    print("10) Admin: GET /api/admin/users")
    st, j = get_json("/api/admin/users", jar)
    print("10) Admin users:", st, len(j.get("users", [])) if st == 200 else j)
    if st == 200 and len(j.get("users", [])) >= 2:
        print("10) 2+ User in DB ✓")
    else:
        failures.append("admin_users")

    # 11) Admin: neuer User deaktivieren
    if reg_status == 200:
        print("11) Admin: PUT /api/admin/users/<id>/toggle (deaktivieren)")
        st, j = get_json("/api/admin/users", jar)
        testuser_id = None
        for u in (j or {}).get("users", []):
            if u["username"] == "testuser1":
                testuser_id = u["id"]
                break
        if testuser_id:
            d = urllib.parse.urlencode({"is_active": "0"}).encode()
            t_req = urllib.request.Request(f"{BASE}/api/admin/users/{testuser_id}/toggle", data=d, method="PUT")
            t_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            try:
                with t_opener.open(t_req, timeout=20) as r:
                    tj = json.loads(r.read() or b"{}")
                print("11) Deaktivieren OK:", tj)
                # Login sollte jetzt fehlschlagen (403)
                f_req = urllib.request.Request(f"{BASE}/api/login", data=urllib.parse.urlencode({"username": "testuser1", "password": "test123"}).encode(), method="POST")
                f_jar = http.cookiejar.CookieJar()
                f_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(f_jar))
                try:
                    with f_opener.open(f_req, timeout=20) as r2:
                        rj2 = json.loads(r2.read() or b"{}")
                        print("11) Login als deaktivierter User:", r2.status, rj2)
                        failures.append("deactivated_login")
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        print("11) Login als deaktivierter User: 403 ✓")
                    else:
                        print("11) Login als deaktivierter User: unerwarteter Status", e.code)
                        failures.append("deactivated_login")
            except Exception as e:
                print("11) Toggle FEHLER:", e)
                failures.append("admin_toggle")
        else:
            print("11) testuser1 nicht in DB gefunden, skip")

    # 12) Admin: neuer User löschen
    if reg_status == 200:
        print("12) Admin: DELETE /api/admin/users/<id>")
        if testuser_id:
            d_req = urllib.request.Request(f"{BASE}/api/admin/users/{testuser_id}", method="DELETE")
            d_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            try:
                with d_opener.open(d_req, timeout=20) as r:
                    dj = json.loads(r.read() or b"{}")
                print("12) Löschen OK:", dj)
                # Users Liste checken
                st, j = get_json("/api/admin/users", jar)
                users = j.get("users", []) if st == 200 else []
                has_test = any(u["username"] == "testuser1" for u in users)
                print("12) testuser1 noch in DB?", has_test)
                if has_test:
                    failures.append("delete_user")
            except Exception as e:
                print("12) DELETE FEHLER:", e)
                failures.append("delete_user")
        else:
            print("12) testuser1 nicht gefunden, skip")

    print("-" * 50)
    if failures:
        print("ERGEBNIS: FEHLGESCHLAGEN ->", ", ".join(failures))
        sys.exit(1)
    print("ERGEBNIS: ALLE TESTS BESTANDEN ✅")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402
    main()
