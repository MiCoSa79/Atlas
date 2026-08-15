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
import urllib.error
import urllib.request

import pyotp
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


def post_form(path, fields, jar, method="POST"):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method,
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

    # 8) Session-Liste prüfen (mindestens 1 Session nach Chat)
    print("8) GET /api/sessions")
    s_req = urllib.request.Request(f"{BASE}/api/sessions")
    s_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    with s_opener.open(s_req, timeout=30) as sr:
        sj = json.loads(sr.read() or b"{}")
    print("8) Sessions:", sj)
    if sj.get("status") == "ok" and len(sj.get("sessions", [])) >= 1:
        print("8) Session-Liste enthält mindestens 1 Eintrag ✓")
        first = sj["sessions"][0]
        if not first.get("title"):
            failures.append("session_title")
        if not first.get("id"):
            failures.append("session_id")
    else:
        print("8) Session-Liste FEHLER:", sj)
        failures.append("sessions")

    # 9) Logout
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

    # 11b) Admin: Neuen Benutzer manuell anlegen
    print("11b) Admin: POST /api/admin/users (neuer Benutzer)")
    create_data = urllib.parse.urlencode({"username": "adminuser1", "password": "adminpass123"}).encode()
    create_req = urllib.request.Request(f"{BASE}/api/admin/users", data=create_data, method="POST")
    create_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with create_opener.open(create_req, timeout=20) as cr:
            cj = json.loads(cr.read() or b"{}")
        print("11b) Admin create user:", cr.status, cj)
        if cr.status != 200:
            failures.append("admin_create_user")
        else:
            # Nachlegen: User sollte jetzt in der Liste sein (3 User)
            st2, j2 = get_json("/api/admin/users", jar)
            print("11b) User nach Anlegen:", st2, len(j2.get("users", [])) if st2 == 200 else j2)
    except urllib.error.HTTPError as e:
        print("11b) Admin create user FEHLER:", e.code, json.loads(e.read()))
        failures.append("admin_create_user")

    # 12) Admin: neuer User deaktivieren
    if reg_status == 200:
        print("12) Admin: PUT /api/admin/users/<id>/toggle (deaktivieren)")
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
                print("12) Deaktivieren OK:", tj)
                # Login sollte jetzt fehlschlagen (403)
                f_req = urllib.request.Request(f"{BASE}/api/login", data=urllib.parse.urlencode({"username": "testuser1", "password": "test123"}).encode(), method="POST")
                f_jar = http.cookiejar.CookieJar()
                f_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(f_jar))
                try:
                    with f_opener.open(f_req, timeout=20) as r2:
                        rj2 = json.loads(r2.read() or b"{}")
                        print("12) Login als deaktivierter User:", r2.status, rj2)
                        failures.append("deactivated_login")
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        print("12) Login als deaktivierter User: 403 ✓")
                    else:
                        print("12) Login als deaktivierter User: unerwarteter Status", e.code)
                        failures.append("deactivated_login")
            except Exception as e:
                print("12) Toggle FEHLER:", e)
                failures.append("admin_toggle")
        else:
            print("12) testuser1 nicht in DB gefunden, skip")

    # 13) Admin: neuer User löschen
    if reg_status == 200:
        print("13) Admin: DELETE /api/admin/users/<id>")
        if testuser_id:
            d_req = urllib.request.Request(f"{BASE}/api/admin/users/{testuser_id}", method="DELETE")
            d_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            try:
                with d_opener.open(d_req, timeout=20) as r:
                    dj = json.loads(r.read() or b"{}")
                print("13) Löschen OK:", dj)
                # Users Liste checken
                st, j = get_json("/api/admin/users", jar)
                users = j.get("users", []) if st == 200 else []
                has_test = any(u["username"] == "testuser1" for u in users)
                print("13) testuser1 noch in DB?", has_test)
                if has_test:
                    failures.append("delete_user")
            except Exception as e:
                print("13) DELETE FEHLER:", e)
                failures.append("delete_user")
        else:
            print("13) testuser1 nicht gefunden, skip")

    # ---------------------------------------------------------------- 2FA (TOTP)
    print("14) 2FA: TOTP-Setup + Login-Flow")
    # Status-Abfrage (Admin ist eingeloggt)
    st, j = get_json("/api/2fa/status", jar)
    ok = st == 200 and j.get("enabled") is False
    print("14) GET /api/2fa/status (anfangs):", st, j)
    if not ok:
        failures.append("otp_status_initial")

    # Setup
    secret = ""
    setup_req = urllib.request.Request(f"{BASE}/api/2fa/setup", data=b"", method="POST")
    setup_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with setup_opener.open(setup_req, timeout=20) as sr:
            sj = json.loads(sr.read() or b"{}")
        print("14) POST /api/2fa/setup:", sj.get("status"), "| Secret:", (sj.get("secret") or "")[:8] + "…", "| QR:", "ja" if sj.get("qr_data_url") else "NEIN")
        secret = sj.get("secret", "")
        if sj.get("status") != "ok" or not secret or not sj.get("qr_data_url"):
            failures.append("otp_setup")
    except Exception as e:
        print("14) Setup FEHLER:", e)
        failures.append("otp_setup")

    # Falscher Code -> 401
    st, j = post_form("/api/2fa/confirm", {"code": "000000"}, jar)
    ok = st == 401
    print("14) Confirm mit falschem Code:", st, j.get("message"))
    if not ok:
        failures.append("otp_confirm_wrong")

    # Richtiger Code (pyotp generiert den aktuellen TOTP-Code)
    code = pyotp.TOTP(secret).now()
    st, j = post_form("/api/2fa/confirm", {"code": code}, jar)
    ok = st == 200 and j.get("status") == "ok"
    print("14) Confirm mit gültigem Code:", st, j.get("message"))
    if not ok:
        failures.append("otp_confirm")

    # Status: enabled
    st, j = get_json("/api/2fa/status", jar)
    ok = st == 200 and j.get("enabled") is True
    print("14) GET /api/2fa/status (nach Aktivierung):", st, j)
    if not ok:
        failures.append("otp_status_enabled")

    # Logout, dann Login -> 2fa_required (Passwort allein reicht nicht mehr)
    st, j = post_form("/api/logout", {}, jar)
    login_d = urllib.parse.urlencode({"username": ADMIN_USER, "password": ADMIN_PASS}).encode()
    login_req = urllib.request.Request(f"{BASE}/api/login", data=login_d, method="POST")
    login_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        with login_opener.open(login_req, timeout=20) as lr:
            lj = json.loads(lr.read() or b"{}")
            login_status = lr.status
    except urllib.error.HTTPError as e:
        login_status, lj = e.code, json.loads(e.read() or b"{}")
    ok = login_status == 200 and lj.get("status") == "2fa_required" and lj.get("pending_token")
    print("15) Login ohne 2FA-Code:", login_status, lj.get("status"), "(pending_token:", "ja" if lj.get("pending_token") else "nein", ")")
    if not ok:
        failures.append("otp_login_2fa_required")
    # Keine Session darf gestartet sein
    st, sess = get_json("/api/session", jar)
    if sess.get("logged_in"):
        print("15) FEHLER: Session trotz fehlendem 2FA aktiv!")
        failures.append("otp_no_session_without_code")

    # Falscher Code beim Verify -> 401
    st, j = post_form("/api/2fa/verify", {"pending_token": lj.get("pending_token", ""), "code": "000000"}, jar)
    ok = st == 401
    print("15) Verify mit falschem Code:", st, j.get("message"))
    if not ok:
        failures.append("otp_verify_wrong")

    # Richtiger Code -> Session
    code2 = pyotp.TOTP(secret).now()
    st, j = post_form("/api/2fa/verify", {"pending_token": lj.get("pending_token", ""), "code": code2}, jar)
    ok = st == 200 and j.get("status") == "ok"
    print("15) Verify mit gültigem Code:", st, j.get("status"))
    if not ok:
        failures.append("otp_verify_ok")
    st, sess = get_json("/api/session", jar)
    ok = sess.get("logged_in") is True
    print("15) Session nach 2FA:", "OK" if ok else f"FEHLER -> {sess}")
    if not ok:
        failures.append("otp_session_after_verify")

    # Deaktivieren: falsches Passwort -> 401
    st, j = post_form("/api/2fa/disable", {"password": "falsch123"}, jar)
    ok = st == 401
    print("16) Disable mit falschem Passwort:", st, j.get("message"))
    if not ok:
        failures.append("otp_disable_wrong_pw")

    # Deaktivieren: richtiges Passwort -> ok
    st, j = post_form("/api/2fa/disable", {"password": ADMIN_PASS}, jar)
    ok = st == 200 and j.get("status") == "ok"
    print("16) Disable mit richtigem Passwort:", st, j.get("message"))
    if not ok:
        failures.append("otp_disable")

    st, j = get_json("/api/2fa/status", jar)
    ok = st == 200 and j.get("enabled") is False
    print("16) GET /api/2fa/status (nach Disable):", st, j)
    if not ok:
        failures.append("otp_status_disabled")

    # Wichtig: 2FA wieder deaktiviert lassen, damit Folgetests/Updates des Nutzers nicht hängen
    print("14–16) 2FA-Tests abgeschlossen (Admin wieder ohne 2FA) ✓")

    # ---------------------------------------------------------------- 2FA-Pflicht (require_2fa)
    print("17) Admin: require_2fa (2FA verpflichtend) + Nutzer-Flow")
    # Admin aktiviert 2FA-Pflicht
    st, j = post_form("/api/admin/settings", {"allow_registration": "1", "require_2fa": "1"}, jar)
    ok = st == 200
    print("17) Admin setzt require_2fa=1:", st, j)
    if not ok:
        failures.append("otp_require_set")
    st, j = get_json("/api/admin/settings", jar)
    ok = st == 200 and j.get("require_2fa") is True
    print("17) require_2fa gelesen:", j)
    if not ok:
        failures.append("otp_require_read")

    # adminuser1 (aus 11b, ohne 2FA) einloggen -> Session meldet otp_required
    u_jar = http.cookiejar.CookieJar()
    u_login = urllib.parse.urlencode({"username": "adminuser1", "password": "adminpass123"}).encode()
    u_req = urllib.request.Request(f"{BASE}/api/login", data=u_login, method="POST")
    u_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(u_jar))
    try:
        with u_opener.open(u_req, timeout=20) as ur_:
            uj = json.loads(ur_.read() or b"{}")
        print("17) Login adminuser1 (kein 2FA):", ur_.status, uj.get("status"))
        if ur_.status != 200:
            failures.append("otp_require_login")
    except urllib.error.HTTPError as e:
        print("17) Login adminuser1 FEHLER:", e.code, e.read())
        failures.append("otp_require_login")
    st, sess = get_json("/api/session", u_jar)
    ok = sess.get("logged_in") and sess.get("otp_required") is True
    print("17) Session otp_required (ohne 2FA):", sess.get("otp_required"))
    if not ok:
        failures.append("otp_required_flag")

    # Nutzer richtet 2FA ein -> otp_required muss verschwinden
    u_setup = urllib.request.Request(f"{BASE}/api/2fa/setup", data=b"", method="POST")
    u_setup_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(u_jar))
    with u_setup_opener.open(u_setup, timeout=20) as usr:
        usj = json.loads(usr.read() or b"{}")
    u_secret = usj.get("secret", "")
    u_code = pyotp.TOTP(u_secret).now()
    st, j = post_form("/api/2fa/confirm", {"code": u_code}, u_jar)
    ok = st == 200
    print("17) adminuser1 2FA aktiviert:", st, j.get("message"))
    if not ok:
        failures.append("otp_require_confirm")
    st, sess = get_json("/api/session", u_jar)
    ok = sess.get("logged_in") and sess.get("otp_required") is False and sess.get("otp_enabled") is True
    print("17) Session otp_required (mit 2FA):", sess.get("otp_required"), "| otp_enabled:", sess.get("otp_enabled"))
    if not ok:
        failures.append("otp_required_cleared")

    # Aufräumen: adminuser1 2FA deaktivieren + Admin stellt require_2fa=0 zurück
    st, j = post_form("/api/2fa/disable", {"password": "adminpass123"}, u_jar)
    ok = st == 200
    print("17) adminuser1 2FA deaktiviert (Aufräumen):", st, j.get("message"))
    if not ok:
        failures.append("otp_require_cleanup_user")
    st, j = post_form("/api/admin/settings", {"allow_registration": "1", "require_2fa": "0"}, jar)
    ok = st == 200
    print("17) require_2fa zurück auf 0 (Aufräumen):", st, j)
    if not ok:
        failures.append("otp_require_cleanup_admin")
    st, j = get_json("/api/2fa/status", jar)
    ok = st == 200 and j.get("enabled") is False
    print("17) Admin 2FA-Status (unverändert aus):", j)
    if not ok:
        failures.append("otp_require_admin_status")

    print("17) 2FA-Pflicht-Tests abgeschlossen ✓")

    # ---------------------------------------------------------------- Admin-Rechte (role)
    print("18) Admin-Verwaltung: Rechte vergeben/entziehen + letzter-Admin-Schutz")
    st, j = get_json("/api/admin/users", jar)
    uid_admin = next((u["id"] for u in j.get("users", []) if u["username"] == "admin"), None)
    uid_u1 = next((u["id"] for u in j.get("users", []) if u["username"] == "adminuser1"), None)
    print("18) IDs: admin =", uid_admin, "| adminuser1 =", uid_u1)

    # a) adminuser1 zum Admin machen
    st, j = post_form(f"/api/admin/users/{uid_u1}/role", {"is_admin": "1"}, jar, method="PUT")
    ok = st == 200 and j.get("changed") is True
    print("18a) adminuser1 -> Admin:", st, j)
    if not ok:
        failures.append("role_grant")

    # b) adminuser1 sieht in seiner Session is_admin=True (frischer Login)
    au_jar = http.cookiejar.CookieJar()
    au_login = urllib.parse.urlencode({"username": "adminuser1", "password": "adminpass123"}).encode()
    au_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(au_jar))
    with au_opener.open(urllib.request.Request(f"{BASE}/api/login", data=au_login, method="POST"), timeout=20) as aur:
        print("18b) Login adminuser1 (jetzt Admin):", aur.status)
    st, sess = get_json("/api/session", au_jar)
    ok = sess.get("logged_in") and sess.get("is_admin") is True
    print("18b) adminuser1 Session is_admin:", sess.get("is_admin"))
    if not ok:
        failures.append("role_session")

    # c) Selbst-Demote erlaubt, solange noch ein anderer Admin existiert (2 Admins da)
    st, j = post_form(f"/api/admin/users/{uid_admin}/role", {"is_admin": "0"}, jar, method="PUT")
    ok = st == 200 and j.get("changed") is True
    print("18c) Admin entzieht sich selbst das Recht (2 Admins da):", st, j)
    if not ok:
        failures.append("role_self_demote")

    # d) Jetzt ist adminuser1 der EINZIGE Admin -> Selbst-Demote muss scheitern (400)
    st, j = post_form(f"/api/admin/users/{uid_u1}/role", {"is_admin": "0"}, au_jar, method="PUT")
    ok = st == 400
    print("18d) Letzter Admin versucht Selbst-Demote:", st, j.get("message"))
    if not ok:
        failures.append("role_last_admin")

    # e) adminuser1 (einziger Admin) macht den Haupt-Admin wieder zum Admin
    st, j = post_form(f"/api/admin/users/{uid_admin}/role", {"is_admin": "1"}, au_jar, method="PUT")
    ok = st == 200 and j.get("changed") is True
    print("18e) adminuser1 stellt Haupt-Admin wieder her:", st, j)
    if not ok:
        failures.append("role_recover")

    # f) Aufräumen: adminuser1 entzieht sich selbst das Recht (Haupt-Admin ist wieder da)
    st, j = post_form(f"/api/admin/users/{uid_u1}/role", {"is_admin": "0"}, au_jar, method="PUT")
    ok = st == 200 and j.get("changed") is True
    print("18f) adminuser1 demotet sich selbst (Cleanup):", st, j)
    if not ok:
        failures.append("role_cleanup")

    # g) Admin-Reihenfolge prüfen: genau 1 Admin (Haupt-Admin) übrig
    st, j = get_json("/api/admin/users", jar)
    admins = [u["username"] for u in j.get("users", []) if u["is_admin"]]
    ok = admins == ["admin"]
    print("18g) Admins nach Cleanup:", admins)
    if not ok:
        failures.append("role_final")

    print("18) Admin-Rechte-Tests abgeschlossen ✓")

    print("-" * 50)
    if failures:
        print("ERGEBNIS: FEHLGESCHLAGEN ->", ", ".join(failures))
        sys.exit(1)
    print("ERGEBNIS: ALLE TESTS BESTANDEN ✅")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402
    main()
