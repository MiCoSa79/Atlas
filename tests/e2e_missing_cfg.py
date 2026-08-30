"""Repro: Config-Path GESETZT, aber Datei fehlt (ZimaOS-Typfall).

Simuliert ATLAS_HERMES_CONFIG_PATH auf eine nicht existierende Datei:
  - erwartet: GET liefert die gespeicherten Werte (wie DB-Fallback)
  - tatsaechlich: POST leert die DB-Overrides, GET liest leere Datei -> "nicht gespeichert"
"""
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = "/opt/data/profiles/axel/Projekte/Atlas-App/repo"
VENV_PY = "/opt/data/profiles/axel/Projekte/Atlas-App/venv/bin/python"
TEST_DB = "/tmp/atlas_e2e_missingcfg.db"
PORT = 8903
BASE = f"http://127.0.0.1:{PORT}"
MISSING = "/tmp/kaum-da/not-existing/config.yaml"  # Pfad gesetzt, Datei existiert NICHT


def main():
    env = os.environ.copy()
    env["ATLAS_DB"] = TEST_DB
    env["ATLAS_HERMES_CONFIG_PATH"] = MISSING
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    server = subprocess.Popen(
        [VENV_PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    jar = http.cookiejar.CookieJar()
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen(f"{BASE}/", timeout=2).read()
                break
            except Exception:
                time.sleep(0.5)

        def post_form(path, data):
            body = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(f"{BASE}{path}", data=body, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            try:
                with op.open(req, timeout=20) as r:
                    return r.status, json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                return e.code, {}

        def get_json(path):
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            with op.open(f"{BASE}{path}", timeout=20) as r:
                return json.loads(r.read().decode())

        st, j = post_form("/api/setup", {"username": "repro", "password": "Repro123!"})
        st, j = post_form("/api/login", {"username": "repro", "password": "Repro123!"})
        print("0) Setup/Login:", st, j.get("status"))

        st, j1 = post_form("/api/profile/models",
                           {"scope": "main", "main_provider": "custom:repro", "main_model": "Qwen3"})
        print("1) POST main ->", st, "| config_written:", j1.get("config_written"),
              "| fallback:", j1.get("fallback"))
        print("   message:", j1.get("config_message", "")[:110])

        j2 = get_json("/api/profile/models")
        m = j2.get("main", {})
        print("2) GET main  -> config_access:", j2.get("config_access"),
              "| model:", repr(m.get("model")), "| provider:", repr(m.get("provider")))

        # DB-Zustand direkt pruefen (users.model)
        import sqlite3
        conn = sqlite3.connect(TEST_DB)
        row = conn.execute("SELECT model, provider FROM users WHERE username='repro'").fetchone()
        conn.close()
        print("3) DB users  -> model:", repr(row[0] if row else None),
              "| provider:", repr(row[1] if row else None))

        ok = j2.get("main", {}).get("model") == "Qwen3"
        print("ERGEBNIS:", "BUG REPRODUZIERT (GET leer obwohl gespeichert)" if not ok
              else "OK (Werte kommen zurueck)")
        return 1 if not ok else 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except Exception:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
