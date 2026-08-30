"""E2E DB-only-Fallback (v0.0.237): Save-Modelle OHNE Hermes-Config-Zugriff.

Simuliert den ZimaOS-Container ohne ATLAS_HERMES_CONFIG_PATH/DIR:
  - POST /api/profile/models (main + aux)  -> config_written=False, fallback=db
  - GET  /api/profile/models               -> liefert die zuletzt gespeicherten Werte
    (Regression: vor v0.0.237 kamen leere Werte -> UI setzte die Auswahl zurück)

Aufruf:  venv/bin/python scripts/run_e2e_dbonly.py
Exit 0  = "ERGEBNIS: ALLE TESTS BESTANDEN".
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
TEST_DB = "/tmp/atlas_e2e_dbonly.db"
PORT = 8901
BASE = f"http://127.0.0.1:{PORT}"


def main():
    env = os.environ.copy()
    env["ATLAS_DB"] = TEST_DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    server = subprocess.Popen(
        [VENV_PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    failures = []
    jar = http.cookiejar.CookieJar()
    try:
        # Auf Port warten
        for _ in range(40):
            try:
                urllib.request.urlopen(f"{BASE}/", timeout=2).read()
                break
            except Exception:
                time.sleep(0.5)

        def post_form(path, data, which=jar):
            body = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(f"{BASE}{path}", data=body, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(which))
            try:
                with op.open(req, timeout=20) as r:
                    return r.status, json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                return e.code, {}

        def get_json(path, which=jar):
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(which))
            with op.open(f"{BASE}{path}", timeout=20) as r:
                return json.loads(r.read().decode())

        # 0) Setup + Login
        st, j = post_form("/api/setup", {"username": "dbadmin", "password": "DbAdmin123!"})
        st, j = post_form("/api/login", {"username": "dbadmin", "password": "DbAdmin123!"})
        ok = j.get("status") == "ok"
        print("0) Setup/Login:", st, j.get("status"))

        # 1) Save main (Main-Modell) -> DB-Fallback, config_written False
        st, j1 = post_form("/api/profile/models",
                           {"scope": "main", "main_provider": "custom:test-db", "main_model": "Qwen3"})
        print("1) POST main:", st, "| config_written:", j1.get("config_written"), "| fallback:", j1.get("fallback"))
        if not (st == 200 and j1.get("config_written") is False and j1.get("fallback") == "db"):
            failures.append("dbonly_main_post")

        # 2) Save aux (Auxiliary) -> DB-Fallback
        aux = {"compression": {"provider": "custom:test-db", "model": "Mistral"},
               "title_generation": {"provider": "custom:test-db", "model": "DeepSeek-V4-Flash"}}
        st, j2 = post_form("/api/profile/models", {"scope": "aux", "aux": json.dumps(aux)})
        print("2) POST aux:", st, "| config_written:", j2.get("config_written"))
        if not (st == 200 and j2.get("config_written") is False):
            failures.append("dbonly_aux_post")

        # 3) GET -> Werte müssen zurückkommen (Regression „Auswahl wird zurückgesetzt")
        g = get_json("/api/profile/models")
        gm, ga = g.get("main") or {}, g.get("aux") or {}
        print("3) GET main:", gm.get("model"), "/", gm.get("provider"),
              "| aux:", {k: (v.get("model") if isinstance(v, dict) else v) for k, v in ga.items()})
        if not (g.get("config_access") is False and gm.get("model") == "Qwen3"
                and ga.get("compression", {}).get("model") == "Mistral"
                and ga.get("title_generation", {}).get("model") == "DeepSeek-V4-Flash"):
            failures.append("dbonly_readback")

        # 4) Persistenz: Server-Neustart, Werte bleiben (DB-Fallback ist dauerhaft)
        server.terminate()
        server.wait(timeout=10)
        server = subprocess.Popen(
            [VENV_PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
            cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for _ in range(40):
            try:
                urllib.request.urlopen(f"{BASE}/", timeout=2).read()
                break
            except Exception:
                time.sleep(0.5)
        jar2 = http.cookiejar.CookieJar()
        post_form("/api/login", {"username": "dbadmin", "password": "DbAdmin123!"}, which=jar2)
        g2 = get_json("/api/profile/models", which=jar2)
        gm2, ga2 = g2.get("main") or {}, g2.get("aux") or {}
        print("4) GET nach Neustart main:", gm2.get("model"), "| aux compression:",
              ga2.get("compression", {}).get("model"))
        if not (gm2.get("model") == "Qwen3" and ga2.get("compression", {}).get("model") == "Mistral"):
            failures.append("dbonly_persist")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except Exception:
            server.kill()

    if failures:
        print("FEHLGESCHLAGEN:", failures)
        return 1
    print("ERGEBNIS: ALLE TESTS BESTANDEN (DB-only-Fallback)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
