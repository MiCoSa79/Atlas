# Atlas App

## Workflow
- Immer Wiki pflegen: Nach jedem Code-Commit MUSS `/opt/data/wiki/log.md` und `entities/atlas-app.md` gepatcht werden.
- Wiki liegt in `/opt/data/wiki/` — ist **kein Git-Repo** (Host: exit 128).
- E2E-Tests vor Push: `ATLAS_DB=/tmp/atlas_e2e.db python tests/e2e_test.py`
- JS-Syntax-Check mit Platzhalter-Substitution für Jinja2.