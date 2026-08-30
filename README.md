# Atlas Docker Proxy

Ein eigenständiger Docker-Container für den Zugriff auf Hermes-Agenten über ein Webinterface.

## Funktionen
- **Multi-User:** Jeder Benutzer hat sein eigenes Konto.
- **Hermes-Proxy:** Verbindet sich mit einem beliebigen Hermes-Container (Login-Daten werden pro User in der Atlas-DB verschlüsselt gespeichert — Angabe im Atlas-UI unter Profil → Einstellungen).
- **Profile:** Auswahl des Hermes-Profils (falls vorhanden).
- **PWA:** Installierbar auf iOS/Android.
- **Profil-Modelle (v0.0.234+):** Hauptmodell, Reasoning, Schnellmodus und Auxiliary-Modelle können pro Hermes-Profil direkt in dessen `config.yaml` gespeichert werden.

## Installation (Docker Compose)

Die mitgelieferte `docker-compose.yml` ist **direkt nutzbar** — sie funktioniert ohne Änderungen:

```bash
docker compose up -d          # Pull + Start
docker compose up -d --build  # alternativ: lokal bauen
```

Atlas ist danach unter `http://<host>:8899` erreichbar. Beim ersten Start legst du über die
Web-Oberfläche den ersten Admin-Account an und trägst in den Profil-Einstellungen die
Hermes-Verbindung (URL, Benutzer, Passwort, Profil) ein.

### Benötigte Variablen

Alle Variablen sind **optional** — der Container startet mit sinnvollen Vorgaben:

| Variable | Wofür? | Vorgabe |
|---|---|---|
| `ATLAS_PORT` | Host-Port, unter dem Atlas erreichbar ist | `8899` |
| `HERMES_CONFIG_DIR` | Host-Verzeichnis mit den Hermes-Profil-Configs (`<dir>/<profil>/config.yaml`). Notwendig, damit „Modelle für dieses Hermes-Profil“ (v0.0.234+) wirklich in die Config schreiben. Läuft Hermes auf demselben Host: dessen Profil-Ordner eintragen (z.B. `/opt/data/profiles`). Ohne Angabe funktioniert der Rest der App normal, nur das Config-Schreiben nicht (`config_written: false`). | `/data/profiles` |

### Optionale Variablen (in der `docker-compose.yml` auskommentiert)

| Variable | Wofür? |
|---|---|
| `ATLAS_DB` | Pfad zur SQLite-Datenbank im Volume (nur ändern, wenn die DB woanders liegen soll) |
| `ATLAS_HERMES_CONFIG_DIR` | Basis-Verzeichnis der Hermes-Profile im Container — nur nötig, wenn der Pfad vom Standard-`/data/profiles`-Mount abweicht |
| `ATLAS_HERMES_CONFIG_PATH` | Fester Dateipfad zur `config.yaml` statt Verzeichnis (Sonderfall) |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` | Passkey-Login (seit v0.0.229 nur Fallback — die Admin-Settings im Atlas-UI haben Vorrang). `RP_ID` = Domain (eTLD+1, ohne Schema/Port), `ORIGIN` = vollständige URL inkl. Schema/Port |
| `TZ` | Zeitzone der Container-Logs (z.B. `Europe/Berlin`) |

### Was der Container mitbringt (Volumes)

| Mount | Inhalt |
|---|---|
| `atlas-data:/data` (named volume) | SQLite-DB (`/data/atlas.db`) + hochgeladene Dateien (`/data/uploads/`) — persistiert Container-Updates |
| `${HERMES_CONFIG_DIR:-/data/profiles}:/data/profiles` | Zugriff auf die Hermes-Profil-Configs des Hosts (optional; Zeile entfernen, wenn Hermes nicht auf dem Host läuft). Achtung: Atlas **patcht** die `config.yaml` schreibend — kein `:ro`-Mount |

### Hinweise

- **Passwort-Login funktioniert immer.** Passkeys brauchen zusätzlich `WEBAUTHN_RP_ID`/`WEBAUTHN_ORIGIN` oder die Admin-Settings.
- **Healthcheck** ist integriert: `docker compose ps` zeigt `healthy`, sobald die Startseite antwortet.
- Für Produktions-Updates ein **festes Tag** verwenden statt `latest`, z.B. `micosa79/atlas:v0.0.236`.
