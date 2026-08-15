# Atlas Docker Proxy

Ein eigenständiger Docker-Container für den Zugriff auf Hermes-Agenten über ein Webinterface.

## Funktionen
- **Multi-User:** Jeder Benutzer hat sein eigenes Konto.
- **Hermes-Proxy:** Verbindet sich mit einem beliebigen Hermes-Container (Basic Auth).
- **Profile:** Auswahl des Hermes-Profils (falls vorhanden).
- **PWA:** Installierbar auf iOS/Android.

## Installation (Docker Compose)

Erstelle ein `docker-compose.yml` im Stammverzeichnis des Containers:

```yaml
version: '3'
services:
  atlas:
    image: micosa79/atlas:latest
    restart: always
    network_mode: host  # Wichtig für direkten Zugriff auf Hermes im selben Host
    environment:
      - ATLAS_SECRET_KEY=dein_sicheres_geheimnis # Mindestens 32 Zeichen
      - ATLAS_SETUP_TOKEN=dein_erster_setup_token # Nur beim ersten Start benötigt
```
