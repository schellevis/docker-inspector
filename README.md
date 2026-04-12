# Docker Vulnerability Scanner

A self-contained Dockerized web application that scans all currently running Docker containers on the host for known CVEs and presents the results in a clean web interface. It talks directly to `/var/run/docker.sock` to enumerate images, invokes [Grype](https://github.com/anchore/grype) to scan them, persists findings in SQLite, and serves a FastAPI/HTMX/Tailwind UI — no build step required.

---

## Quick start

```bash
git clone https://github.com/schellevis/docker-inspector.git
cd docker-inspector
docker compose up -d
```

Then visit **http://localhost:8000**.

The dashboard will be empty until you trigger the first scan.

---

## Triggering a manual scan

Click **Scan now** on the dashboard, or POST to the API:

```bash
curl -X POST http://localhost:8000/scan
```

To scan a single image:

```bash
curl -X POST http://localhost:8000/scan/<full-sha256-image-id>
```

Scans also run automatically every night at **03:00** (configurable via `SCAN_CRON` in `docker-compose.yml`).

---

## Docker socket security note

This container mounts `/var/run/docker.sock` and therefore has **effective root access to the host**. Only run it on private networks behind an authenticating reverse proxy (e.g., Authelia + Nginx Proxy Manager). Do not expose port 8000 to the internet.

The container's user (`scanner`, UID 1000) is added to GID 999, which is the conventional GID for the `docker` group. If your host's Docker socket uses a different GID, pass `--group-add <gid>` in `docker-compose.yml`:

```yaml
group_add:
  - "974"   # replace with the actual GID of /var/run/docker.sock on your host
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SCANNER_DB_PATH` | `/data/scanner.db` | SQLite database path |
| `GRYPE_DB_CACHE_DIR` | `/data/grype-db` | Grype vulnerability DB cache directory |
| `SCAN_CRON` | `0 3 * * *` | Cron expression for scheduled scans |
| `TZ` | `Europe/Amsterdam` | Timezone for timestamps |

---

## Backing up the database

The SQLite file and Grype DB live in `./data/` on the host (mounted at `/data` inside the container):

```bash
cp ./data/scanner.db ./data/scanner.db.bak
```

For hot backups while the container is running, use SQLite's online backup:

```bash
sqlite3 ./data/scanner.db ".backup './data/scanner.db.bak'"
```

---

## How it works

1. **Inventory** — On demand (or on schedule), the app calls `docker.from_env().containers.list()` and collects the unique set of image IDs currently in use by running containers. Tags are stored for display only; all scanning is keyed on the SHA256 image ID.
2. **Scan** — For each unique image ID, Grype is invoked as a subprocess (`grype <image_id> -o json`). The Grype vulnerability database is cached in `/data/grype-db` so it survives container restarts.
3. **Store** — Results are persisted in SQLite (`/data/scanner.db`) across three tables: `images`, `scans`, and `findings`.
4. **Display** — FastAPI serves Jinja2 templates with HTMX for interactivity. The dashboard shows severity badges per image; `/image/<id>` shows full findings; `/diff` highlights CVEs that appeared or disappeared between the last two scans.

---

## Troubleshooting

**`permission denied` on Docker socket**
The container user needs read access to `/var/run/docker.sock`. Check the GID:
```bash
ls -la /var/run/docker.sock
```
Then add the matching GID to the container via `group_add` in `docker-compose.yml`.

**Grype DB update failures**
The DB update happens in the background at startup. Check logs:
```bash
docker logs docker-vuln-scanner | grep -i grype
```
If the update fails repeatedly, verify the container can reach `toolbox.anchore.io` on port 443.

**Scan hangs / times out**
Grype sets a 10-minute timeout per image. If a scan is stuck, restart the container — the scan state is in-process only and will reset. Large images (e.g., full OS images) can take several minutes; this is normal.

**Dashboard shows no images after scan**
Make sure the container has at least one other running container to scan on the same Docker host. The scanner only inventories *running* containers.

---

## API

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard |
| `/image/{id}` | GET | Per-image detail with findings |
| `/image/{id}/history` | GET | Scan history for one image |
| `/diff` | GET | New/resolved CVEs across all images |
| `/scan` | POST | Trigger full scan (async) |
| `/scan/{id}` | POST | Trigger scan for one image (async) |
| `/scan/status` | GET | Current scan status JSON |
| `/api/findings` | GET | JSON findings; query params: `severity`, `image_id`, `fixable_only` |
| `/healthz` | GET | Liveness probe |