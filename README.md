<img width="2853" height="1566" alt="image" src="https://github.com/user-attachments/assets/169fe35d-a01f-47aa-85db-6c6fb62ed78c" />
<img width="2866" height="1571" alt="image" src="https://github.com/user-attachments/assets/bf7e3ca0-38c5-4cdb-9e67-a2f9f46ca8e5" />

# Data Manager

Data Manager is a Dockerized web app that watches a completed-downloads folder, identifies movie and TV files, verifies metadata, scans for malware, renames files, moves sidecar subtitle/artwork files, and organizes media into library folders.

It includes a web UI for queue visibility, processing stages, logs, alerts, manual library scans, duplicate checks, malware checks, settings, SSO, and role-based user management.

## Features

- Automatic import queue for new media files.
- Movie naming: `Movie Title (Year)/Movie Title [Year] [Quality].ext`.
- TV naming: `Show Name [Year]/Season 01/Show Name [Year] [S01E01] Episode Name [Quality].ext`.
- TMDB metadata lookup for movies and TV, with optional TVmaze fallback for TV episode details.
- ffprobe quality detection for resolution, codec, audio channels, HDR, bitrate, runtime, and size.
- Smart conflict rules for higher-quality replacements.
- Sidecar subtitle/artwork handling for files such as `.srt`, `.ass`, `.ssa`, `.sub`, `.idx`, `.vtt`, `.sup`, `.nfo`, `.jpg`, and `.png`.
- Manual File Management scans for existing movie and TV libraries.
- Duplicate Checker with side-by-side file details and delete controls.
- ClamAV malware scans on new files, plus manual and scheduled library scans.
- Pushover notifications for success, failure, duplicates, scan completion, mount failures, metadata failures, and malware quarantines.
- Local admin/view-only accounts and optional OIDC/SSO with role mapping.
- SQLite-backed settings, logs, users, and job stats.

## Requirements

- Docker
- Docker Compose
- Read/write access to:
  - a completed downloads folder
  - a movie library folder
  - a TV library folder
  - a duplicate review folder
  - a malware quarantine folder
- A TMDB API key is strongly recommended because metadata-required mode prevents bad release names from entering the library.

## Versions And Releases

The app version is stored in `pyproject.toml`:

```toml
[project]
version = "1.7.0"
```

The web UI shows this version in the header. Docker images also receive this value as an OCI image label when built through Compose.

Recommended release flow:

```bash
git status
git add .
git commit -m "Release v1.7.0"
git tag -a v1.7.0 -m "Data Manager v1.7.0"
git push origin main
git push origin v1.7.0
```

Install a specific version:

```bash
git clone --branch v1.7.0 --depth 1 <your-repo-url> data-manager
cd data-manager
cp .env.example .env
```

Upgrade an existing install to a specific version:

```bash
cd /mnt/user/appdata/data-manager
git fetch --tags
git checkout v1.7.0
docker compose -f docker-compose.unraid.yml up -d --build
```

If you copy files instead of using Git on the server, copy code files only and keep production `.env` and `data/` in place.

## Quick Start

1. Clone the repo.

```bash
git clone <your-repo-url> data-manager
cd data-manager
```

2. Create your local environment file.

```bash
cp .env.example .env
openssl rand -hex 32
```

3. Edit `.env`.

Set a strong admin password, paste the random session secret, and point the media paths at your folders:

```dotenv
DATA_MANAGER_ADMIN_PASSWORD=change-this-admin-password
DATA_MANAGER_SESSION_SECRET=paste-random-secret-here
DATA_MANAGER_WATCH_DIR=/absolute/path/to/downloads/completed
DATA_MANAGER_REVIEW_DIR=/absolute/path/to/downloads/to-review
DATA_MANAGER_QUARANTINE_DIR=/absolute/path/to/downloads/quarantine
DATA_MANAGER_MOVIE_DIR=/absolute/path/to/movies
DATA_MANAGER_TV_DIR=/absolute/path/to/tv-shows
TMDB_API_KEY=
```

4. Start the app.

```bash
docker compose up -d --build
```

5. Open the UI.

```text
http://SERVER-IP:8085
```

Default username comes from `.env` and defaults to `admin`. The password is the value you set in `DATA_MANAGER_ADMIN_PASSWORD`.

## Unraid Install

On Unraid, place the project somewhere persistent, such as an appdata folder:

```bash
mkdir -p /mnt/user/appdata/data-manager
cd /mnt/user/appdata/data-manager
```

Copy the project files there, then create `.env` from `.env.example` and set the Unraid host paths:

```bash
cp .env.example .env
nano .env
```

Start with the Unraid compose file:

```bash
docker compose -f docker-compose.unraid.yml up -d --build
```

The app listens on host port `8085` by default.

## Safe Upgrades Without Losing Settings

Settings, accounts, logs, and job stats live in the SQLite database mounted at:

```text
/data/data-manager.db
```

With the provided compose files, `/data` maps to `DATA_MANAGER_DATA_DIR`, which defaults to `./data`.

Do not overwrite or delete this folder when copying new code to production. A safe copy command looks like this:

```bash
rsync -av --exclude data --exclude .env --exclude __pycache__ ./ root@SERVER-IP:/mnt/user/appdata/data-manager/
```

Then restart:

```bash
ssh root@SERVER-IP
cd /mnt/user/appdata/data-manager
docker compose -f docker-compose.unraid.yml up -d --build
```

This updates the code and image while preserving `.env` and the SQLite database.

For a lightweight code-only copy that will not overwrite production YAML, `.env`, or `data/`:

```bash
scp app.py data_manager_*.py pyproject.toml Dockerfile root@SERVER-IP:/mnt/user/appdata/data-manager/
```

Then rebuild with your existing production compose file:

```bash
ssh root@SERVER-IP
cd /mnt/user/appdata/data-manager
docker compose -f docker-compose.unraid.yml up -d --build
```

## Settings

Most behavior can be configured from the web UI after first boot. The compose and `.env` files only need enough information to start the container and mount the folders.

Important settings:

- `TMDB API key`: metadata provider key.
- `Metadata required`: when enabled, files stay in downloads if metadata cannot be verified.
- `New-file workers`: how many ready downloads can process concurrently.
- `File management workers`: workers for manual library cleanup scans.
- `Duplicate checker workers`: workers for duplicate indexing.
- `Malware scan workers`: parallel ClamAV workers.
- `Transfer chunk bytes`: bytes read per transfer chunk.
- `Automatic Runs`: daily, weekly, monthly, or disabled schedules for duplicate and malware scans.

## User Management

Settings includes a User Management panel for local accounts.

- `admin`: can change settings, run scans, clear logs, delete duplicate files, and test integrations.
- `viewer`: can view dashboards, logs, alerts, scan pages, and results, but cannot modify anything.

Local passwords are saved as PBKDF2 hashes. Secret fields are never rendered back into the HTML; leave a secret field blank to keep the saved value.

## SSO / OIDC

Data Manager supports OIDC providers such as Authentik.

Typical Authentik settings:

- Client type: confidential
- Client auth method: `client_secret_basic`
- Token request client ID in body: `yes`
- PKCE: `no` for confidential clients
- Redirect URI: `http://SERVER-IP:8085/sso/callback`
- Scopes: `openid email profile`

SSO access can be mapped by identity:

- `SSO admin users`: comma-separated identities that should be admin.
- `SSO view-only users`: comma-separated identities that should be viewer.
- `Default SSO role`: role for valid SSO users not listed above.

Use the Settings page's SSO diagnostics and Test SSO Credentials button to confirm the provider accepts the configured client.

## Metadata Lookup

Data Manager uses TMDB for movies and TV metadata. TV lookup can also use TVmaze as a fallback for episode details.

If metadata-required mode is enabled and no verified match is found:

- the file is not moved
- the file remains in the watch folder
- a failure is logged for review

This prevents release tags, language tags, uploader names, and encoder names from becoming library names.

## File Management

The File Management page provides manual-only scans for existing libraries:

- Scan Movies: rename and reorganize movie files into the current movie format.
- Scan TV: rename show folders, create `Season 01` folders, and move episodes into the correct season folder.
- Scan All: run both checks.

Manual scans show stages, current folder/file activity, progress, worker count, rate, elapsed time, and recent activity.

## Duplicate Checker

The Duplicate Checker can run manually or on a schedule. It compares library media and stores duplicate findings. Results show both files side by side with quality, size, codec, audio, HDR, bitrate, runtime, path, and a recommended keep file.

Smart conflict rules prefer the better copy by score:

- 4K over 1080p, 1080p over 720p.
- BluRay over WEB-DL when resolution is otherwise comparable.
- HDR, better codec, more audio channels, higher bitrate, and larger file size are tie-breakers.

When a better incoming file replaces an existing lower-quality file, the lower-quality existing file can be removed according to the app's conflict handling rules.

## Malware Checks

The container installs ClamAV tools.

- New downloads are scanned before metadata lookup, renaming, duplicate checks, or moving.
- Infected files or source folders are moved to `/quarantine` without being renamed.
- Manual scans can target Movies, TV, or All.
- Scheduled malware scans can run daily, weekly, monthly, or be disabled.
- If malware scanning is enabled but ClamAV is unavailable, the import pipeline fails closed and leaves the file in downloads.

## Notifications

Pushover can be configured from Settings. Notification toggles are separate for:

- successful transfers
- failures
- duplicates/conflicts
- scan completion
- mount unavailable
- metadata provider down
- malware quarantines

Use Send Test Alert after saving the Pushover token and user/group key.

## Security Notes

- Do not commit `.env`.
- Do not commit the `data/` folder.
- Use a long random `DATA_MANAGER_SESSION_SECRET`.
- Change the default admin password before real use.
- Keep the app behind a trusted network or reverse proxy.
- Use SSO admin allowlists or set default SSO role to `viewer` after confirming your admin identity.

## Code Layout

- `app.py`: runtime coordinator, scanners, schedulers, and processing pipeline.
- `data_manager_config.py`: default settings and constants.
- `data_manager_utils.py`: formatting, resource stats, safe filenames, and helpers.
- `data_manager_media.py`: parsing, ffprobe, quality detection, and naming.
- `data_manager_store.py`: SQLite schema, migrations, settings, accounts, logs, and job stats.
- `data_manager_jobs.py`: background job state and threaded job launcher.
- `data_manager_inventory.py`: cached library walking and inventory collection.
- `data_manager_server.py`: HTTP routes, sessions, auth, SSO, form posts, and API responses.
- `data_manager_views.py`: HTML fragments for pages and panels.
- `data_manager_assets.py`: JavaScript and CSS.
- `pyproject.toml`: project metadata and release version.
