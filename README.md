
# Data Manager

Data Manager watches a downloads folder, detects new video files, renames them, creates the correct library folders, and moves them into movie or TV destinations.

## Run with Docker Compose

This compose file is set up for the Unraid media paths you provided:

- Downloads watched at `/mnt/user/plex-server-media/downloads/completed`
- Movies moved to `/mnt/user/plex-server-media/movies`
- TV episodes moved to `/mnt/user/plex-server-media/tv-shows`
- Malware quarantine stored at `/mnt/user/plex-server-media/downloads/quarantine`

If you run this container on Unraid, those paths can be mounted directly. If you run it on the dev VM instead, mount the Unraid share into the VM first, then update the left side of the volume paths to the VM mount paths.

Then start it:

```bash
docker compose up -d --build
```

## Run Directly On Unraid

Use `docker-compose.unraid.yml` when running Data Manager directly on the Unraid server. It mounts the local Unraid paths instead of the dev VM CIFS mount:

```bash
docker compose -f docker-compose.unraid.yml up -d --build
```

The Unraid compose file uses:

```text
/mnt/user/plex-server-media/downloads/completed -> /watch
/mnt/user/plex-server-media/downloads/to-review -> /to-review
/mnt/user/plex-server-media/downloads/quarantine -> /quarantine
/mnt/user/plex-server-media/movies -> /movies
/mnt/user/plex-server-media/tv-shows -> /tv
```

## Deploy Without Wiping Production Data

Do not copy the local `data/` folder to production. That folder contains the SQLite database with processing history and settings.

Use one of these safe deploy commands from the dev VM:

```bash
scp "/home/t0admnmleon/Data Manager/app.py" "/home/t0admnmleon/Data Manager/Dockerfile" "/home/t0admnmleon/Data Manager/docker-compose.yml" "/home/t0admnmleon/Data Manager/README.md" t0admnmleon@10.60.1.221:/home/t0admnmleon/data-manager/
```

Or, if `rsync` is installed:

```bash
rsync -av --exclude data --exclude __pycache__ "/home/t0admnmleon/Data Manager/" t0admnmleon@10.60.1.221:/home/t0admnmleon/data-manager/
```

Open `http://SERVER-IP:8080`.

Default login:

- Username: `admin`
- Password: `changeme`

Change `DATA_MANAGER_ADMIN_PASSWORD` and `DATA_MANAGER_SESSION_SECRET` before using it for real.

## Metadata Lookup

Data Manager can use TMDB to correct movie titles, movie years, TV show names, TV years, and TV episode names. Create a TMDB API key, then put it in `docker-compose.yml`:

```yaml
environment:
  TMDB_API_KEY: "your-key-here"
```

By default, Data Manager requires a metadata match before moving a file. Movies use TMDB movie search. TV shows use TMDB TV search plus TVmaze fallback for show and episode details. TV lookup also tries common title variants such as `Love Island US`, `Love Island USA`, and `Love Island (US)` so release names can still match the correct database title. If no metadata database match is found, the file is left in the watch folder and a failure is logged for manual review. This prevents release tags like `BDRip`, languages, encoder names, or uploader names from becoming part of the library filename.

## Naming Rules

Movies:

```text
Movie Title (Year)/Movie Title [Year] [Quality].ext
```

TV:

```text
Show Name [Year]/Season 01/Show Name [Year] [S01E01] Episode Name [Quality].ext
```

The app detects TV files from common patterns like `S01E02`, `S01.E02`, `S01 E02`, `1x02`, `Season 1 Episode 2`, and episode files inside `Season 01` folders. Anything without an episode pattern is treated as a movie.

## Duplicate Review Folder

The compose file mounts `/mnt/unraid/plex-server-media/downloads/to-review` as `/to-review`. If Data Manager finds that the same movie file already exists in the corrected movie folder, or the same TV `SxxEyy` already exists in the corrected season folder, it renames the incoming file and moves it to the review folder instead of adding a duplicate to the library.

Review paths use this layout:

```text
/to-review/Movies/Movie Title (Year)/Movie Title [Year] [Quality].ext
/to-review/TV Shows/Show Name [Year]/Season 01/Show Name [Year] [S01E01] Episode Name [Quality].ext
```

## File Management

The File Management page provides manual-only scans for existing libraries:

- Scan Movies renames and reorganizes movie files into the current movie format.
- Scan TV renames show folders to `Show Name [Year]`, creates `Season 01` style folders, and moves episodes into the correct season folder.
- Scan All runs both checks.

Manual scans show a live progress bar, processed count, and completion message. They use the same TMDB/TVmaze matching rules as imports.
When running directly on Unraid, the File Management and Duplicate Checker pages show full library visibility stats, including supported file counts, total supported media size, folders scanned, ignored extensions, and sample files. Set `DATA_MANAGER_LIBRARY_VISIBILITY_SCAN_LIMIT` above `0` if you ever want to cap that visibility scan again.

## Duplicate Checker

The Duplicate Checker page can be run manually and also runs automatically every day at 03:00 server time. It compares library media and stores duplicate findings. The page shows both files side by side with size, quality, path, and a recommended keep file. You can delete either file directly from the result card.

Quality and duplicate recommendations use `ffprobe` when available. The container installs `ffmpeg`, which provides `ffprobe`, so Data Manager can inspect resolution, video codec, audio channels, HDR flags, bitrate, runtime, and file size. Filename quality is still used as a fallback when a file cannot be probed.

Smart conflict rules prefer the better copy by score:

- 4K over 1080p, 1080p over 720p.
- BluRay is preferred over WEB-DL when resolution is otherwise comparable.
- HDR, better codec, more audio channels, higher bitrate, and larger file size are tie-breakers.
- If an incoming file is better than the existing library file, the existing file is moved to the review folder and the incoming file stays in the library.
- If the existing file is same or better, the incoming file is moved to the review folder.

## Malware Checks

Data Manager uses ClamAV for malware and virus scanning. The container installs `clamav`, `clamav-freshclam`, and `clamscan`.

- New downloads are scanned before metadata lookup, renaming, duplicate checks, or moving.
- If ClamAV detects a threat, the original file or original download folder is moved to `/quarantine` without being renamed.
- Manual malware scans can be started from the Malware Checks page for Movies, TV, or All.
- Scheduled malware scans run daily at `DATA_MANAGER_MALWARE_SCAN_HOUR`, default `12`.
- FreshClam definition updates are enabled by default through the `malware_update_definitions` setting.

The Unraid compose file mounts:

```text
/mnt/user/plex-server-media/downloads/quarantine -> /quarantine
```

If ClamAV definitions cannot be updated or loaded, the new-file pipeline fails closed: the file stays in downloads and a critical alert is logged instead of moving an unscanned file into the library.

## System Status And Alerts

Every authenticated page has a top system status strip with container CPU, memory, alert count, queue count, File Management stage, Duplicate Checker stage, and Malware Scan stage. The Alerts menu item shows a red badge only for current failure/critical log entries. General system activity stays on the Logs page.

Notification settings can be controlled separately for successful transfers, failures, duplicate/conflict findings, scan completion, unavailable mounts, metadata provider failures, and malware quarantines.

## Dashboard Workflow

The dashboard shows each file moving through nine stages:

1. Queued: detected and waiting for the file to stop changing.
2. Malware Check: scans the new file or original download folder with ClamAV.
3. Checking: parsing the filename and checking metadata.
4. Renaming: creating the final folder and filename plan.
5. Folder Check: checking whether the corrected movie or show folder already exists, including matching existing folder names.
6. Duplicate Check: checking whether the same movie or TV episode already exists in the destination library.
7. Moving: moving the media and matching sidecar files into the existing, newly created, or review folder.
8. Completed or failed: transferred media is verified in the destination.
9. Cleanup: if the source media came from a subfolder under the watch folder and no other supported media remains there, the original source folder is removed.

Logs can be exported as CSV or cleared by category from the web UI.

## Notifications

Data Manager can send Pushover alerts when a file completes or fails. In Settings:

- Set `Enable Pushover notifications` to `yes`.
- Enter your `Pushover app token`.
- Enter your `Pushover user/group key`.
- Optionally enter a device name if alerts should only go to one device.
- Leave `Notify successful transfers` and `Notify failures` set to `yes` for both alert types.

Successful alerts include the original filename, corrected filename, destination path, media type, and metadata source. Failure alerts include the original path and error message.

After saving settings, use **Send Test Alert** on the Settings page to validate the token, user/group key, optional device, and message delivery. The dashboard Pushover health check uses Pushover's user/group validation endpoint and caches the result briefly so the 5-second dashboard refresh does not spam the API.

## Container Health

The dashboard health checks include container CPU and memory usage when Docker cgroup stats are available inside the container.

- Below 80% is shown as good.
- 80% to 89.9% is shown as warn.
- 90% and above is shown as critical.

CPU usage is sampled between dashboard refreshes, so the first reading after startup may show `0.0%` until a second sample is available. The memory card uses container cgroup stats and reports working memory separately from filesystem cache when Docker exposes those counters.
The compose file sets `mem_limit: 4g` and `DATA_MANAGER_MEMORY_LIMIT_BYTES: 4294967296` so large SMB/CIFS transfers have enough room for cache without making the app look critical during every movie move.

## Queue And Memory Limits

The scanner is intentionally bounded for large imports:

- `DATA_MANAGER_MAX_READY_PER_SCAN`: number of ready files processed per scan loop.
- `DATA_MANAGER_MAX_QUEUE_DISPLAY`: number of queued files rendered in the dashboard.
- `DATA_MANAGER_TRANSFER_CHUNK_SIZE`: bytes read into memory per transfer chunk. Default is `1048576` (1 MB).
- `DATA_MANAGER_MAX_NEW_FILE_EVENTS_PER_SCAN`: number of new-file queue events logged per scan.
- `DATA_MANAGER_MAX_REQUEUE_PER_CLICK`: number of current watch files reset by one dashboard requeue click.
- `DATA_MANAGER_MEDIA_SCAN_WORKERS`: number of read-only duplicate-scan workers. Default is `2`.
- `DATA_MANAGER_FFPROBE_TIMEOUT`: seconds allowed for one ffprobe inspection. Default is `20`.
- `DATA_MANAGER_MALWARE_SCAN_HOUR`: scheduled daily malware scan hour. Default is `12`.
- `DATA_MANAGER_MALWARE_SCAN_TIMEOUT`: seconds allowed for one ClamAV scan command. Default is `900`.
- `DATA_MANAGER_MALWARE_SCAN_WORKERS`: number of parallel ClamAV workers for manual/scheduled library scans. Default is `2`.

Defaults are conservative so large movie batches do not create a huge dashboard response or Python memory spike. Linux and Docker may still show high memory during large SMB/CIFS copies because the kernel uses free RAM as filesystem cache; that memory is normally reclaimable and is not the app loading the whole movie into Python.

## Delete Guard

Data Manager defaults to moving media into the destination library:

- Media is transferred into the destination folder and then removed from the watch folder after the destination verifies.
- Sidecar files follow the selected transfer mode.
- The health check writes a small `.data-manager-healthcheck` probe file but does not delete it.
- App logs can still be cleared from the dashboard. The delete guard is for media files and mounted media folders, not the app's SQLite log records.
- Malware detections are moved to quarantine. This is an intentional safety exception to keep infected files out of the active downloads and library folders.

Use the `transfer_mode` setting to choose `move` or `copy`. Use `move` if you do not want the original file left in downloads.

Note: normal Linux, Docker, and SMB/CIFS permissions do not provide a simple "write but cannot delete" mode for a writable directory. If a process can write to a directory, it can usually remove files from that directory. This app-level guard avoids delete calls, but OS-level enforcement requires more advanced storage permissions or snapshots.

## Good Future Features

- Manual review queue for files that cannot be confidently identified.
- Dry-run mode so you can preview renames before moving files.
- Duplicate detection and conflict rules.
- Support for subtitles and sidecar files by language tags.
- Notifications through Discord, Slack, email, or Gotify.
- Per-library rules, such as anime handling or 4K movie destinations.
- Import history search and CSV export.
- Role-based users if more than one admin will manage it.
- Health checks for mount availability and write permissions.
- Approval workflow for low-confidence metadata matches.
- Retention policies for old logs and completed queue entries.
=======
# Data-Manager
Scans and renames/ moves your media from a single download folder to seprate folders, example if you have tv shows and movies all downloading to the same folder, this will scan each item and it will scan, check for virus's, rename, check if this file already exists, if it doesn't it will move to correct tv or movie folder. Plus more

