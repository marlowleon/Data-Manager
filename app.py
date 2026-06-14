#!/usr/bin/env python3
import base64
import concurrent.futures
import hashlib
import hmac
import html
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import csv
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_NAME = "Data Manager"
DB_PATH = Path(os.environ.get("DATA_MANAGER_DB", "/data/data-manager.db"))
HOST = os.environ.get("DATA_MANAGER_HOST", "0.0.0.0")
PORT = int(os.environ.get("DATA_MANAGER_PORT", "8080"))
SESSION_SECRET = os.environ.get("DATA_MANAGER_SESSION_SECRET", "change-me-in-production")
ADMIN_USER = os.environ.get("DATA_MANAGER_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("DATA_MANAGER_ADMIN_PASSWORD", "changeme")
TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "")
TMDB_BASE_URL = "https://api.themoviedb.org/3"
TVMAZE_BASE_URL = "https://api.tvmaze.com"
STAGE_PAUSE_SECONDS = 10
COMPLETION_VISIBLE_SECONDS = 10
CLEANUP_VISIBLE_SECONDS = 5
MAX_READY_PER_SCAN = int(os.environ.get("DATA_MANAGER_MAX_READY_PER_SCAN", "5"))
MAX_QUEUE_DISPLAY = int(os.environ.get("DATA_MANAGER_MAX_QUEUE_DISPLAY", "50"))
TRANSFER_CHUNK_SIZE = int(os.environ.get("DATA_MANAGER_TRANSFER_CHUNK_SIZE", str(1024 * 1024)))
MAX_NEW_FILE_EVENTS_PER_SCAN = int(os.environ.get("DATA_MANAGER_MAX_NEW_FILE_EVENTS_PER_SCAN", "25"))
MAX_REQUEUE_PER_CLICK = int(os.environ.get("DATA_MANAGER_MAX_REQUEUE_PER_CLICK", "100"))
DUPLICATE_SCAN_HOUR = int(os.environ.get("DATA_MANAGER_DUPLICATE_SCAN_HOUR", "3"))
LIBRARY_VISIBILITY_SCAN_LIMIT = int(os.environ.get("DATA_MANAGER_LIBRARY_VISIBILITY_SCAN_LIMIT", "0"))
LIBRARY_VISIBILITY_CACHE_SECONDS = int(os.environ.get("DATA_MANAGER_LIBRARY_VISIBILITY_CACHE_SECONDS", "300"))
FFPROBE_TIMEOUT = int(os.environ.get("DATA_MANAGER_FFPROBE_TIMEOUT", "20"))
MEDIA_SCAN_WORKERS = int(os.environ.get("DATA_MANAGER_MEDIA_SCAN_WORKERS", "2"))
MALWARE_SCAN_HOUR = int(os.environ.get("DATA_MANAGER_MALWARE_SCAN_HOUR", "12"))
MALWARE_SCAN_TIMEOUT = int(os.environ.get("DATA_MANAGER_MALWARE_SCAN_TIMEOUT", "900"))
MALWARE_SCAN_WORKERS = int(os.environ.get("DATA_MANAGER_MALWARE_SCAN_WORKERS", "2"))

VIDEO_EXTENSIONS = {
    ".3g2", ".3gp", ".avi", ".flv", ".m2ts", ".m4v", ".mkv", ".mov",
    ".mp4", ".mpeg", ".mpg", ".mts", ".ts", ".vob", ".webm", ".wmv",
}
SIDE_EXTENSIONS = {".srt", ".ass", ".ssa", ".sub", ".idx", ".nfo", ".jpg", ".jpeg", ".png"}
IGNORED_WORDS = {
    "1080p", "2160p", "720p", "480p", "bluray", "blu-ray", "webrip",
    "webdl", "web-dl", "hdtv", "hdrip", "dvdrip", "x264", "x265",
    "h264", "h265", "hevc", "aac", "dts", "yify", "rarbg", "proper",
    "repack", "extended", "remastered", "uhd", "hdr", "10bit",
    "bdrip", "brrip", "ita", "eng", "multi", "dual", "audio",
    "itvx", "web", "dl", "web dl", "aac2", "aac2 0", "h 264", "rawr",
}
DEFAULT_SETTINGS = {
    "watch_folder": "/watch",
    "movie_folder": "/movies",
    "tv_folder": "/tv",
    "review_folder": "/to-review",
    "quarantine_folder": "/quarantine",
    "poll_interval": "15",
    "stable_seconds": "30",
    "movie_extensions": ",".join(sorted(VIDEO_EXTENSIONS)),
    "metadata_provider": "tmdb",
    "metadata_enabled": "yes",
    "metadata_required": "yes",
    "transfer_mode": "move",
    "pushover_enabled": "no",
    "pushover_app_token": "",
    "pushover_user_key": "",
    "pushover_device": "",
    "notify_success": "yes",
    "notify_failure": "yes",
    "notify_duplicate": "yes",
    "notify_scan_complete": "yes",
    "notify_mount_unavailable": "yes",
    "notify_metadata_down": "yes",
    "notify_malware": "yes",
    "malware_enabled": "yes",
    "malware_update_definitions": "yes",
    "malware_daily_hour": str(MALWARE_SCAN_HOUR),
}

db_lock = threading.Lock()
scan_event = threading.Event()
inventory_lock = threading.Lock()
resource_lock = threading.Lock()
last_cpu_sample = {"time": time.time(), "usage_usec": None}
pushover_lock = threading.Lock()
pushover_validation_cache = {"checked_at": 0, "settings_key": "", "result": None}
media_info_lock = threading.Lock()
media_info_cache = {}
malware_lock = threading.Lock()
malware_definition_cache = {"checked_at": 0, "ok": False, "detail": "Not checked yet"}
watch_inventory_cache = {
    "total": 0,
    "supported": 0,
    "ignored_exts": {},
    "samples": [],
    "updated_at": "Never",
}
job_lock = threading.Lock()
library_visibility_lock = threading.Lock()
library_visibility_cache = {}
jobs = {
    "file_management": {
        "running": False,
        "kind": "Idle",
        "progress": 0,
        "processed": 0,
        "total": 0,
        "started_at": "",
        "updated_at": "",
        "stage": "Idle",
        "current_folder": "",
        "current_file": "",
        "last_success_at": "",
        "last_error": "",
        "changed": 0,
        "failed": 0,
        "activity": [],
        "message": "No manual scan running",
    },
    "duplicate_checker": {
        "running": False,
        "kind": "Idle",
        "progress": 0,
        "processed": 0,
        "total": 0,
        "started_at": "",
        "updated_at": "",
        "stage": "Idle",
        "current_folder": "",
        "current_file": "",
        "last_success_at": "",
        "last_error": "",
        "open_count": 0,
        "resolved_count": 0,
        "activity": [],
        "message": "No duplicate scan running",
    },
    "malware_scanner": {
        "running": False,
        "kind": "Idle",
        "progress": 0,
        "processed": 0,
        "total": 0,
        "started_at": "",
        "updated_at": "",
        "stage": "Idle",
        "current_folder": "",
        "current_file": "",
        "last_success_at": "",
        "last_error": "",
        "changed": 0,
        "failed": 0,
        "infected": 0,
        "quarantined": 0,
        "activity": [],
        "message": "No malware scan running",
    },
}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock, db() as conn:
        conn.executescript(
            """
            create table if not exists settings (
                key text primary key,
                value text not null
            );
            create table if not exists events (
                id integer primary key autoincrement,
                created_at text not null,
                media_type text not null,
                status text not null,
                original_path text not null,
                renamed_to text,
                moved_to text,
                message text
            );
            create table if not exists seen_files (
                path text primary key,
                size integer not null,
                mtime real not null,
                first_seen real not null,
                processed integer not null default 0,
                stage text not null default 'queued',
                reason text,
                media_type text,
                planned_name text,
                target_path text,
                last_error text,
                transfer_progress integer not null default 0,
                transferred_bytes integer not null default 0,
                total_bytes integer not null default 0
            );
            create table if not exists duplicate_results (
                id integer primary key autoincrement,
                created_at text not null,
                media_type text not null,
                title text not null,
                item_key text not null,
                file_a text not null,
                file_b text not null,
                size_a integer not null,
                size_b integer not null,
                quality_a text,
                quality_b text,
                recommendation text,
                status text not null default 'open'
            );
            """
        )
        migrate_seen_files(conn)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "insert or ignore into settings (key, value) values (?, ?)",
                (key, value),
            )
        conn.execute(
            "update settings set value = 'move' where key = 'transfer_mode' and value = 'copy'"
        )
        conn.commit()


def migrate_seen_files(conn):
    columns = {row["name"] for row in conn.execute("pragma table_info(seen_files)").fetchall()}
    migrations = {
        "stage": "alter table seen_files add column stage text not null default 'queued'",
        "reason": "alter table seen_files add column reason text",
        "media_type": "alter table seen_files add column media_type text",
        "planned_name": "alter table seen_files add column planned_name text",
        "target_path": "alter table seen_files add column target_path text",
        "last_error": "alter table seen_files add column last_error text",
        "transfer_progress": "alter table seen_files add column transfer_progress integer not null default 0",
        "transferred_bytes": "alter table seen_files add column transferred_bytes integer not null default 0",
        "total_bytes": "alter table seen_files add column total_bytes integer not null default 0",
    }
    for column, statement in migrations.items():
        if column not in columns:
            conn.execute(statement)


def get_settings():
    with db_lock, db() as conn:
        rows = conn.execute("select key, value from settings").fetchall()
    settings = DEFAULT_SETTINGS.copy()
    settings.update({row["key"]: row["value"] for row in rows})
    return settings


def save_settings(values):
    with db_lock, db() as conn:
        for key in DEFAULT_SETTINGS:
            conn.execute(
                "insert into settings (key, value) values (?, ?) "
                "on conflict(key) do update set value=excluded.value",
                (key, values.get(key, DEFAULT_SETTINGS[key]).strip()),
            )
        conn.commit()


def add_event(media_type, status, original_path, renamed_to=None, moved_to=None, message=None):
    with db_lock, db() as conn:
        conn.execute(
            """
            insert into events
            (created_at, media_type, status, original_path, renamed_to, moved_to, message)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (now_iso(), media_type, status, str(original_path), renamed_to, moved_to, message),
        )
        conn.commit()


def get_events(limit=80):
    with db_lock, db() as conn:
        return conn.execute(
            "select * from events order by id desc limit ?",
            (limit,),
        ).fetchall()


def clear_events(media_type=None, status=None):
    with db_lock, db() as conn:
        if media_type:
            conn.execute("delete from events where media_type = ?", (media_type,))
        elif status:
            conn.execute("delete from events where status = ?", (status,))
        else:
            conn.execute("delete from events")
        conn.commit()


def export_events():
    rows = get_events(5000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "media_type", "status", "original_path", "renamed_to", "moved_to", "message"])
    for row in reversed(rows):
        writer.writerow([
            row["id"], row["created_at"], row["media_type"], row["status"],
            row["original_path"], row["renamed_to"], row["moved_to"], row["message"],
        ])
    return output.getvalue()


def get_queue():
    settings = get_settings()
    stable_seconds = max(0, int(settings.get("stable_seconds", "30") or "30"))
    now = time.time()
    with db_lock, db() as conn:
        rows = conn.execute(
            "select * from seen_files where processed = 0 order by first_seen limit ?",
            (MAX_QUEUE_DISPLAY,),
        ).fetchall()
    queue = []
    for row in rows:
        remaining = max(0, int(stable_seconds - (now - row["first_seen"])))
        reason = row["reason"] or "Waiting to be scanned"
        if row["stage"] == "queued" and remaining:
            reason = f"Waiting {remaining}s for file to stay stable before processing"
        item = {**dict(row), "remaining_seconds": remaining, "reason": reason}
        item["display_file"] = Path(row["path"]).name
        queue.append(item)
    return queue


def stats():
    with db_lock, db() as conn:
        totals = conn.execute(
            "select media_type, status, count(*) as total from events group by media_type, status"
        ).fetchall()
        queued = conn.execute("select count(*) as total from seen_files where processed = 0").fetchone()
        active = conn.execute("select count(*) as total from seen_files where processed = 0 and stage != 'queued'").fetchone()
    watch_inventory = get_watch_inventory_cache()
    result = {
        "movie": {"done": 0, "error": 0},
        "tv": {"done": 0, "error": 0},
        "queued": queued["total"],
        "active": active["total"],
        "display_limit": MAX_QUEUE_DISPLAY,
        "hidden_queue": max(0, queued["total"] - MAX_QUEUE_DISPLAY),
        "watch_visible": watch_inventory["supported"],
        "watch_total": watch_inventory["total"],
        "watch_inventory_updated_at": watch_inventory["updated_at"],
    }
    for row in totals:
        result.setdefault(row["media_type"], {})
        result[row["media_type"]][row["status"]] = row["total"]
    return result


def get_watch_inventory_cache():
    with inventory_lock:
        return {
            "total": watch_inventory_cache["total"],
            "supported": watch_inventory_cache["supported"],
            "ignored_exts": dict(watch_inventory_cache["ignored_exts"]),
            "samples": list(watch_inventory_cache["samples"]),
            "updated_at": watch_inventory_cache["updated_at"],
        }


def update_watch_inventory_cache(inventory):
    with inventory_lock:
        watch_inventory_cache.update({
            "total": inventory["total"],
            "supported": inventory["supported"],
            "ignored_exts": dict(inventory["ignored_exts"]),
            "samples": list(inventory["samples"]),
            "updated_at": now_iso(),
        })


def count_watch_files(settings):
    return watch_file_inventory(settings)["supported"]


def watch_file_inventory(settings):
    watch_folder = Path(settings["watch_folder"])
    inventory = {"total": 0, "supported": 0, "ignored_exts": {}, "samples": []}
    if not watch_folder.exists():
        return inventory
    exts = extension_set(settings)
    for path in watch_folder.rglob("*"):
        if not path.is_file():
            continue
        inventory["total"] += 1
        suffix = path.suffix.lower() or "(none)"
        if suffix in exts:
            inventory["supported"] += 1
        else:
            inventory["ignored_exts"][suffix] = inventory["ignored_exts"].get(suffix, 0) + 1
            if len(inventory["samples"]) < 5:
                inventory["samples"].append(str(path))
    return inventory


def inventory_message(inventory, settings):
    ignored = ", ".join(
        f"{ext}: {count}" for ext, count in sorted(inventory["ignored_exts"].items())
    ) or "none"
    samples = "; ".join(inventory["samples"]) or "none"
    return (
        f"Watch scan at {settings['watch_folder']}: "
        f"{inventory['total']} total files, {inventory['supported']} supported media files. "
        f"Ignored extensions: {ignored}. Samples: {samples}"
    )


def requeue_watch_files():
    settings = get_settings()
    watch_folder = Path(settings["watch_folder"])
    if not watch_folder.exists():
        add_event("system", "error", watch_folder, message="Cannot requeue: watch folder does not exist")
        return 0
    inventory = watch_file_inventory(settings)
    update_watch_inventory_cache(inventory)
    exts = extension_set(settings)
    now = time.time()
    stable_seconds = max(0, int(settings.get("stable_seconds", "30") or "30"))
    ready_time = now - stable_seconds - 1
    count = 0
    with db_lock, db() as conn:
        for path in watch_folder.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if count >= MAX_REQUEUE_PER_CLICK:
                break
            stat = path.stat()
            conn.execute(
                """
                insert into seen_files
                (path, size, mtime, first_seen, processed, stage, reason, transfer_progress, transferred_bytes, total_bytes)
                values (?, ?, ?, ?, 0, 'queued', ?, 0, 0, 0)
                on conflict(path) do update set
                    size = excluded.size,
                    mtime = excluded.mtime,
                    first_seen = excluded.first_seen,
                    processed = 0,
                    stage = 'queued',
                    reason = excluded.reason,
                    media_type = null,
                    planned_name = null,
                    target_path = null,
                    last_error = null,
                    transfer_progress = 0,
                    transferred_bytes = 0,
                    total_bytes = 0
                """,
                (str(path), stat.st_size, stat.st_mtime, ready_time, "Manually requeued and ready for processing"),
            )
            count += 1
        conn.commit()
    add_event(
        "system",
        "stage_queued",
        watch_folder,
        message=(
            f"Manually requeued {count} watch files for immediate processing "
            f"(limit {MAX_REQUEUE_PER_CLICK} per click). {inventory_message(inventory, settings)}"
        ),
    )
    scan_event.set()
    return count


def dashboard_health():
    settings = get_settings()
    checks = [
        tmdb_health_check(),
        tmdb_tv_health_check(),
        ffprobe_health_check(),
        clamav_health_check(settings),
        pushover_health_check(settings),
        path_health_check("Watch mount", settings["watch_folder"], needs_write=True),
        path_health_check("Movie mount", settings["movie_folder"], needs_write=True),
        path_health_check("TV mount", settings["tv_folder"], needs_write=True),
        path_health_check("Review mount", settings["review_folder"], needs_write=True),
        path_health_check("Quarantine mount", settings["quarantine_folder"], needs_write=True),
        path_health_check("Database", DB_PATH.parent, needs_write=True),
    ]
    return checks


def resource_health_check(name, value):
    if value is None:
        return {"name": name, "status": "warn", "detail": "Usage unavailable"}
    if isinstance(value, dict):
        percent = value.get("percent")
        detail = value.get("detail")
        if percent is None:
            return {"name": name, "status": "warn", "detail": detail or "Usage unavailable"}
        extra_detail = detail
        value = percent
    else:
        extra_detail = None
    if value >= 90:
        status = "fail"
        label = "critical"
    elif value >= 80:
        status = "warn"
        label = "warn"
    else:
        status = "ok"
        label = "good"
    detail = extra_detail or f"{value:.1f}% used ({label})"
    return {"name": name, "status": status, "detail": detail}


def container_memory_percent():
    current = first_int_file([
        "/sys/fs/cgroup/memory.current",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes",
    ])
    cache = container_memory_cache_bytes()
    working = max(0, current - cache) if current is not None and cache is not None else current
    limit = memory_limit_bytes()
    if current is None:
        return {"percent": None, "detail": "Usage unavailable"}
    if limit:
        measured = working if working is not None else current
        percent = min(100.0, (measured / limit) * 100)
        cache_detail = f"; cache {format_bytes(cache)}" if cache else ""
        return {
            "percent": percent,
            "detail": f"{format_bytes(measured)} working / {format_bytes(limit)} limit ({percent:.1f}%){cache_detail}",
        }
    host_total = proc_memtotal_bytes()
    if host_total:
        measured = working if working is not None else current
        percent = min(100.0, (measured / host_total) * 100)
        cache_detail = f"; cache {format_bytes(cache)}" if cache else ""
        return {
            "percent": percent,
            "detail": f"{format_bytes(measured)} working ({percent:.1f}% of host memory; no Docker memory limit){cache_detail}",
        }
    return {"percent": None, "detail": f"{format_bytes(current)} used; limit unavailable"}


def container_memory_cache_bytes():
    stats = read_key_value_file("/sys/fs/cgroup/memory.stat")
    if stats:
        return stats.get("inactive_file", stats.get("file"))
    stats = read_key_value_file("/sys/fs/cgroup/memory/memory.stat")
    if stats:
        return stats.get("total_inactive_file", stats.get("cache"))
    return None


def memory_limit_bytes():
    max_value = read_text_file("/sys/fs/cgroup/memory.max")
    if max_value and max_value != "max":
        try:
            value = int(max_value)
            if 0 < value < 1 << 60:
                return value
        except ValueError:
            pass
    value = read_int_file("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if value and 0 < value < 1 << 60:
        return value
    env_limit = os.environ.get("DATA_MANAGER_MEMORY_LIMIT_BYTES", "").strip()
    if env_limit:
        try:
            value = int(env_limit)
            if value > 0:
                return value
        except ValueError:
            pass
    return None


def proc_memtotal_bytes():
    text = read_text_file("/proc/meminfo")
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1]) * 1024
    return None


def container_cpu_percent():
    usage = read_cpu_usage_usec()
    now = time.time()
    if usage is None:
        return None
    with resource_lock:
        previous_usage = last_cpu_sample["usage_usec"]
        previous_time = last_cpu_sample["time"]
        last_cpu_sample["usage_usec"] = usage
        last_cpu_sample["time"] = now
    if previous_usage is None:
        return 0.0
    elapsed = max(0.001, now - previous_time)
    cpu_count = effective_cpu_count()
    used_seconds = (usage - previous_usage) / 1_000_000
    return max(0.0, min(100.0, (used_seconds / (elapsed * cpu_count)) * 100))


def read_cpu_usage_usec():
    text = read_text_file("/sys/fs/cgroup/cpu.stat")
    if not text:
        return None
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key == "usage_usec":
            return int(value)
    return None


def effective_cpu_count():
    quota_text = read_text_file("/sys/fs/cgroup/cpu.max")
    if quota_text:
        quota, _, period = quota_text.partition(" ")
        if quota != "max":
            try:
                return max(1.0, int(quota) / int(period))
            except Exception:
                pass
    return max(1, os.cpu_count() or 1)


def read_int_file(path):
    text = read_text_file(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def first_int_file(paths):
    for path in paths:
        value = read_int_file(path)
        if value is not None:
            return value
    return None


def read_key_value_file(path):
    text = read_text_file(path)
    if not text:
        return {}
    values = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        try:
            values[key] = int(value)
        except ValueError:
            continue
    return values


def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def tmdb_health_check():
    if not TMDB_API_KEY:
        return {
            "name": "TMDB API",
            "status": "fail",
            "detail": "TMDB_API_KEY is missing",
        }
    try:
        data = tmdb_get("/search/movie", {"query": "Fight Club", "year": "1999", "include_adult": "false", "page": "1"})
        if data and isinstance(data.get("results"), list):
            return {
                "name": "TMDB API",
                "status": "ok",
                "detail": "API key accepted and search is responding",
            }
        return {
            "name": "TMDB API",
            "status": "warn",
            "detail": "API responded, but the response did not include results",
        }
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            detail = "API key rejected by TMDB"
        else:
            detail = f"HTTP {exc.code} from TMDB"
        return {"name": "TMDB API", "status": "fail", "detail": detail}
    except Exception as exc:
        return {"name": "TMDB API", "status": "fail", "detail": f"Connection failed: {exc}"}


def ffprobe_health_check():
    if not shutil.which("ffprobe"):
        return {"name": "ffprobe", "status": "fail", "detail": "ffprobe is not installed in the container"}
    try:
        result = subprocess.run(["ffprobe", "-version"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0:
            first_line = (result.stdout or "ffprobe available").splitlines()[0]
            return {"name": "ffprobe", "status": "ok", "detail": first_line[:120]}
        return {"name": "ffprobe", "status": "fail", "detail": "ffprobe command failed"}
    except Exception as exc:
        return {"name": "ffprobe", "status": "fail", "detail": str(exc)}


def clamav_health_check(settings):
    if not setting_enabled(settings, "malware_enabled"):
        return {"name": "ClamAV Malware Scan", "status": "warn", "detail": "Malware scanning is disabled"}
    if not shutil.which("clamscan"):
        return {"name": "ClamAV Malware Scan", "status": "fail", "detail": "clamscan is not installed in the container"}
    try:
        result = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=10, check=False)
    except Exception as exc:
        return {"name": "ClamAV Malware Scan", "status": "fail", "detail": str(exc)}
    version = (result.stdout or result.stderr or "ClamAV available").strip().splitlines()[0]
    with malware_lock:
        cached = dict(malware_definition_cache)
    if cached["ok"]:
        return {"name": "ClamAV Malware Scan", "status": "ok", "detail": f"{version}; definitions ready"}
    if time.time() - cached["checked_at"] < 3600:
        return {"name": "ClamAV Malware Scan", "status": "warn", "detail": f"{version}; {cached['detail']}"}
    if clamav_database_available():
        return {"name": "ClamAV Malware Scan", "status": "ok", "detail": f"{version}; local definitions present"}
    return {"name": "ClamAV Malware Scan", "status": "warn", "detail": f"{version}; definitions not verified yet"}


def tmdb_tv_health_check():
    if not TMDB_API_KEY:
        return {
            "name": "TMDB TV API",
            "status": "fail",
            "detail": "TMDB_API_KEY is missing",
        }
    try:
        data = tmdb_get("/search/tv", {"query": "Breaking Bad", "first_air_date_year": "2008", "include_adult": "false", "page": "1"})
        if data and isinstance(data.get("results"), list):
            return {
                "name": "TMDB TV API",
                "status": "ok",
                "detail": "TV database search is responding",
            }
        return {
            "name": "TMDB TV API",
            "status": "warn",
            "detail": "TV API responded, but the response did not include results",
        }
    except urllib.error.HTTPError as exc:
        detail = "API key rejected by TMDB" if exc.code in {401, 403} else f"HTTP {exc.code} from TMDB"
        return {"name": "TMDB TV API", "status": "fail", "detail": detail}
    except Exception as exc:
        return {"name": "TMDB TV API", "status": "fail", "detail": f"Connection failed: {exc}"}


def pushover_health_check(settings):
    if not setting_enabled(settings, "pushover_enabled"):
        return {"name": "Pushover", "status": "warn", "detail": "Notifications are disabled"}
    if not settings.get("pushover_app_token", "").strip() or not settings.get("pushover_user_key", "").strip():
        return {"name": "Pushover", "status": "fail", "detail": "Token or user key is missing"}
    return validate_pushover_cached(settings)


def validate_pushover_cached(settings, force=False):
    settings_key = "|".join([
        settings.get("pushover_app_token", "").strip(),
        settings.get("pushover_user_key", "").strip(),
        settings.get("pushover_device", "").strip(),
    ])
    now = time.time()
    with pushover_lock:
        cached = pushover_validation_cache["result"]
        fresh = now - pushover_validation_cache["checked_at"] < 300
        if cached and fresh and pushover_validation_cache["settings_key"] == settings_key and not force:
            return cached
    result = validate_pushover(settings)
    with pushover_lock:
        pushover_validation_cache.update({
            "checked_at": now,
            "settings_key": settings_key,
            "result": result,
        })
    return result


def validate_pushover(settings):
    payload = {
        "token": settings.get("pushover_app_token", "").strip(),
        "user": settings.get("pushover_user_key", "").strip(),
    }
    device = settings.get("pushover_device", "").strip()
    if device:
        payload["device"] = device
    try:
        data = post_form("https://api.pushover.net/1/users/validate.json", payload, timeout=8)
        if data.get("status") == 1:
            devices = data.get("devices") or []
            device_detail = f"; devices: {', '.join(devices[:5])}" if devices else ""
            return {"name": "Pushover", "status": "ok", "detail": f"Connection valid{device_detail}"}
        return {"name": "Pushover", "status": "fail", "detail": pushover_error_detail(data)}
    except urllib.error.HTTPError as exc:
        return {"name": "Pushover", "status": "fail", "detail": f"Validation failed: HTTP {exc.code}"}
    except Exception as exc:
        return {"name": "Pushover", "status": "fail", "detail": f"Validation failed: {exc}"}


def path_health_check(name, path_value, needs_write=False):
    path = Path(path_value)
    if not path.exists():
        return {"name": name, "status": "fail", "detail": f"{path} does not exist"}
    if not path.is_dir():
        return {"name": name, "status": "fail", "detail": f"{path} is not a directory"}
    if not os.access(path, os.R_OK | os.X_OK):
        return {"name": name, "status": "fail", "detail": f"{path} is not readable"}
    if needs_write:
        probe = path / ".data-manager-healthcheck"
        try:
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write(now_iso())
        except Exception as exc:
            return {"name": name, "status": "fail", "detail": f"{path} is not writable: {exc}"}
    return {"name": name, "status": "ok", "detail": f"{path} is available"}


def sign(value):
    sig = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def verify_signed(cookie):
    if not cookie or "." not in cookie:
        return None
    value, sig = cookie.rsplit(".", 1)
    expected = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return value
    return None


def clean_title(text):
    text = strip_known_extension(text)
    text = re.sub(r"^\s*(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}\s*[-_ ]+\s*", " ", text, flags=re.I)
    text = re.sub(r"[._]+", " ", text)
    text = re.sub(r"\bH[ ._-]?264\b", "h264", text, flags=re.I)
    text = re.sub(r"\bH[ ._-]?265\b", "h265", text, flags=re.I)
    text = re.sub(r"\bWEB[ ._-]?DL\b", "webdl", text, flags=re.I)
    text = re.sub(r"\bAAC[ ._-]?2[ ._-]?0\b", "aac", text, flags=re.I)
    text = re.sub(r"\[[^\]]+\]|\([^\)]*\b(?:1080p|720p|2160p|x264|x265|hevc)\b[^\)]*\)", " ", text, flags=re.I)
    text = re.sub(r"[\[\]\(\)]", " ", text)
    text = re.sub(r"-[A-Za-z0-9]+$", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" -._")
    tokens = []
    for token in text.split():
        if token.lower() in IGNORED_WORDS:
            break
        tokens.append(token)
    cleaned = " ".join(tokens).strip(" -._")
    return title_case(cleaned) if cleaned else "Unknown"


def strip_known_extension(text):
    value = str(text)
    suffix = Path(value).suffix.lower()
    if suffix in VIDEO_EXTENSIONS or suffix in SIDE_EXTENSIONS:
        return str(Path(value).with_suffix(""))
    return value


def title_case(text):
    small = {"a", "an", "and", "as", "at", "but", "by", "for", "in", "nor", "of", "on", "or", "the", "to"}
    words = text.split()
    output = []
    for idx, word in enumerate(words):
        if word.isupper() and len(word) <= 4:
            output.append(word)
            continue
        lower = word.lower()
        output.append(lower if idx and lower in small else lower.capitalize())
    return " ".join(output)


def parse_year(text):
    match = re.search(r"(?:19|20)\d{2}", text)
    return match.group(0) if match else "Unknown Year"


def detect_tv(text):
    patterns = [
        r"\bS(?P<season>\d{1,2})E(?P<episode>\d{1,3})\b",
        r"\bS(?P<season>\d{1,2})[ ._-]+E(?P<episode>\d{1,3})\b",
        r"\b(?P<season>\d{1,2})x(?P<episode>\d{1,3})\b",
        r"\bSeason[ ._-]*(?P<season>\d{1,2})[ ._-]*Episode[ ._-]*(?P<episode>\d{1,3})\b",
        r"\bSeason[ ._-]*(?P<season>\d{1,2})[ ._-]*(?P<episode>\d{1,3})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match
    return None


def parse_tv(path):
    stem = strip_known_extension(path.name)
    tv_match = detect_tv(stem)
    season_from_folder = None
    if not tv_match:
        folder_text = " ".join(part for part in path.parent.parts[-3:])
        season_folder_match = re.search(r"\bSeason[ ._-]*(?P<season>\d{1,2})\b|\bS(?P<season_short>\d{1,2})\b", folder_text, re.I)
        episode_match = re.search(r"(?:^|[ ._-])E?(?P<episode>\d{1,3})(?:[ ._-]|$)", stem, re.I)
        if season_folder_match and episode_match:
            season_from_folder = int(season_folder_match.group("season") or season_folder_match.group("season_short"))
            class FolderTvMatch:
                def __init__(self, match):
                    self._match = match
                def group(self, name):
                    if name == "season":
                        return str(season_from_folder)
                    return self._match.group(name)
                def start(self):
                    return self._match.start()
                def end(self):
                    return self._match.end()
            tv_match = FolderTvMatch(episode_match)
    if not tv_match:
        return None

    title_part = stem[:tv_match.start()]
    if season_from_folder and not title_part.strip(" ._-"):
        title_part = infer_show_title_from_folders(path)
    after_part = stem[tv_match.end():]
    year = parse_year(title_part)
    title_part = re.sub(r"(?:19|20)\d{2}", " ", title_part)
    title = clean_title(title_part)
    season = int(tv_match.group("season"))
    episode = int(tv_match.group("episode"))
    episode_name = clean_title(after_part) if after_part.strip(" ._-") else ""
    return {
        "title": title,
        "year": year,
        "season": season,
        "episode": episode,
        "episode_name": "" if episode_name == "Unknown" else episode_name,
    }


def infer_show_title_from_folders(path):
    for part in reversed(path.parent.parts):
        if re.search(r"\bSeason[ ._-]*\d{1,2}\b|\bS\d{1,2}\b", part, re.I):
            continue
        if part in {"/", "", "watch", "downloads", "completed"}:
            continue
        return part
    return path.parent.name


def parse_movie(path):
    stem = strip_known_extension(path.name)
    year = parse_year(stem)
    year_match = re.search(r"(?:19|20)\d{2}", stem)
    title_part = stem[:year_match.start()] if year_match else stem
    return {"title": clean_title(title_part), "year": year}


def quality_label(path):
    info = media_info(path)
    if info.get("resolution_label") != "Unknown":
        if info.get("is_bluray") and info.get("resolution_label") == "4k":
            return "Blueray(4k)"
        return info["resolution_label"]
    return filename_quality_label(path)


def filename_quality_label(path):
    text = " ".join([path.name, path.parent.name]).lower()
    has_4k = bool(re.search(r"\b(2160p|4k|uhd)\b", text))
    has_bluray = bool(re.search(r"\b(blu[ ._-]?ray|bluray|bdrip|brrip)\b", text))
    if has_4k and has_bluray:
        return "Blueray(4k)"
    if has_4k:
        return "4k"
    for value in ("1080p", "720p", "480p"):
        if re.search(rf"\b{value}\b", text):
            return value
    if has_bluray:
        return "Blueray"
    if re.search(r"\b(web[ ._-]?dl|webrip|web)\b", text):
        return "WEB-DL"
    if re.search(r"\bhdtv\b", text):
        return "HDTV"
    return "Unknown"


def media_info(path):
    path = Path(path)
    try:
        stat = path.stat()
    except OSError:
        return fallback_media_info(path)
    cache_key = (str(path), stat.st_size, stat.st_mtime)
    with media_info_lock:
        cached = media_info_cache.get(cache_key)
        if cached:
            return dict(cached)
    info = ffprobe_media_info(path, stat)
    with media_info_lock:
        media_info_cache[cache_key] = dict(info)
        if len(media_info_cache) > 1000:
            media_info_cache.clear()
    return info


def ffprobe_media_info(path, stat):
    base = fallback_media_info(path)
    try:
        result = subprocess.run(
            [
                "ffprobe", "-v", "error",
                "-show_entries",
                "format=duration,bit_rate:stream=index,codec_type,codec_name,width,height,pix_fmt,color_transfer,color_primaries,color_space,channels",
                "-of", "json",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=FFPROBE_TIMEOUT,
            check=False,
        )
    except Exception:
        return base
    if result.returncode != 0 or not result.stdout.strip():
        return base
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return base
    streams = data.get("streams") or []
    video = next((stream for stream in streams if stream.get("codec_type") == "video"), {})
    audio = [stream for stream in streams if stream.get("codec_type") == "audio"]
    fmt = data.get("format") or {}
    width = int(video.get("width") or 0)
    height = int(video.get("height") or 0)
    duration = float(fmt.get("duration") or 0)
    bit_rate = int(fmt.get("bit_rate") or 0)
    if not bit_rate and duration:
        bit_rate = int((stat.st_size * 8) / duration)
    channels = max([int(stream.get("channels") or 0) for stream in audio] or [0])
    hdr = is_hdr_video(video)
    is_bluray = filename_quality_label(path).lower().startswith("blueray")
    return {
        "source": "ffprobe",
        "width": width,
        "height": height,
        "resolution_label": resolution_label(width, height),
        "video_codec": video.get("codec_name") or "unknown",
        "audio_channels": channels,
        "hdr": hdr,
        "bitrate": bit_rate,
        "runtime": duration,
        "is_bluray": is_bluray,
        "size": stat.st_size,
    }


def fallback_media_info(path):
    label = filename_quality_label(path)
    return {
        "source": "filename",
        "width": 0,
        "height": 0,
        "resolution_label": label,
        "video_codec": "unknown",
        "audio_channels": 0,
        "hdr": bool(re.search(r"\b(hdr|dv|dolby[ ._-]?vision)\b", path.name, re.I)),
        "bitrate": 0,
        "runtime": 0,
        "is_bluray": label.lower().startswith("blueray"),
        "size": path.stat().st_size if path.exists() else 0,
    }


def resolution_label(width, height):
    longest = max(width, height)
    if longest >= 3800 or height >= 2000:
        return "4k"
    if height >= 1000 or longest >= 1900:
        return "1080p"
    if height >= 700 or longest >= 1200:
        return "720p"
    if height >= 430:
        return "480p"
    return "Unknown"


def is_hdr_video(video):
    values = " ".join(str(video.get(key) or "").lower() for key in ("pix_fmt", "color_transfer", "color_primaries", "color_space"))
    return any(token in values for token in ("smpte2084", "arib-std-b67", "bt2020", "hdr", "pq", "hlg"))


def movie_folder_name(title, year):
    return safe_name(f"{strip_media_type(title)} ({year})")


def tv_show_folder_name(title, year):
    return safe_name(f"{strip_media_type(title)} [{year}]")


def movie_file_base(title, year, quality):
    return safe_name(f"{strip_media_type(title)} [{year}] [{quality}]")


def tv_file_base(title, year, season, episode, episode_name, quality):
    base = f"{strip_media_type(title)} [{year}] [S{season:02d}E{episode:02d}]"
    if episode_name:
        base += f" {episode_name}"
    base += f" [{quality}]"
    return safe_name(base)


def tmdb_get(endpoint, params):
    if not TMDB_API_KEY:
        return None
    params = dict(params)
    params["api_key"] = TMDB_API_KEY
    params.setdefault("language", "en-US")
    url = f"{TMDB_BASE_URL}{endpoint}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def tvmaze_get(endpoint, params):
    url = f"{TVMAZE_BASE_URL}{endpoint}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def setting_enabled(settings, key):
    return settings.get(key, "no").lower() in {"yes", "true", "1", "on"}


def send_pushover(settings, title, message, priority=0):
    if not setting_enabled(settings, "pushover_enabled"):
        return False
    token = settings.get("pushover_app_token", "").strip()
    user = settings.get("pushover_user_key", "").strip()
    if not token or not user:
        add_event("system", "error", "pushover", message="Pushover is enabled but token or user key is missing")
        return False
    payload = {
        "token": token,
        "user": user,
        "title": title,
        "message": message,
        "priority": str(priority),
    }
    device = settings.get("pushover_device", "").strip()
    if device:
        payload["device"] = device
    try:
        data = post_form("https://api.pushover.net/1/messages.json", payload, timeout=8)
        if data.get("status") != 1:
            raise ValueError(pushover_error_detail(data))
        return True
    except Exception as exc:
        add_event("system", "error", "pushover", message=f"Pushover notification failed: {exc}")
        return False


def post_form(url, payload, timeout=8):
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {}


def pushover_error_detail(data):
    errors = data.get("errors") if isinstance(data, dict) else None
    if errors:
        return "; ".join(str(error) for error in errors)
    if isinstance(data, dict):
        for key, value in data.items():
            if key not in {"status", "request"}:
                return f"{key}: {value}"
    return "Pushover rejected the request"


def test_pushover():
    settings = get_settings()
    validation = validate_pushover_cached(settings, force=True)
    if validation["status"] != "ok":
        add_event("system", "error", "pushover", message=f"Pushover test failed validation: {validation['detail']}")
        return False
    message = "\n".join([
        "Test notification from Data Manager",
        f"Server time: {now_iso()}",
        "If you received this, Pushover alerts are working.",
    ])
    if send_pushover(settings, "Data Manager: Test Alert", message, priority=0):
        add_event("system", "done", "pushover", message="Pushover test notification sent successfully")
        validate_pushover_cached(settings, force=True)
        return True
    return False


def notify_success(settings, media_type, original_path, renamed_to, moved_to, source):
    if not setting_enabled(settings, "notify_success"):
        return
    message = "\n".join([
        "Completed successfully",
        f"Type: {media_type}",
        f"Original: {Path(original_path).name}",
        f"Renamed: {renamed_to}",
        f"Moved to: {moved_to}",
        f"Metadata: {source}",
    ])
    send_pushover(settings, "Data Manager: Completed", message, priority=0)


def notify_failure(settings, original_path, error):
    if not setting_enabled(settings, "notify_failure"):
        return
    message = "\n".join([
        "Processing failed",
        f"Original: {Path(original_path).name}",
        f"Path: {original_path}",
        f"Error: {error}",
    ])
    send_pushover(settings, "Data Manager: Failed", message, priority=1)


def notify_duplicate(settings, detail, existing_path=None, review_path=None):
    if not setting_enabled(settings, "notify_duplicate"):
        return
    message = "\n".join([
        "Duplicate/conflict detected",
        f"Detail: {detail}",
        f"Existing: {existing_path or 'n/a'}",
        f"Review: {review_path or 'n/a'}",
    ])
    send_pushover(settings, "Data Manager: Duplicate", message, priority=0)


def notify_scan_complete(settings, scan_name, message):
    if not setting_enabled(settings, "notify_scan_complete"):
        return
    send_pushover(settings, f"Data Manager: {scan_name} Complete", message, priority=0)


def notify_mount_unavailable(settings, mount_name, path_value):
    if not setting_enabled(settings, "notify_mount_unavailable"):
        return
    send_pushover(settings, "Data Manager: Mount Unavailable", f"{mount_name}: {path_value}", priority=1)


def notify_metadata_down(settings, provider, error):
    if not setting_enabled(settings, "notify_metadata_down"):
        return
    send_pushover(settings, "Data Manager: Metadata Provider Down", f"{provider}: {error}", priority=1)


def notify_malware(settings, original_path, quarantine_path, detail):
    if not setting_enabled(settings, "notify_malware"):
        return
    message = "\n".join([
        "Malware or virus detection",
        f"Original: {original_path}",
        f"Quarantine: {quarantine_path}",
        f"Detail: {detail}",
    ])
    send_pushover(settings, "Data Manager: Malware Quarantined", message, priority=1)


def first_year(value):
    if value and re.match(r"\d{4}-\d{2}-\d{2}", value):
        return value[:4]
    return "Unknown Year"


def metadata_enabled(settings):
    return settings.get("metadata_enabled", "yes").lower() in {"yes", "true", "1", "on"}


def metadata_required(settings):
    return settings.get("metadata_required", "yes").lower() in {"yes", "true", "1", "on"}


def metadata_source_ok(media_type, source):
    if media_type == "tv":
        return source != "filename"
    return source == "tmdb"


def enrich_movie(movie, settings):
    if not metadata_enabled(settings) or settings.get("metadata_provider") != "tmdb":
        return movie, "filename"
    try:
        params = {"query": movie["title"], "include_adult": "false", "page": "1"}
        if movie["year"] != "Unknown Year":
            params["year"] = movie["year"]
        data = tmdb_get("/search/movie", params)
        results = data.get("results", []) if data else []
        if not results and movie["year"] != "Unknown Year":
            data = tmdb_get("/search/movie", {"query": movie["title"], "include_adult": "false", "page": "1"})
            results = data.get("results", []) if data else []
        if results:
            best = results[0]
            title = best.get("title") or best.get("original_title") or movie["title"]
            year = first_year(best.get("release_date")) or movie["year"]
            return {"title": title, "year": year}, "tmdb"
    except Exception as exc:
        add_event("system", "error", movie["title"], message=f"TMDB movie lookup failed: {exc}")
        notify_metadata_down(settings, "TMDB movie", exc)
    return movie, "filename"


def enrich_tv(tv, settings):
    if not metadata_enabled(settings) or settings.get("metadata_provider") != "tmdb":
        return tv, "filename"
    enriched = None
    source = "filename"
    try:
        results = search_tmdb_tv(tv)
        if results:
            best = choose_tmdb_tv_show(results, tv)
            title = best.get("name") or best.get("original_name") or tv["title"]
            year = first_year(best.get("first_air_date")) or tv["year"]
            enriched = dict(tv)
            enriched["title"] = title
            enriched["year"] = year
            source = "tmdb"
            try:
                episode = tmdb_get(
                    f"/tv/{best['id']}/season/{tv['season']}/episode/{tv['episode']}",
                    {},
                )
                if episode and episode.get("name"):
                    enriched["episode_name"] = episode["name"]
            except Exception as exc:
                add_event("system", "error", tv["title"], message=f"TMDB TV episode lookup failed: {exc}; trying TVmaze")
    except Exception as exc:
        add_event("system", "error", tv["title"], message=f"TMDB TV lookup failed: {exc}")
        notify_metadata_down(settings, "TMDB TV", exc)

    tvmaze_enriched, tvmaze_source = enrich_tv_with_tvmaze(enriched or tv)
    if tvmaze_source == "tvmaze":
        return tvmaze_enriched, "tvmaze" if source == "filename" else f"{source}+tvmaze"
    if enriched:
        return enriched, source
    return tv, "filename"


def search_tmdb_tv(tv):
    combined = []
    seen_ids = set()
    for title in tv_title_variants(tv["title"]):
        params = {"query": title, "include_adult": "false", "page": "1"}
        if tv["year"] != "Unknown Year":
            params["first_air_date_year"] = tv["year"]
        data = tmdb_get("/search/tv", params)
        results = data.get("results", []) if data else []
        if not results and tv["year"] != "Unknown Year":
            data = tmdb_get("/search/tv", {"query": title, "include_adult": "false", "page": "1"})
            results = data.get("results", []) if data else []
        for item in results:
            item_id = item.get("id")
            if item_id in seen_ids:
                continue
            seen_ids.add(item_id)
            combined.append(item)
    return combined


def choose_tmdb_tv_show(results, tv):
    desired_country = desired_tv_country(tv["title"])
    title_keys = {normalize_lookup_title(title) for title in tv_title_variants(tv["title"])}
    exact = [
        item for item in results
        if normalize_lookup_title(item.get("name") or item.get("original_name") or "") in title_keys
    ]
    if desired_country:
        country_match = [
            item for item in exact or results
            if desired_country in (item.get("origin_country") or [])
        ]
        if country_match:
            return country_match[0]
    if exact:
        return exact[0]
    if not desired_country and normalize_lookup_title(tv["title"]) == "love island":
        gb = [item for item in results if "GB" in (item.get("origin_country") or [])]
        if gb:
            return gb[0]
    return results[0]


def enrich_tv_with_tvmaze(tv):
    try:
        data = []
        for title in tv_title_variants(tv["title"]):
            data = tvmaze_get("/search/shows", {"q": title})
            if data:
                break
        if not data:
            return tv, "filename"
        best = choose_tvmaze_show(data, tv["title"])
        show = best.get("show", best)
        enriched = dict(tv)
        enriched["title"] = show.get("name") or tv["title"]
        enriched["year"] = first_year(show.get("premiered")) or tv["year"]
        episode = tvmaze_get(
            f"/shows/{show['id']}/episodebynumber",
            {"season": tv["season"], "number": tv["episode"]},
        )
        if episode and episode.get("name"):
            enriched["episode_name"] = episode["name"]
        return enriched, "tvmaze"
    except Exception as exc:
        add_event("system", "error", tv["title"], message=f"TVmaze lookup failed: {exc}")
    return tv, "filename"


def choose_tvmaze_show(results, title):
    desired_country = desired_tv_country(title)
    title_keys = {normalize_lookup_title(item) for item in tv_title_variants(title)}
    exact = [
        item for item in results
        if normalize_lookup_title(item.get("show", {}).get("name", "")) in title_keys
    ]
    if desired_country:
        country_match = [
            item for item in exact or results
            if tvmaze_show_country(item.get("show", {})) == desired_country
        ]
        if country_match:
            return country_match[0]
    gb = [
        item for item in exact
        if tvmaze_show_country(item.get("show", {})) == "GB"
    ]
    if gb:
        return gb[0]
    if exact:
        return exact[0]
    return results[0]


def tv_title_variants(title):
    variants = []

    def add(value):
        value = re.sub(r"\s+", " ", value).strip()
        if value and value.lower() not in {item.lower() for item in variants}:
            variants.append(value)

    add(title)
    usa_title = re.sub(r"\bU[ ._-]?S[ ._-]?A?\b$", "USA", title, flags=re.I)
    add(usa_title)
    add(re.sub(r"\bUSA\b$", "(US)", usa_title, flags=re.I))
    add(re.sub(r"\bUSA\b$", "United States", usa_title, flags=re.I))
    add(re.sub(r"\bUK\b$", "United Kingdom", title, flags=re.I))
    return variants


def normalize_lookup_title(title):
    title = re.sub(r"\(\s*U[ ._-]?S[ ._-]?A?\s*\)", " USA ", title, flags=re.I)
    title = re.sub(r"\(\s*United States\s*\)", " USA ", title, flags=re.I)
    title = re.sub(r"\(\s*UK\s*\)", " UK ", title, flags=re.I)
    title = re.sub(r"\(\s*United Kingdom\s*\)", " UK ", title, flags=re.I)
    title = re.sub(r"\([^)]*\)", " ", title)
    title = re.sub(r"\bUnited States\b", "USA", title, flags=re.I)
    title = re.sub(r"\bU[ ._-]?S[ ._-]?A?\b", "USA", title, flags=re.I)
    title = re.sub(r"\bUnited Kingdom\b", "UK", title, flags=re.I)
    title = re.sub(r"[^a-z0-9]+", " ", title.lower())
    return re.sub(r"\s+", " ", title).strip()


def desired_tv_country(title):
    normalized = normalize_lookup_title(title)
    if re.search(r"\busa\b$", normalized):
        return "US"
    if re.search(r"\buk\b$", normalized):
        return "GB"
    return None


def tvmaze_show_country(show):
    network = show.get("network") or {}
    web_channel = show.get("webChannel") or {}
    country = (network.get("country") or web_channel.get("country") or {})
    return country.get("code")


def safe_name(name):
    name = re.sub(r'[<>:"/\\|?*]', " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name or "Unknown"


def strip_media_type(name):
    cleaned = str(name).strip()
    for extension in VIDEO_EXTENSIONS:
        if cleaned.lower().endswith(extension):
            cleaned = cleaned[: -len(extension)].strip()
            break
    return cleaned


def library_folder_name(title, year):
    return safe_name(f"{strip_media_type(title)} ({year})")


def resolve_library_folder(root, desired_name):
    root = Path(root)
    desired = root / desired_name
    if desired.exists() and desired.is_dir():
        return desired, True, f"Existing folder found: {desired.name}"
    if root.exists():
        wanted = normalize_folder_name(desired_name)
        for child in root.iterdir():
            if child.is_dir() and normalize_folder_name(child.name) == wanted:
                return child, True, f"Existing folder found with matching name: {child.name}"
    return desired, False, f"Folder does not exist yet and will be created: {desired.name}"


def normalize_folder_name(name):
    name = re.sub(r"[^a-z0-9]+", " ", str(name).lower())
    return re.sub(r"\s+", " ", name).strip()


def duplicate_movie_file(target_dir):
    if not target_dir.exists():
        return None
    for path in target_dir.iterdir():
        if path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS:
            return path
    return None


def duplicate_tv_episode_file(target_dir, season, episode):
    if not target_dir.exists():
        return None
    pattern = re.compile(rf"\bS{season:02d}E{episode:02d}\b", re.I)
    for path in target_dir.iterdir():
        if path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS and pattern.search(path.stem):
            return path
    return None


def review_target(settings, media_type, folder_name, subfolder_name, base_name, suffix):
    root = Path(settings["review_folder"])
    if media_type == "tv":
        target_dir = root / "TV Shows" / folder_name / subfolder_name
    else:
        target_dir = root / "Movies" / folder_name
    return target_dir, unique_path(target_dir / f"{base_name}{suffix.lower()}")


def conflict_decision(incoming, existing, settings, media_type, folder_name, subfolder_name, base_name):
    existing_review_dir, existing_review_file = review_target(settings, media_type, folder_name, subfolder_name, existing.stem, existing.suffix)
    incoming_review_dir, incoming_review_file = review_target(settings, media_type, folder_name, subfolder_name, base_name, incoming.suffix)
    incoming_score = quality_score(incoming)
    existing_score = quality_score(existing)
    if incoming_score > existing_score:
        return {
            "duplicate": True,
            "conflict_action": "replace_with_incoming",
            "existing_duplicate": existing,
            "existing_review_target": existing_review_file,
            "review_dir": existing_review_dir,
            "duplicate_status": (
                f"Incoming file appears higher quality than {existing.name}; "
                f"moving existing file to review and keeping incoming in library"
            ),
        }
    return {
        "duplicate": True,
        "conflict_action": "incoming_to_review",
        "existing_duplicate": existing,
        "existing_review_target": None,
        "review_dir": incoming_review_dir,
        "duplicate_status": (
            f"Existing file appears same or better quality: {existing.name}; "
            f"moving incoming file to review"
        ),
    }


def unique_path(path):
    if not path.exists():
        return path
    counter = 2
    while True:
        candidate = path.with_name(f"{path.stem} ({counter}){path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def set_file_stage(path, stage, reason=None, media_type=None, planned_name=None, target_path=None, last_error=None):
    with db_lock, db() as conn:
        conn.execute(
            """
            update seen_files
            set stage = ?,
                reason = coalesce(?, reason),
                media_type = coalesce(?, media_type),
                planned_name = coalesce(?, planned_name),
                target_path = coalesce(?, target_path),
                last_error = coalesce(?, last_error)
            where path = ?
            """,
            (stage, reason, media_type, planned_name, str(target_path) if target_path else None, last_error, str(path)),
        )
        conn.commit()


def set_transfer_progress(path, transferred_bytes, total_bytes, force=False):
    progress = 100 if total_bytes <= 0 else min(100, int((transferred_bytes / total_bytes) * 100))
    if not force:
        with db_lock, db() as conn:
            row = conn.execute(
                "select transfer_progress from seen_files where path = ?",
                (str(path),),
            ).fetchone()
        if row and row["transfer_progress"] == progress:
            return
    with db_lock, db() as conn:
        conn.execute(
            """
            update seen_files
            set transfer_progress = ?,
                transferred_bytes = ?,
                total_bytes = ?,
                reason = ?
            where path = ?
            """,
            (
                progress,
                transferred_bytes,
                total_bytes,
                f"Transferring file: {progress}% complete",
                str(path),
            ),
        )
        conn.commit()


def build_file_plan(path, settings):
    tv = parse_tv(path)
    if tv:
        tv, source = enrich_tv(tv, settings)
        if metadata_required(settings) and not metadata_source_ok("tv", source):
            raise ValueError("No TV metadata match found; file left in place for manual review")
        quality = quality_label(path)
        show_folder = tv_show_folder_name(tv["title"], tv["year"])
        season_folder = f"Season {tv['season']:02d}"
        base_name = tv_file_base(tv["title"], tv["year"], tv["season"], tv["episode"], tv["episode_name"], quality)
        show_dir, folder_exists, folder_status = resolve_library_folder(settings["tv_folder"], show_folder)
        season_dir = show_dir / season_folder
        if folder_exists and season_dir.exists():
            folder_status = f"{folder_status}; season folder exists: {season_folder}"
        elif folder_exists:
            folder_status = f"{folder_status}; season folder will be created: {season_folder}"
        target_dir = season_dir
        library_target_file = target_dir / f"{base_name}{path.suffix.lower()}"
        duplicate = duplicate_tv_episode_file(target_dir, tv["season"], tv["episode"])
        media_type = "tv"
        if duplicate:
            decision = conflict_decision(path, duplicate, settings, media_type, show_folder, season_folder, base_name)
            duplicate_status = decision["duplicate_status"]
            if decision["conflict_action"] == "incoming_to_review":
                target_dir, target_file = decision["review_dir"], unique_path(decision["review_dir"] / f"{base_name}{path.suffix.lower()}")
            else:
                target_file = library_target_file
        else:
            decision = {}
            target_file = library_target_file
            duplicate_status = "No matching episode found in library; moving to normal TV folder"
        renamed_to = target_file.name
    else:
        movie = parse_movie(path)
        movie, source = enrich_movie(movie, settings)
        if metadata_required(settings) and not metadata_source_ok("movie", source):
            raise ValueError("No TMDB movie match found; file left in place for manual review")
        quality = quality_label(path)
        folder_name = movie_folder_name(movie["title"], movie["year"])
        base_name = movie_file_base(movie["title"], movie["year"], quality)
        target_dir, folder_exists, folder_status = resolve_library_folder(settings["movie_folder"], folder_name)
        library_target_file = target_dir / f"{base_name}{path.suffix.lower()}"
        duplicate = duplicate_movie_file(target_dir)
        media_type = "movie"
        if duplicate:
            decision = conflict_decision(path, duplicate, settings, media_type, folder_name, None, base_name)
            duplicate_status = decision["duplicate_status"]
            if decision["conflict_action"] == "incoming_to_review":
                target_dir, target_file = decision["review_dir"], unique_path(decision["review_dir"] / f"{base_name}{path.suffix.lower()}")
            else:
                target_file = library_target_file
        else:
            decision = {}
            target_file = library_target_file
            duplicate_status = "No matching movie file found in library; moving to normal movie folder"
        renamed_to = target_file.name

    return {
        "media_type": media_type,
        "renamed_to": renamed_to,
        "target_dir": target_dir,
        "target_file": target_file,
        "source": source,
        "folder_exists": folder_exists,
        "folder_status": folder_status,
        "duplicate": bool(duplicate),
        "duplicate_status": duplicate_status,
        "conflict_action": decision.get("conflict_action"),
        "existing_duplicate": decision.get("existing_duplicate"),
        "existing_review_target": decision.get("existing_review_target"),
    }


def process_file(path, settings):
    if path.suffix.lower() not in extension_set(settings):
        return

    quarantined = scan_new_arrival_for_malware(path, settings)
    if quarantined:
        return

    set_file_stage(path, "checking", "Checking file name and metadata")
    add_event("system", "stage_checking", path, message="Stage 3: checking file name and metadata")
    time.sleep(STAGE_PAUSE_SECONDS)
    plan = build_file_plan(path, settings)
    set_file_stage(
        path,
        "renaming",
        "Rename plan created",
        media_type=plan["media_type"],
        planned_name=plan["renamed_to"],
        target_path=plan["target_file"],
    )
    add_event(
        plan["media_type"],
        "stage_renaming",
        path,
        renamed_to=plan["renamed_to"],
        moved_to=str(plan["target_file"]),
        message=f"Stage 4: planned rename using {plan['source']}",
    )
    time.sleep(STAGE_PAUSE_SECONDS)

    set_file_stage(
        path,
        "folder_check",
        plan["folder_status"],
        media_type=plan["media_type"],
        planned_name=plan["renamed_to"],
        target_path=plan["target_file"],
    )
    add_event(
        plan["media_type"],
        "stage_folder_check",
        path,
        renamed_to=plan["renamed_to"],
        moved_to=str(plan["target_file"]),
        message=f"Stage 5: {plan['folder_status']}",
    )
    time.sleep(STAGE_PAUSE_SECONDS)

    set_file_stage(
        path,
        "duplicate_check",
        plan["duplicate_status"],
        media_type=plan["media_type"],
        planned_name=plan["renamed_to"],
        target_path=plan["target_file"],
    )
    add_event(
        plan["media_type"],
        "stage_duplicate_check",
        path,
        renamed_to=plan["renamed_to"],
        moved_to=str(plan["target_file"]),
        message=f"Stage 6: {plan['duplicate_status']}",
    )
    time.sleep(STAGE_PAUSE_SECONDS)

    set_file_stage(path, "moving", "Transferring file into destination folder")
    add_event(
        plan["media_type"],
        "stage_moving",
        path,
        renamed_to=plan["renamed_to"],
        moved_to=str(plan["target_file"]),
        message="Stage 7: transferring file into destination folder",
    )
    target_dir = plan["target_dir"]
    target_file = plan["target_file"]
    transfer_mode = settings.get("transfer_mode", "move").lower()
    if transfer_mode not in {"copy", "move"}:
        transfer_mode = "move"
    expected_size = path.stat().st_size
    target_dir.mkdir(parents=True, exist_ok=True)
    handle_conflict_action(plan, settings)
    if transfer_mode == "move":
        transfer_file_with_progress(path, target_file)
    else:
        transfer_file_with_progress(path, target_file)
    set_file_stage(path, "moving", "Transfer 100% complete; verifying destination file")
    verify_target_file(target_file, expected_size)
    if transfer_mode == "move" and path.exists():
        path.unlink()
    transfer_sidecars(path, target_dir, target_file.stem, transfer_mode)
    set_file_stage(path, "completed", f"Completed and verified at {target_file}", target_path=target_file)
    add_event(
        plan["media_type"],
        "done",
        path,
        plan["renamed_to"],
        str(target_file),
        f"Stage 8: completed and verified in destination using {plan['source']} via {transfer_mode}",
    )
    notify_success(settings, plan["media_type"], path, plan["renamed_to"], str(target_file), plan["source"])
    time.sleep(COMPLETION_VISIBLE_SECONDS)
    set_file_stage(path, "cleanup", "Cleaning up original download folder")
    add_event(
        plan["media_type"],
        "stage_cleanup",
        path,
        plan["renamed_to"],
        str(target_file),
        "Stage 9: cleanup original download folder",
    )
    cleanup_source_folder(path, settings)
    time.sleep(CLEANUP_VISIBLE_SECONDS)


def handle_conflict_action(plan, settings):
    if plan.get("conflict_action") != "replace_with_incoming":
        if plan.get("duplicate"):
            notify_duplicate(settings, plan["duplicate_status"], plan.get("existing_duplicate"), plan["target_file"])
        return
    existing = plan.get("existing_duplicate")
    review_target_path = plan.get("existing_review_target")
    if not existing or not review_target_path or not Path(existing).exists():
        return
    review_target_path = unique_path(Path(review_target_path))
    review_target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(existing), str(review_target_path))
    add_event(
        plan["media_type"],
        "stage_duplicate_check",
        existing,
        moved_to=str(review_target_path),
        message=f"Smart conflict: moved lower-quality existing file to review: {review_target_path}",
    )
    notify_duplicate(settings, plan["duplicate_status"], existing, review_target_path)


def transfer_file_with_progress(source, target):
    total = source.stat().st_size
    transferred = 0
    chunk_size = max(1024 * 1024, TRANSFER_CHUNK_SIZE)
    set_transfer_progress(source, 0, total, force=True)
    with open(source, "rb") as src, open(target, "wb") as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst.write(chunk)
            transferred += len(chunk)
            set_transfer_progress(source, transferred, total)
    shutil.copystat(source, target)
    set_transfer_progress(source, total, total, force=True)


def verify_target_file(target, expected_size):
    if not target.exists():
        raise ValueError(f"Transfer verification failed: {target} does not exist")
    actual_size = target.stat().st_size
    if actual_size != expected_size:
        raise ValueError(f"Transfer verification failed: expected {expected_size} bytes, found {actual_size} bytes")


def transfer_sidecars(source_video, target_dir, target_stem, transfer_mode):
    for sibling in source_video.parent.iterdir():
        if sibling == source_video or sibling.suffix.lower() not in SIDE_EXTENSIONS:
            continue
        if sibling.stem.lower() == source_video.stem.lower():
            target = unique_path(target_dir / f"{target_stem}{sibling.suffix.lower()}")
            if transfer_mode == "move":
                shutil.move(str(sibling), str(target))
            else:
                shutil.copy2(str(sibling), str(target))


def cleanup_source_folder(source_video, settings):
    watch_folder = Path(settings["watch_folder"]).resolve()
    source_dir = source_video.parent.resolve()
    try:
        source_dir.relative_to(watch_folder)
    except ValueError:
        add_event("system", "stage_cleanup", source_video, message=f"Cleanup skipped: {source_dir} is outside watch folder")
        return

    if source_dir == watch_folder:
        add_event("system", "stage_cleanup", source_video, message="Cleanup skipped: source file was directly in watch folder")
        return

    if not source_dir.exists():
        add_event("system", "stage_cleanup", source_video, message="Cleanup skipped: source folder already removed")
        return

    exts = extension_set(settings)
    remaining_media = [
        path for path in source_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in exts
    ]
    if remaining_media:
        add_event(
            "system",
            "stage_cleanup",
            source_video,
            message=f"Cleanup skipped: {source_dir} still contains {len(remaining_media)} supported media file(s)",
        )
        return

    shutil.rmtree(source_dir)
    add_event("system", "stage_cleanup", source_video, message=f"Cleanup removed original source folder {source_dir}")


def extension_set(settings):
    raw = settings.get("movie_extensions", DEFAULT_SETTINGS["movie_extensions"])
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def malware_enabled(settings):
    return setting_enabled(settings, "malware_enabled")


def malware_source_scope(path, settings):
    path = Path(path)
    watch_folder = Path(settings["watch_folder"]).resolve()
    parent = path.parent.resolve()
    try:
        parent.relative_to(watch_folder)
    except ValueError:
        return path
    if parent != watch_folder:
        return parent
    return path


def ensure_malware_definitions(settings, force=False):
    if not setting_enabled(settings, "malware_update_definitions"):
        return True, "Automatic definition updates disabled"
    if not shutil.which("freshclam"):
        return False, "freshclam is not installed"
    now = time.time()
    with malware_lock:
        cached = dict(malware_definition_cache)
        if cached["ok"] and not force and now - cached["checked_at"] < 12 * 3600:
            return True, cached["detail"]
    try:
        result = subprocess.run(
            ["freshclam", "--stdout"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        detail = (output.splitlines()[-1] if output else "Definitions checked")[:220]
        if result.returncode == 0:
            ok = True
        elif clamav_database_available():
            ok = True
            detail = f"Definition update failed, using existing database: {detail}"
        else:
            ok = False
    except Exception as exc:
        ok = False
        detail = str(exc)
    with malware_lock:
        malware_definition_cache.update({"checked_at": now, "ok": ok, "detail": detail})
    return ok, detail


def clamav_database_available():
    db_dir = Path("/var/lib/clamav")
    if not db_dir.exists():
        return False
    patterns = ("*.cvd", "*.cld")
    return any(path.is_file() for pattern in patterns for path in db_dir.glob(pattern))


def run_malware_scan(target, settings):
    if not shutil.which("clamscan"):
        raise ValueError("ClamAV clamscan is not installed")
    definitions_ok, definition_detail = ensure_malware_definitions(settings)
    if not definitions_ok:
        raise ValueError(f"ClamAV definitions are not ready: {definition_detail}")
    target = Path(target)
    args = [
        "clamscan",
        "--infected",
        "--recursive",
        "--no-summary",
        "--stdout",
        str(target),
    ]
    result = subprocess.run(args, capture_output=True, text=True, timeout=MALWARE_SCAN_TIMEOUT, check=False)
    output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    infected = result.returncode == 1
    if result.returncode not in {0, 1}:
        detail = output or f"clamscan exited with {result.returncode}"
        raise ValueError(detail[:500])
    return {
        "clean": not infected,
        "infected": infected,
        "detail": parse_clamav_detail(output) if infected else "No threats detected",
        "raw": output,
    }


def parse_clamav_detail(output):
    infected_lines = [line for line in output.splitlines() if " FOUND" in line]
    if infected_lines:
        return "; ".join(infected_lines[:5])
    return output[:500] or "Threat detected"


def quarantine_target_for(source, settings):
    source = Path(source)
    root = Path(settings["quarantine_folder"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_source_name = safe_name(source.name) or "quarantined-item"
    target = root / stamp / safe_source_name
    return unique_path(target)


def quarantine_source(source, settings, detail):
    source = Path(source)
    target = quarantine_target_for(source, settings)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(target))
    add_event("system", "error", source, moved_to=str(target), message=f"Malware quarantined: {detail}")
    notify_malware(settings, source, target, detail)
    return target


def scan_new_arrival_for_malware(path, settings):
    if not malware_enabled(settings):
        return None
    source = malware_source_scope(path, settings)
    set_file_stage(path, "malware_check", f"Scanning {source.name} for viruses and malware")
    add_event("system", "stage_malware_check", path, message=f"Stage 2: malware scan started for {source}")
    result = run_malware_scan(source, settings)
    if result["infected"]:
        target = quarantine_source(source, settings, result["detail"])
        set_file_stage(path, "quarantined", f"Malware detected; moved to quarantine: {target}", target_path=target, last_error=result["detail"])
        return target
    set_file_stage(path, "malware_check", "Malware scan clean")
    add_event("system", "stage_malware_check", path, message="Stage 2: malware scan passed")
    return None


def scan_once():
    settings = get_settings()
    watch_folder = Path(settings["watch_folder"])
    if not watch_folder.exists():
        add_event("system", "error", watch_folder, message="Watch folder does not exist")
        notify_mount_unavailable(settings, "Watch folder", watch_folder)
        return

    stable_seconds = max(0, int(settings.get("stable_seconds", "30") or "30"))
    now = time.time()
    exts = extension_set(settings)
    new_files = []
    inventory = {"total": 0, "supported": 0, "ignored_exts": {}, "samples": []}
    with db_lock, db() as conn:
        for path in watch_folder.rglob("*"):
            if not path.is_file():
                continue
            inventory["total"] += 1
            suffix = path.suffix.lower() or "(none)"
            if suffix not in exts:
                inventory["ignored_exts"][suffix] = inventory["ignored_exts"].get(suffix, 0) + 1
                if len(inventory["samples"]) < 5:
                    inventory["samples"].append(str(path))
                continue
            inventory["supported"] += 1
            stat = path.stat()
            row = conn.execute("select * from seen_files where path = ?", (str(path),)).fetchone()
            if row:
                if row["processed"] and row["stage"] == "failed":
                    if stat.st_size != row["size"] or stat.st_mtime != row["mtime"]:
                        conn.execute(
                            """
                            update seen_files
                            set size = ?, mtime = ?, first_seen = ?, processed = 0,
                                stage = 'queued', reason = ?, last_error = null
                            where path = ?
                            """,
                            (stat.st_size, stat.st_mtime, now, "File changed after failure; queued for retry", str(path)),
                        )
                        new_files.append(path)
                    continue
                if row["processed"]:
                    if stat.st_size == row["size"] and stat.st_mtime == row["mtime"]:
                        continue
                    conn.execute(
                        """
                        update seen_files
                        set size = ?, mtime = ?, first_seen = ?, processed = 0,
                            stage = 'queued', reason = ?, last_error = null
                        where path = ?
                        """,
                        (stat.st_size, stat.st_mtime, now, "Stage 1: detected again; waiting for file to stay stable", str(path)),
                    )
                    new_files.append(path)
                elif stat.st_size != row["size"] or stat.st_mtime != row["mtime"]:
                    conn.execute(
                        """
                        update seen_files
                        set size = ?, mtime = ?, first_seen = ?, stage = 'queued', reason = ?
                        where path = ?
                        """,
                        (stat.st_size, stat.st_mtime, now, "File is still changing; waiting for it to finish downloading", str(path)),
                    )
            else:
                conn.execute(
                    """
                    insert into seen_files
                    (path, size, mtime, first_seen, processed, stage, reason)
                    values (?, ?, ?, ?, 0, 'queued', ?)
                    """,
                    (str(path), stat.st_size, stat.st_mtime, now, "Stage 1: detected; waiting for file to stay stable"),
                )
                new_files.append(path)
        conn.commit()

        ready = conn.execute(
            "select * from seen_files where processed = 0 and ? - first_seen >= ? order by first_seen limit ?",
            (now, stable_seconds, MAX_READY_PER_SCAN),
        ).fetchall()

    update_watch_inventory_cache(inventory)

    for path in new_files[:MAX_NEW_FILE_EVENTS_PER_SCAN]:
        add_event("system", "stage_queued", path, message="Stage 1: detected and queued")
    if len(new_files) > MAX_NEW_FILE_EVENTS_PER_SCAN:
        add_event(
            "system",
            "stage_queued",
            watch_folder,
            message=f"Stage 1: detected {len(new_files)} new files; logging first {MAX_NEW_FILE_EVENTS_PER_SCAN}",
        )

    for row in ready:
        path = Path(row["path"])
        try:
            if not path.exists():
                set_file_stage(path, "failed", "File disappeared before processing", last_error="File disappeared before processing")
                add_event("system", "error", path, message="File disappeared before processing")
                notify_failure(settings, path, "File disappeared before processing")
                mark_processed(path)
                continue
            current = path.stat()
            if current.st_size != row["size"] or current.st_mtime != row["mtime"]:
                set_file_stage(path, "queued", "File is still changing; waiting for it to finish downloading")
                reset_seen(path, current)
                continue
            process_file(path, settings)
            mark_processed(path)
        except Exception as exc:
            set_file_stage(path, "failed", f"Processing failed: {exc}", last_error=str(exc))
            add_event("system", "error", path, message=str(exc))
            notify_failure(settings, path, str(exc))
            mark_processed(path)


def mark_processed(path):
    with db_lock, db() as conn:
        conn.execute("update seen_files set processed = 1 where path = ?", (str(path),))
        conn.commit()


def reset_seen(path, stat):
    with db_lock, db() as conn:
        conn.execute(
            "update seen_files set size = ?, mtime = ?, first_seen = ?, stage = 'queued', reason = ? where path = ?",
            (stat.st_size, stat.st_mtime, time.time(), "File is still changing; waiting for it to finish downloading", str(path)),
        )
        conn.commit()


def get_job(name):
    with job_lock:
        job = dict(jobs[name])
        job["activity"] = list(jobs[name].get("activity", []))
        return job


def update_job(name, **values):
    activity = values.pop("activity", None)
    with job_lock:
        jobs[name].update(values)
        if activity:
            items = jobs[name].setdefault("activity", [])
            items.insert(0, {"time": now_iso(), "text": str(activity)})
            del items[25:]
        jobs[name]["updated_at"] = now_iso()


def start_background_job(name, kind, target):
    with job_lock:
        if jobs[name]["running"]:
            return False
        jobs[name].update({
            "running": True,
            "kind": kind,
            "progress": 0,
            "processed": 0,
            "total": 0,
            "started_at": now_iso(),
            "updated_at": now_iso(),
            "stage": "Starting",
            "current_folder": "",
            "current_file": "",
            "last_error": "",
            "changed": 0,
            "failed": 0,
            "infected": 0,
            "quarantined": 0,
            "open_count": 0,
            "resolved_count": 0,
            "activity": [{"time": now_iso(), "text": f"{kind} started"}],
            "message": f"{kind} starting",
        })
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return True


def media_files(root, settings):
    root = Path(root)
    if not root.exists():
        return []
    exts = extension_set(settings)
    return [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in exts]


def library_inventory(root, settings):
    root = Path(root)
    cache_key = (str(root), settings.get("movie_extensions", ""))
    now = time.time()
    with library_visibility_lock:
        cached = library_visibility_cache.get(cache_key)
        if cached and now - cached["cached_at"] < LIBRARY_VISIBILITY_CACHE_SECONDS:
            return dict(cached["inventory"])

    inventory = {
        "path": str(root),
        "exists": root.exists(),
        "readable": os.access(root, os.R_OK | os.X_OK) if root.exists() else False,
        "total_files": 0,
        "supported_files": 0,
        "supported_bytes": 0,
        "folders": 0,
        "ignored_exts": {},
        "samples": [],
        "limited": False,
        "scanned_entries": 0,
    }
    if not inventory["exists"] or not root.is_dir():
        return inventory
    exts = extension_set(settings)
    stack = [root]
    while stack and (LIBRARY_VISIBILITY_SCAN_LIMIT <= 0 or inventory["scanned_entries"] < LIBRARY_VISIBILITY_SCAN_LIMIT):
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    inventory["scanned_entries"] += 1
                    if LIBRARY_VISIBILITY_SCAN_LIMIT > 0 and inventory["scanned_entries"] >= LIBRARY_VISIBILITY_SCAN_LIMIT:
                        inventory["limited"] = True
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            inventory["folders"] += 1
                            stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    path = Path(entry.path)
                    inventory["total_files"] += 1
                    suffix = path.suffix.lower() or "(none)"
                    if suffix in exts:
                        inventory["supported_files"] += 1
                        try:
                            inventory["supported_bytes"] += path.stat().st_size
                        except OSError:
                            pass
                        if len(inventory["samples"]) < 5:
                            inventory["samples"].append(str(path))
                    else:
                        inventory["ignored_exts"][suffix] = inventory["ignored_exts"].get(suffix, 0) + 1
        except OSError:
            continue
    if stack:
        inventory["limited"] = True
    with library_visibility_lock:
        library_visibility_cache[cache_key] = {"cached_at": now, "inventory": dict(inventory)}
    return inventory


def library_inventory_summary(label, inventory):
    if not inventory["exists"]:
        return f"{label}: {inventory['path']} does not exist inside the container"
    if not inventory["readable"]:
        return f"{label}: {inventory['path']} exists but is not readable"
    ignored = ", ".join(f"{key}: {value}" for key, value in sorted(inventory["ignored_exts"].items())) or "none"
    samples = "; ".join(Path(item).name for item in inventory["samples"]) or "none"
    return (
        f"{label}: {inventory['supported_files']} supported media files, "
        f"{inventory['total_files']} total files, {inventory['folders']} folders. "
        f"Ignored extensions: {ignored}. Samples: {samples}"
        + (" Scan was limited for speed." if inventory.get("limited") else "")
    )


def manual_scan_movies_job():
    settings = get_settings()
    files = media_files(settings["movie_folder"], settings)
    run_manual_scan("movie", files, settings)


def manual_scan_tv_job():
    settings = get_settings()
    files = media_files(settings["tv_folder"], settings)
    run_manual_scan("tv", files, settings)


def manual_scan_all_job():
    settings = get_settings()
    files = media_files(settings["movie_folder"], settings) + media_files(settings["tv_folder"], settings)
    run_manual_scan("all", files, settings)


def run_manual_scan(kind, files, settings):
    total = len(files)
    update_job("file_management", total=total, stage="Inventory", message=f"Found {total} files to scan", activity=f"Inventory complete: {total} files")
    if total == 0:
        movie_inventory = library_inventory(settings["movie_folder"], settings)
        tv_inventory = library_inventory(settings["tv_folder"], settings)
        message = "No supported video files found. " + library_inventory_summary("Movies", movie_inventory) + " " + library_inventory_summary("TV", tv_inventory)
        update_job(
            "file_management",
            running=False,
            stage="Complete",
            progress=100,
            processed=0,
            total=0,
            message=message,
            activity=message,
        )
        add_event("system", "error", "file-management", message=message)
        return
    changed = 0
    failed = 0
    for index, path in enumerate(files, start=1):
        try:
            update_job(
                "file_management",
                stage="Checking",
                current_folder=str(path.parent),
                current_file=path.name,
                message=f"Checking {path.name}",
            )
            if kind == "movie" and parse_tv(path):
                update_job("file_management", activity=f"Skipped TV-looking file during movie scan: {path.name}")
                continue
            if kind == "tv" and not parse_tv(path):
                update_job("file_management", activity=f"Skipped non-TV file during TV scan: {path.name}")
                continue
            before = str(path)
            target = manual_library_target(path, settings)
            update_job(
                "file_management",
                stage="Planning",
                current_folder=str(target.parent) if target else str(path.parent),
                current_file=path.name,
                message=f"Planned target for {path.name}",
            )
            if target and path.resolve() != target.resolve():
                update_job("file_management", stage="Renaming", message=f"Moving {path.name} into {target.parent}")
                target.parent.mkdir(parents=True, exist_ok=True)
                final_target = unique_path(target)
                shutil.move(str(path), str(final_target))
                changed += 1
                update_job(
                    "file_management",
                    changed=changed,
                    current_folder=str(final_target.parent),
                    current_file=final_target.name,
                    activity=f"Changed: {before} -> {final_target}",
                )
            else:
                update_job("file_management", activity=f"Already correct: {path}")
        except Exception as exc:
            failed += 1
            update_job(
                "file_management",
                failed=failed,
                last_error=str(exc),
                stage="Failed",
                activity=f"Failed: {path} - {exc}",
            )
            add_event("system", "error", path, message=f"Manual library scan failed: {exc}")
        progress = 100 if not total else int((index / total) * 100)
        update_job(
            "file_management",
            stage="Scanning",
            progress=progress,
            processed=index,
            changed=changed,
            failed=failed,
            message=f"Scanned {index} of {total}. Renamed/moved {changed}; failed {failed}",
        )
    update_job(
        "file_management",
        running=False,
        stage="Complete",
        progress=100,
        processed=total,
        changed=changed,
        failed=failed,
        last_success_at=now_iso() if failed == 0 else "",
        message=f"Manual scan complete. Renamed/moved {changed}; failed {failed}",
        activity=f"Manual scan complete: {changed} changed, {failed} failed",
    )
    add_event("system", "done", "file-management", message=f"Manual {kind} scan complete: {changed} changed, {failed} failed")
    notify_scan_complete(settings, "File Management", f"Manual {kind} scan complete: {changed} changed, {failed} failed")


def manual_library_target(path, settings):
    tv = parse_tv(path)
    if tv:
        tv, source = enrich_tv(tv, settings)
        if metadata_required(settings) and not metadata_source_ok("tv", source):
            raise ValueError("No TV metadata match found")
        quality = quality_label(path)
        show_folder = tv_show_folder_name(tv["title"], tv["year"])
        season_folder = f"Season {tv['season']:02d}"
        base_name = tv_file_base(tv["title"], tv["year"], tv["season"], tv["episode"], tv["episode_name"], quality)
        return Path(settings["tv_folder"]) / show_folder / season_folder / f"{base_name}{path.suffix.lower()}"
    movie = parse_movie(path)
    movie, source = enrich_movie(movie, settings)
    if metadata_required(settings) and not metadata_source_ok("movie", source):
        raise ValueError("No TMDB movie match found")
    quality = quality_label(path)
    folder_name = movie_folder_name(movie["title"], movie["year"])
    base_name = movie_file_base(movie["title"], movie["year"], quality)
    return Path(settings["movie_folder"]) / folder_name / f"{base_name}{path.suffix.lower()}"


def duplicate_scan_job():
    settings = get_settings()
    movie_files = media_files(settings["movie_folder"], settings)
    tv_files = media_files(settings["tv_folder"], settings)
    files = movie_files + tv_files
    total = len(files)
    update_job("duplicate_checker", total=total, stage="Inventory", message=f"Scanning {total} library files", activity=f"Inventory: {len(movie_files)} movie files, {len(tv_files)} TV files")
    if total == 0:
        movie_inventory = library_inventory(settings["movie_folder"], settings)
        tv_inventory = library_inventory(settings["tv_folder"], settings)
        message = "No supported video files found for duplicate scan. " + library_inventory_summary("Movies", movie_inventory) + " " + library_inventory_summary("TV", tv_inventory)
        update_job(
            "duplicate_checker",
            running=False,
            stage="Complete",
            progress=100,
            processed=0,
            total=0,
            message=message,
            activity=message,
        )
        add_event("system", "error", "duplicate-checker", message=message)
        return
    groups = {}
    workers = max(1, MEDIA_SCAN_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(duplicate_key, path, settings): path for path in files}
        for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            path = futures[future]
            try:
                key = future.result()
            except Exception:
                key = None
                update_job("duplicate_checker", activity=f"Could not index: {path.name}")
            if key:
                groups.setdefault(key, []).append(path)
            else:
                update_job("duplicate_checker", activity=f"Could not index: {path.name}")
            progress = 100 if not total else int((index / total) * 70)
            update_job(
                "duplicate_checker",
                stage="Indexing",
                current_folder=str(path.parent),
                current_file=path.name,
                progress=progress,
                processed=index,
                message=f"Indexed {index} of {total} files with {workers} worker(s)",
            )
    findings = []
    update_job("duplicate_checker", stage="Analyzing", progress=75, message=f"Analyzing {len(groups)} media groups", activity=f"Analyzing {len(groups)} grouped media keys")
    for key, paths in groups.items():
        if len(paths) < 2:
            continue
        sorted_paths = sorted(paths, key=lambda item: quality_score(item), reverse=True)
        keep = sorted_paths[0]
        for duplicate in sorted_paths[1:]:
            findings.append((key, keep, duplicate))
            update_job("duplicate_checker", activity=f"Duplicate found: keep {keep.name}; review {duplicate.name}")
    update_job("duplicate_checker", stage="Saving", progress=90, message=f"Saving {len(findings)} duplicate pair(s)")
    save_duplicate_results(findings)
    counts = duplicate_status_counts()
    update_job(
        "duplicate_checker",
        running=False,
        stage="Complete",
        progress=100,
        processed=total,
        open_count=counts["open"],
        resolved_count=counts["resolved"],
        last_success_at=now_iso(),
        message=f"Duplicate scan complete. Found {len(findings)} duplicate pair(s)",
        activity=f"Duplicate scan complete: {len(findings)} pair(s), {counts['open']} need attention",
    )
    add_event("system", "done", "duplicate-checker", message=f"Duplicate scan complete: {len(findings)} duplicate pair(s)")
    notify_scan_complete(settings, "Duplicate Scan", f"Duplicate scan complete: {len(findings)} duplicate pair(s); {counts['open']} need attention")


def duplicate_key(path, settings):
    try:
        tv = parse_tv(path)
        if tv:
            tv, _ = enrich_tv(tv, settings)
            return ("tv", normalize_folder_name(tv["title"]), str(tv["year"]), f"S{tv['season']:02d}E{tv['episode']:02d}")
        movie = parse_movie(path)
        movie, _ = enrich_movie(movie, settings)
        return ("movie", normalize_folder_name(movie["title"]), str(movie["year"]))
    except Exception:
        return None


def malware_scan_movies_job():
    settings = get_settings()
    run_malware_library_scan("movies", media_files(settings["movie_folder"], settings), settings)


def malware_scan_tv_job():
    settings = get_settings()
    run_malware_library_scan("tv", media_files(settings["tv_folder"], settings), settings)


def malware_scan_all_job():
    settings = get_settings()
    files = media_files(settings["movie_folder"], settings) + media_files(settings["tv_folder"], settings)
    run_malware_library_scan("all", files, settings)


def run_malware_library_scan(kind, files, settings):
    total = len(files)
    update_job("malware_scanner", total=total, stage="Inventory", message=f"Found {total} files to scan", activity=f"Inventory complete: {total} files")
    if not malware_enabled(settings):
        message = "Malware scanning is disabled in Settings"
        update_job("malware_scanner", running=False, stage="Complete", progress=100, message=message, activity=message)
        add_event("system", "error", "malware-scanner", message=message)
        return
    if total == 0:
        message = "No supported video files found for malware scan"
        update_job("malware_scanner", running=False, stage="Complete", progress=100, processed=0, total=0, message=message, activity=message)
        add_event("system", "done", "malware-scanner", message=message)
        return
    definitions_ok, definition_detail = ensure_malware_definitions(settings, force=False)
    update_job("malware_scanner", stage="Definitions", message=definition_detail, activity=f"Definitions: {definition_detail}")
    if not definitions_ok:
        message = f"Cannot run malware scan: {definition_detail}"
        update_job("malware_scanner", running=False, stage="Failed", progress=100, failed=total, last_error=message, message=message, activity=message)
        add_event("system", "error", "malware-scanner", message=message)
        notify_failure(settings, "malware-scanner", message)
        return

    infected = 0
    quarantined = 0
    failed = 0
    workers = max(1, MALWARE_SCAN_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(run_malware_scan, path, settings): path for path in files}
        for index, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            path = futures[future]
            try:
                result = future.result()
                if result["infected"]:
                    infected += 1
                    target = quarantine_source(path, settings, result["detail"])
                    quarantined += 1
                    activity = f"Quarantined: {path.name} -> {target}"
                else:
                    activity = f"Clean: {path.name}"
            except Exception as exc:
                failed += 1
                activity = f"Failed: {path.name} - {exc}"
                add_event("system", "error", path, message=f"Malware scan failed: {exc}")
            progress = int((index / total) * 100)
            update_job(
                "malware_scanner",
                stage="Scanning",
                current_folder=str(path.parent),
                current_file=path.name,
                progress=progress,
                processed=index,
                infected=infected,
                quarantined=quarantined,
                failed=failed,
                message=f"Scanned {index} of {total} with {workers} worker(s). Infected {infected}; quarantined {quarantined}; failed {failed}",
                activity=activity,
            )

    final_stage = "Complete" if failed == 0 else "Failed"
    message = f"Malware {kind} scan complete: {infected} infected, {quarantined} quarantined, {failed} failed"
    update_job(
        "malware_scanner",
        running=False,
        stage=final_stage,
        progress=100,
        processed=total,
        infected=infected,
        quarantined=quarantined,
        failed=failed,
        last_success_at=now_iso() if failed == 0 else "",
        last_error="" if failed == 0 else message,
        message=message,
        activity=message,
    )
    add_event("system", "done" if failed == 0 else "error", "malware-scanner", message=message)
    notify_scan_complete(settings, "Malware Scan", message)


def quality_score(path):
    info = media_info(path)
    text = f"{quality_label(path)} {path.name}".lower()
    height = info.get("height") or 0
    bitrate = info.get("bitrate") or 0
    score = (info.get("size") or 0) / (1024 * 1024 * 1024)
    if height >= 2000 or "4k" in text or "2160" in text:
        score += 1000
    elif height >= 1000 or "1080" in text:
        score += 600
    elif height >= 700 or "720" in text:
        score += 300
    elif height >= 430 or "480" in text:
        score += 100
    if "blur" in text or "blue" in text:
        score += 80
    if "web-dl" in text or "webdl" in text:
        score += 35
    if info.get("hdr"):
        score += 60
    codec = (info.get("video_codec") or "").lower()
    if codec in {"hevc", "h265", "h.265"}:
        score += 30
    elif codec in {"h264", "h.264", "avc"}:
        score += 20
    score += min(40, (info.get("audio_channels") or 0) * 5)
    score += min(80, bitrate / 1_000_000)
    return score


def save_duplicate_results(findings):
    with db_lock, db() as conn:
        conn.execute("delete from duplicate_results where status = 'open'")
        for key, keep, duplicate in findings:
            media_type = key[0]
            title = " ".join(key[1:]) if media_type == "movie" else f"{key[1]} {key[2]} {key[3]}"
            conn.execute(
                """
                insert into duplicate_results
                (created_at, media_type, title, item_key, file_a, file_b, size_a, size_b, quality_a, quality_b, recommendation, status)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                """,
                (
                    now_iso(), media_type, title, "|".join(key), str(keep), str(duplicate),
                    keep.stat().st_size, duplicate.stat().st_size, quality_label(keep), quality_label(duplicate),
                    str(keep),
                ),
            )
        conn.commit()


def get_duplicate_results():
    with db_lock, db() as conn:
        return conn.execute("select * from duplicate_results order by id desc limit 200").fetchall()


def duplicate_status_counts():
    counts = {"open": 0, "resolved": 0}
    with db_lock, db() as conn:
        rows = conn.execute("select status, count(*) as total from duplicate_results group by status").fetchall()
    for row in rows:
        counts[row["status"]] = row["total"]
    return counts


def alert_count():
    with db_lock, db() as conn:
        row = conn.execute(
            "select count(*) as total from events where status = 'error'"
        ).fetchone()
    return row["total"] if row else 0


def delete_duplicate_file(result_id, side):
    with db_lock, db() as conn:
        row = conn.execute("select * from duplicate_results where id = ?", (result_id,)).fetchone()
    if not row:
        return False, "Duplicate record not found"
    file_path = Path(row["file_a"] if side == "a" else row["file_b"])
    if not file_path.exists():
        message = f"{file_path} was already missing"
    else:
        file_path.unlink()
        message = f"Deleted duplicate file {file_path}"
    with db_lock, db() as conn:
        conn.execute("update duplicate_results set status = 'resolved' where id = ?", (result_id,))
        conn.commit()
    add_event("system", "done", file_path, message=message)
    return True, message


def scanner_loop():
    while True:
        try:
            scan_once()
        except Exception as exc:
            add_event("system", "error", "scanner", message=str(exc))
        settings = get_settings()
        interval = max(5, int(settings.get("poll_interval", "15") or "15"))
        scan_event.wait(interval)
        scan_event.clear()


def duplicate_scheduler_loop():
    last_run_day = None
    while True:
        local = time.localtime()
        day_key = time.strftime("%Y-%m-%d", local)
        if local.tm_hour == DUPLICATE_SCAN_HOUR and last_run_day != day_key:
            if start_background_job("duplicate_checker", "Scheduled Duplicate Scan", duplicate_scan_job):
                last_run_day = day_key
        time.sleep(60)


def malware_scheduler_loop():
    last_run_day = None
    while True:
        settings = get_settings()
        try:
            hour = int(settings.get("malware_daily_hour", str(MALWARE_SCAN_HOUR)) or MALWARE_SCAN_HOUR)
        except ValueError:
            hour = MALWARE_SCAN_HOUR
        local = time.localtime()
        day_key = time.strftime("%Y-%m-%d", local)
        if malware_enabled(settings) and local.tm_hour == hour and last_run_day != day_key:
            if start_background_job("malware_scanner", "Scheduled Malware Scan", malware_scan_all_job):
                last_run_day = day_key
        time.sleep(60)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urllib.parse.urlparse(self.path).path
        if route == "/login":
            self.render_login()
        elif route == "/logout":
            self.redirect("/login", clear_cookie=True)
        elif not self.authenticated():
            self.redirect("/login")
        elif route == "/":
            self.render_dashboard()
        elif route == "/api/dashboard":
            self.render_dashboard_api()
        elif route == "/settings":
            self.render_settings()
        elif route == "/file-management":
            self.render_file_management()
        elif route == "/api/file-management":
            self.render_file_management_api()
        elif route == "/duplicates":
            self.render_duplicates()
        elif route == "/api/duplicates":
            self.render_duplicates_api()
        elif route == "/malware":
            self.render_malware()
        elif route == "/api/malware":
            self.render_malware_api()
        elif route == "/logs":
            self.render_logs()
        elif route == "/alerts":
            self.render_alerts()
        elif route == "/scan-now":
            scan_event.set()
            self.redirect("/")
        elif route == "/requeue-watch":
            requeue_watch_files()
            self.redirect("/")
        elif route == "/export-logs":
            self.render_log_export()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path
        if route == "/login":
            form = self.form()
            if form.get("username") == ADMIN_USER and form.get("password") == ADMIN_PASSWORD:
                self.redirect("/", cookie=sign(ADMIN_USER))
            else:
                self.render_login("Invalid username or password")
        elif route == "/settings" and self.authenticated():
            save_settings(self.form())
            scan_event.set()
            self.redirect("/settings")
        elif route == "/test-pushover" and self.authenticated():
            test_pushover()
            self.redirect("/settings")
        elif route == "/file-management/run" and self.authenticated():
            form = self.form()
            scan_type = form.get("scan_type", "all")
            target = {"movies": manual_scan_movies_job, "tv": manual_scan_tv_job}.get(scan_type, manual_scan_all_job)
            start_background_job("file_management", f"Manual {scan_type} scan", target)
            self.redirect("/file-management")
        elif route == "/duplicates/run" and self.authenticated():
            start_background_job("duplicate_checker", "Manual Duplicate Scan", duplicate_scan_job)
            self.redirect("/duplicates")
        elif route == "/malware/run" and self.authenticated():
            form = self.form()
            scan_type = form.get("scan_type", "all")
            target = {"movies": malware_scan_movies_job, "tv": malware_scan_tv_job}.get(scan_type, malware_scan_all_job)
            start_background_job("malware_scanner", f"Manual {scan_type} malware scan", target)
            self.redirect("/malware")
        elif route == "/duplicates/delete" and self.authenticated():
            form = self.form()
            delete_duplicate_file(int(form.get("id", "0") or "0"), form.get("side", "b"))
            self.redirect("/duplicates")
        elif route == "/clear-logs" and self.authenticated():
            form = self.form()
            scope = form.get("scope", "all")
            if scope in {"movie", "tv", "system"}:
                clear_events(media_type=scope)
            elif scope == "errors":
                clear_events(status="error")
            elif scope == "all":
                clear_events()
            self.redirect("/")
        else:
            self.send_error(HTTPStatus.FORBIDDEN)

    def form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode()
        parsed = urllib.parse.parse_qs(body)
        return {key: values[0] for key, values in parsed.items()}

    def authenticated(self):
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            key, _, value = item.strip().partition("=")
            if key == "dm_session" and verify_signed(value) == ADMIN_USER:
                return True
        return False

    def redirect(self, location, cookie=None, clear_cookie=False):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", f"dm_session={cookie}; HttpOnly; SameSite=Lax; Path=/")
        if clear_cookie:
            self.send_header("Set-Cookie", "dm_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def page(self, title, content):
        nav = ""
        if self.authenticated():
            alerts = alert_count()
            alert_label = f"Alerts <span class='alert-dot'>{alerts}</span>" if alerts else "Alerts"
            nav = """
            <nav>
              <a href="/">Dashboard</a>
              <a href="/file-management">File Management</a>
              <a href="/duplicates">Duplicate Checker</a>
              <a href="/malware">Malware Checks</a>
              <a href="/alerts">{alert_label}</a>
              <a href="/logs">Logs</a>
              <a href="/settings">Settings</a>
              <a href="/scan-now">Scan now</a>
              <a href="/logout">Logout</a>
            </nav>
            """.format(alert_label=alert_label)
        body = f"""<!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{html.escape(title)} - {APP_NAME}</title>
          <style>{CSS}</style>
        </head>
        <body>
          <header><h1>{APP_NAME}</h1>{nav}</header>
          <main>{system_status_strip() if self.authenticated() else ""}{content}</main>
          <div id="loading-overlay" class="loading-overlay" aria-live="polite" aria-hidden="true">
            <div class="loading-card">
              <div class="loading-orbit"><i></i><i></i><i></i></div>
              <strong>Please wait</strong>
              <span>Gathering data...</span>
              <div class="loading-bars"><b></b><b></b><b></b></div>
            </div>
          </div>
          <script>{GLOBAL_JS}</script>
        </body>
        </html>"""
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def render_login(self, error=""):
        message = f"<p class='error'>{html.escape(error)}</p>" if error else ""
        self.page("Login", f"""
        <section class="login">
          <h2>Admin Login</h2>
          {message}
          <form method="post" action="/login">
            <label>Username <input name="username" autocomplete="username" required></label>
            <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
            <button type="submit">Log in</button>
          </form>
        </section>
        """)

    def render_dashboard(self):
        try:
            content = f"""
            <div id="dashboard-root">
              {dashboard_content()}
            </div>
            <script>{DASHBOARD_JS}</script>
            """
        except Exception as exc:
            add_event("system", "error", "dashboard", message=f"Dashboard render failed: {exc}")
            content = dashboard_error_panel(exc)
            print(f"Dashboard render failed: {exc}", flush=True)
            self.page("Dashboard", content)
            return
        self.page("Dashboard", content)

    def render_dashboard_api(self):
        try:
            body = json.dumps({"html": dashboard_content(), "updated_at": now_iso()}).encode("utf-8")
        except Exception as exc:
            add_event("system", "error", "dashboard", message=f"Dashboard API render failed: {exc}")
            body = json.dumps({"html": dashboard_error_panel(exc), "updated_at": now_iso()}).encode("utf-8")
            print(f"Dashboard API render failed: {exc}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def render_log_export(self):
        data = export_events().encode("utf-8")
        filename = f"data-manager-logs-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def render_settings(self):
        settings = get_settings()
        fields = "\n".join(
            settings_field(key, value)
            for key, value in settings.items()
            if key in DEFAULT_SETTINGS
        )
        self.page("Settings", f"""
        <section class="panel">
          <h2>Settings</h2>
          <form method="post" action="/settings" class="settings">
            {fields}
            <button type="submit">Save settings</button>
          </form>
        </section>
        <section class="panel">
          <div class="panel-title">
            <h2>Pushover Test</h2>
            <form method="post" action="/test-pushover" class="inline-form">
              <button type="submit">Send Test Alert</button>
            </form>
          </div>
          <p>Use this after saving the Pushover token, user key, and optional device name.</p>
        </section>
        <section class="panel">
          <h2>Format Rules</h2>
          <p>Movies become <code>Movie Title (Year)/Movie Title [Year] [Quality].ext</code>.</p>
          <p>TV episodes become <code>Show Name [Year]/Season 01/Show Name [Year] [S01E01] Episode Name [Quality].ext</code>.</p>
        </section>
        """)

    def render_file_management(self):
        self.page("File Management", f"""
        <div id="file-management-root">
          {file_management_content()}
        </div>
        <script>{FILE_MANAGEMENT_JS}</script>
        """)

    def render_file_management_api(self):
        body = json.dumps({"html": file_management_content(), "updated_at": now_iso()}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def render_duplicates(self):
        self.page("Duplicate Checker", f"""
        <div id="duplicates-root">
          {duplicates_content()}
        </div>
        <script>{DUPLICATES_JS}</script>
        """)

    def render_duplicates_api(self):
        body = json.dumps({"html": duplicates_content(), "updated_at": now_iso()}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def render_malware(self):
        self.page("Malware Checks", f"""
        <div id="malware-root">
          {malware_content()}
        </div>
        <script>{MALWARE_JS}</script>
        """)

    def render_malware_api(self):
        body = json.dumps({"html": malware_content(), "updated_at": now_iso()}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def render_logs(self):
        events = get_events(500)
        self.page("Logs", f"""
        <section class="panel">
          <div class="panel-title">
            <h2>System Logs</h2>
            <a href="/export-logs">Download CSV</a>
          </div>
          {log_actions()}
          {organized_log_table(events)}
        </section>
        """)

    def render_alerts(self):
        rows = [
            row for row in get_events(300)
            if row["status"] == "error"
        ]
        self.page("Alerts", f"""
        <section class="panel">
          <h2>Alerts</h2>
          {organized_log_table(rows)}
        </section>
        """)

    def log_message(self, fmt, *args):
        return


def dashboard_content():
    events = get_events()
    queue = get_queue()
    s = stats()
    health = dashboard_health()
    movie_rows = [row for row in events if row["media_type"] == "movie"]
    tv_rows = [row for row in events if row["media_type"] == "tv"]
    return f"""
        <section class="stats">
          {stat_card("Queue", s["queued"], "Waiting or stabilizing")}
          {stat_card("Active", s["active"], "Checking or moving")}
          {stat_card("Watch Files", s["watch_visible"], f"Supported of {s['watch_total']} total")}
          {stat_card("Movies", s.get("movie", {}).get("done", 0), "Processed")}
          {stat_card("TV Shows", s.get("tv", {}).get("done", 0), "Processed")}
        </section>
        <p class="refresh-note" id="refresh-note">Dashboard checks every 5 seconds and switches to live updates while a file is in an active stage.</p>
        {watch_visibility_note(s)}
        {queue_limit_note(s)}
        {health_panel(health)}
        {queue_panel(queue)}
        <section class="columns">
          {event_table("Movies", movie_rows)}
          {event_table("TV Shows", tv_rows)}
        </section>
    """


def system_status_strip():
    cpu = resource_health_check("CPU", container_cpu_percent())
    memory = resource_health_check("Memory", container_memory_percent())
    s = stats()
    alerts = alert_count()
    file_job = get_job("file_management")
    duplicate_job = get_job("duplicate_checker")
    malware_job = get_job("malware_scanner")
    return f"""
    <section class="system-strip">
      {system_metric("CPU", cpu["detail"], cpu["status"])}
      {system_metric("Memory", memory["detail"], memory["status"])}
      {system_metric("Alerts", str(alerts), "fail" if alerts else "ok")}
      {system_metric("Queue", str(s["queued"]), "warn" if s["queued"] else "ok")}
      {system_metric("File Scan", file_job.get("stage") or "Idle", "warn" if file_job.get("running") else "ok")}
      {system_metric("Duplicate Scan", duplicate_job.get("stage") or "Idle", "warn" if duplicate_job.get("running") else "ok")}
      {system_metric("Malware Scan", malware_job.get("stage") or "Idle", "warn" if malware_job.get("running") else "ok")}
    </section>
    """


def system_metric(label, value, status):
    return f"""
    <article class="system-metric {html.escape(status)}">
      <strong>{html.escape(label)}</strong>
      <span>{html.escape(value)}</span>
    </article>
    """


def dashboard_error_panel(exc):
    return f"""
    <section class="panel">
      <h2>Dashboard Error</h2>
      <p class="error">The dashboard could not render, but the app is still running.</p>
      <p>{html.escape(str(exc))}</p>
      <p>Check container logs with <code>docker logs data-manager --tail 100</code>.</p>
    </section>
    """


def file_management_content():
    job = get_job("file_management")
    settings = get_settings()
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>File Management</h2>
        <span class="badge {'moving' if job['running'] else 'completed'}">{html.escape(job['kind'])}</span>
      </div>
      <p>Manual scans rename and organize existing movie and TV libraries using the current naming format.</p>
      <div class="actions">
        <form method="post" action="/file-management/run"><input type="hidden" name="scan_type" value="movies"><button type="submit">Scan Movies</button></form>
        <form method="post" action="/file-management/run"><input type="hidden" name="scan_type" value="tv"><button type="submit">Scan TV</button></form>
        <form method="post" action="/file-management/run"><input type="hidden" name="scan_type" value="all"><button type="submit">Scan All</button></form>
      </div>
    </section>
    {library_visibility_panel(settings)}
    {file_management_health(job)}
    {scan_stage_panel(job, ["Starting", "Inventory", "Checking", "Planning", "Renaming", "Scanning", "Complete"])}
    {job_panel("Manual Scan Progress", job)}
    {job_activity_panel("Manual Scan Activity", job)}
    """


def duplicates_content():
    job = get_job("duplicate_checker")
    settings = get_settings()
    rows = get_duplicate_results()
    counts = duplicate_status_counts()
    cards = "".join(duplicate_card(row) for row in rows) or "<p class='empty'>No duplicate results yet.</p>"
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>Duplicate Checker</h2>
        <form method="post" action="/duplicates/run" class="inline-form"><button type="submit">Run Duplicate Scan</button></form>
      </div>
      <p>Automatic duplicate scans run daily at {DUPLICATE_SCAN_HOUR:02d}:00 server time. Results stay here until resolved or the next scan refreshes open results.</p>
    </section>
    {library_visibility_panel(settings)}
    {duplicate_health(job, counts)}
    {scan_stage_panel(job, ["Starting", "Inventory", "Indexing", "Analyzing", "Saving", "Complete"])}
    {job_panel("Duplicate Scan Progress", job)}
    {job_activity_panel("Duplicate Scan Activity", job)}
    <section class="panel">
      <h2>Duplicate Results</h2>
      <div class="duplicate-list">{cards}</div>
    </section>
    """


def malware_content():
    job = get_job("malware_scanner")
    settings = get_settings()
    events = [
        row for row in get_events(80)
        if "malware" in (row["message"] or "").lower() or row["status"] == "stage_malware_check"
    ]
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>Malware Checks</h2>
        <span class="badge {'moving' if job['running'] else 'completed'}">{html.escape(job['kind'])}</span>
      </div>
      <p>New downloads are scanned before rename planning. Infected files or source folders are moved to quarantine without renaming.</p>
      <div class="actions">
        <form method="post" action="/malware/run"><input type="hidden" name="scan_type" value="movies"><button type="submit">Scan Movies</button></form>
        <form method="post" action="/malware/run"><input type="hidden" name="scan_type" value="tv"><button type="submit">Scan TV</button></form>
        <form method="post" action="/malware/run"><input type="hidden" name="scan_type" value="all"><button type="submit">Scan All</button></form>
      </div>
    </section>
    {malware_health(job, settings)}
    {scan_stage_panel(job, ["Starting", "Inventory", "Definitions", "Scanning", "Complete"])}
    {job_panel("Malware Scan Progress", job)}
    {job_activity_panel("Malware Scan Activity", job)}
    <section class="panel">
      <h2>Recent Malware Events</h2>
      {organized_log_table(events)}
    </section>
    """


def library_visibility_panel(settings):
    movie_inventory = library_inventory(settings["movie_folder"], settings)
    tv_inventory = library_inventory(settings["tv_folder"], settings)
    total_files = movie_inventory["supported_files"] + tv_inventory["supported_files"]
    total_size = movie_inventory["supported_bytes"] + tv_inventory["supported_bytes"]
    return f"""
    <section class="stats mini-stats">
      {stat_card("Library Files", total_files, "Supported media files")}
      {stat_card("Library Size", format_bytes(total_size), "Supported media total")}
      {stat_card("Movie Files", movie_inventory["supported_files"], format_bytes(movie_inventory["supported_bytes"]))}
      {stat_card("TV Files", tv_inventory["supported_files"], format_bytes(tv_inventory["supported_bytes"]))}
    </section>
    <section class="panel">
      <div class="panel-title">
        <h2>Library Visibility</h2>
        <span class="badge {visibility_badge_class(movie_inventory, tv_inventory)}">{visibility_badge_text(movie_inventory, tv_inventory)}</span>
      </div>
      <div class="columns">
        {inventory_card("Movies", movie_inventory)}
        {inventory_card("TV Shows", tv_inventory)}
      </div>
    </section>
    """


def inventory_card(title, inventory):
    samples = "".join(
        f"<li title='{html.escape(sample)}'>{html.escape(Path(sample).name)}</li>"
        for sample in inventory["samples"]
    ) or "<li>No supported samples visible</li>"
    ignored = ", ".join(f"{html.escape(key)}: {count}" for key, count in sorted(inventory["ignored_exts"].items())) or "none"
    status = "ok" if inventory["exists"] and inventory["readable"] and inventory["supported_files"] else "warn"
    if not inventory["exists"] or not inventory["readable"]:
        status = "fail"
    return f"""
    <article class="health-item {status}">
      <div>{health_badge(status)}<strong>{html.escape(title)}</strong></div>
      <p>{html.escape(inventory['path'])}</p>
      <dl>
        <dt>Supported</dt><dd>{inventory['supported_files']}</dd>
        <dt>Size</dt><dd>{format_bytes(inventory['supported_bytes'])}</dd>
        <dt>Total files</dt><dd>{inventory['total_files']}</dd>
        <dt>Folders</dt><dd>{inventory['folders']}</dd>
        <dt>Scanned</dt><dd>{inventory['scanned_entries']}{' sampled limit reached' if inventory.get('limited') else ''}</dd>
        <dt>Ignored</dt><dd>{ignored}</dd>
      </dl>
      <ul class="logs">{samples}</ul>
    </article>
    """


def visibility_badge_class(movie_inventory, tv_inventory):
    if not movie_inventory["exists"] or not tv_inventory["exists"]:
        return "failed"
    if movie_inventory["supported_files"] or tv_inventory["supported_files"]:
        return "completed"
    return "queued"


def visibility_badge_text(movie_inventory, tv_inventory):
    total = movie_inventory["supported_files"] + tv_inventory["supported_files"]
    if total:
        return f"{total} media files visible"
    return "No supported media visible"


def file_management_health(job):
    status = "Running" if job.get("running") else ("Healthy" if job.get("last_success_at") else "Ready")
    return f"""
    <section class="stats mini-stats">
      {stat_card("Status", status, job.get("stage") or "Idle")}
      {stat_card("Last Good Scan", job.get("last_success_at") or "Never", "Completed without failures")}
      {stat_card("Changed", job.get("changed", 0), "Files renamed or moved")}
      {stat_card("Failed", job.get("failed", 0), "Needs review")}
    </section>
    """


def duplicate_health(job, counts):
    last_success = job.get("last_success_at") or "Never"
    status = "Running" if job.get("running") else ("Attention" if counts["open"] else "Healthy")
    return f"""
    <section class="stats mini-stats">
      {stat_card("Status", status, job.get("stage") or "Idle")}
      {stat_card("Last Scan", last_success, f"Daily at {DUPLICATE_SCAN_HOUR:02d}:00")}
      {stat_card("Needs Attention", counts["open"], "Open duplicate pairs")}
      {stat_card("Resolved", counts["resolved"], "Handled duplicate pairs")}
    </section>
    """


def malware_health(job, settings):
    check = clamav_health_check(settings)
    path_check = path_health_check("Quarantine", settings["quarantine_folder"], needs_write=True)
    last_success = job.get("last_success_at") or "Never"
    status = "Running" if job.get("running") else ("Attention" if int(job.get("infected") or 0) else "Ready")
    hour = settings.get("malware_daily_hour", str(MALWARE_SCAN_HOUR))
    return f"""
    <section class="stats mini-stats">
      {stat_card("Status", status, job.get("stage") or "Idle")}
      {stat_card("Last Completed Scan", last_success, f"Daily at {hour}:00")}
      {stat_card("Infected", job.get("infected", 0), "Detected this run")}
      {stat_card("Quarantined", job.get("quarantined", 0), settings["quarantine_folder"])}
    </section>
    <section class="panel">
      <div class="panel-title"><h2>Scanner Health</h2><span class="badge {health_badge_class(check['status'])}">{html.escape(check['status'].upper())}</span></div>
      <div class="health-grid">
        <article class="health-item {html.escape(check['status'])}">
          <div>{health_badge(check['status'])}<strong>{html.escape(check['name'])}</strong></div>
          <p>{html.escape(check['detail'])}</p>
        </article>
        <article class="health-item {html.escape(path_check['status'])}">
          <div>{health_badge(path_check['status'])}<strong>{html.escape(path_check['name'])}</strong></div>
          <p>{html.escape(path_check['detail'])}</p>
        </article>
      </div>
    </section>
    """


def scan_stage_panel(job, stages):
    current = job.get("stage") or "Idle"
    items = "".join(
        f"<li class='{job_stage_class(stage, current, stages)}'><span>{index}</span>{html.escape(stage)}</li>"
        for index, stage in enumerate(stages, start=1)
    )
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>Live Stages</h2>
        <span class="badge {'moving' if job.get('running') else 'completed'}">{html.escape(current)}</span>
      </div>
      <ol class="timeline job-timeline">{items}</ol>
      <div class="pipeline-focus {'moving' if job.get('running') else 'idle'}">
        <strong>{html.escape(job.get('current_file') or 'No active file')}</strong>
        <span>{html.escape(job.get('current_folder') or job.get('message') or '')}</span>
      </div>
    </section>
    """


def job_stage_class(stage, current, stages):
    if stage == current:
        return "active"
    if current in stages and stages.index(current) > stages.index(stage):
        return "complete"
    return ""


def job_activity_panel(title, job):
    rows = job.get("activity") or []
    if not rows:
        body = "<p class='empty'>No activity yet.</p>"
    else:
        body = "<ul class='logs'>" + "".join(
            f"<li><strong>{html.escape(item['time'])}</strong> {html.escape(item['text'])}</li>"
            for item in rows
        ) + "</ul>"
    return f"""
    <section class="panel">
      <h2>{html.escape(title)}</h2>
      {body}
    </section>
    """


def job_panel(title, job):
    progress = max(0, min(100, int(job.get("progress") or 0)))
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>{html.escape(title)}</h2>
        <span class="badge {'moving' if job.get('running') else 'completed'}">{'Running' if job.get('running') else 'Idle'}</span>
      </div>
      <div class="progress"><span style="width:{progress}%"></span></div>
      <p>{html.escape(job.get('message') or '')}</p>
      <p class="refresh-note">Processed {int(job.get('processed') or 0)} of {int(job.get('total') or 0)}. Last update: {html.escape(job.get('updated_at') or 'Never')}.</p>
    </section>
    """


def duplicate_card(row):
    recommendation = row["recommendation"]
    a_best = row["file_a"] == recommendation
    b_best = row["file_b"] == recommendation
    return f"""
    <article class="duplicate-card">
      <div class="panel-title">
        <h3>{html.escape(row['media_type'].upper())}: {html.escape(row['title'])}</h3>
        <span class="badge {status_class(row['status'])}">{html.escape(row['status'])}</span>
      </div>
      <div class="duplicate-files">
        {duplicate_file_block(row, 'a', row['file_a'], row['size_a'], row['quality_a'], a_best)}
        {duplicate_file_block(row, 'b', row['file_b'], row['size_b'], row['quality_b'], b_best)}
      </div>
    </article>
    """


def duplicate_file_block(row, side, path, size, quality, recommended):
    recommendation = "<span class='badge completed'>Recommended keep</span>" if recommended else ""
    info = media_info(Path(path))
    return f"""
    <div class="duplicate-file">
      <strong>{html.escape(Path(path).name)}</strong>
      {recommendation}
      <dl>
        <dt>Quality</dt><dd>{html.escape(quality or 'Unknown')}</dd>
        <dt>Size</dt><dd>{format_bytes(size)}</dd>
        <dt>Codec</dt><dd>{html.escape(info.get('video_codec') or 'unknown')}</dd>
        <dt>Audio</dt><dd>{html.escape(format_audio_channels(info.get('audio_channels') or 0))}</dd>
        <dt>HDR</dt><dd>{'Yes' if info.get('hdr') else 'No'}</dd>
        <dt>Bitrate</dt><dd>{html.escape(format_bitrate(info.get('bitrate') or 0))}</dd>
        <dt>Runtime</dt><dd>{html.escape(format_duration(info.get('runtime') or 0))}</dd>
        <dt>Path</dt><dd title="{html.escape(path)}">{html.escape(short_path(path))}</dd>
      </dl>
      <form method="post" action="/duplicates/delete">
        <input type="hidden" name="id" value="{int(row['id'])}">
        <input type="hidden" name="side" value="{side}">
        <button type="submit" class="danger">Delete this file</button>
      </form>
    </div>
    """


def format_bitrate(value):
    value = int(value or 0)
    if value <= 0:
        return "Unknown"
    return f"{value / 1_000_000:.1f} Mbps"


def format_duration(seconds):
    seconds = int(float(seconds or 0))
    if seconds <= 0:
        return "Unknown"
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m {secs:02d}s"


def format_audio_channels(channels):
    channels = int(channels or 0)
    if channels <= 0:
        return "Unknown"
    if channels == 6:
        return "5.1"
    if channels == 8:
        return "7.1"
    return str(channels)


def organized_log_table(rows):
    if not rows:
        return "<p class='empty'>No events to show.</p>"
    body = "".join(
        f"""
        <tr>
          <td>{html.escape(row['created_at'])}</td>
          <td>{html.escape(row['media_type'])}</td>
          <td>{status_badge(row['status'])}</td>
          <td title="{html.escape(row['original_path'])}">{html.escape(short_path(row['original_path']))}</td>
          <td>{html.escape(display_media_name(row['renamed_to'] or ''))}</td>
          <td title="{html.escape(row['moved_to'] or '')}">{html.escape(short_path(row['moved_to'] or ''))}</td>
          <td>{html.escape(row['message'] or '')}</td>
        </tr>
        """
        for row in rows
    )
    return f"""
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Type</th><th>Status</th><th>Source</th><th>Renamed</th><th>Destination</th><th>Message</th></tr></thead>
        <tbody>{body}</tbody>
      </table>
    </div>
    """


def status_class(status):
    if status == "open":
        return "queued"
    if status == "resolved":
        return "completed"
    return ""


def label_for(key):
    return {
        "watch_folder": "Download watch folder",
        "movie_folder": "Movie library folder",
        "tv_folder": "TV library folder",
        "review_folder": "Duplicate review folder",
        "quarantine_folder": "Malware quarantine folder",
        "poll_interval": "Scan interval seconds",
        "stable_seconds": "File stable seconds before processing",
        "movie_extensions": "Media extensions",
        "metadata_provider": "Metadata provider",
        "metadata_enabled": "Use metadata lookup",
        "metadata_required": "Require metadata match before moving",
        "transfer_mode": "Transfer mode (copy or move)",
        "pushover_enabled": "Enable Pushover notifications",
        "pushover_app_token": "Pushover app token",
        "pushover_user_key": "Pushover user/group key",
        "pushover_device": "Pushover device name (optional)",
        "notify_success": "Notify successful transfers",
        "notify_failure": "Notify failures",
        "notify_duplicate": "Notify duplicates/conflicts",
        "notify_scan_complete": "Notify scan completion",
        "notify_mount_unavailable": "Notify mount unavailable",
        "notify_metadata_down": "Notify metadata provider down",
        "notify_malware": "Notify malware quarantines",
        "malware_enabled": "Enable malware scanning",
        "malware_update_definitions": "Auto-update malware definitions",
        "malware_daily_hour": "Daily malware scan hour",
    }.get(key, key)


def settings_field(key, value):
    input_type = "password" if key in {"pushover_app_token", "pushover_user_key"} else "text"
    autocomplete = "off" if input_type == "password" else ""
    return (
        f"<label>{label_for(key)}"
        f"<input name='{html.escape(key)}' type='{input_type}' value='{html.escape(value)}' autocomplete='{autocomplete}'>"
        "</label>"
    )


def stat_card(title, value, subtitle):
    return f"<article><span>{html.escape(str(value))}</span><strong>{html.escape(title)}</strong><small>{html.escape(subtitle)}</small></article>"


def queue_limit_note(s):
    if not s.get("hidden_queue"):
        return ""
    return f"""
    <p class="refresh-note">
      Showing the first {s["display_limit"]} queued files. {s["hidden_queue"]} additional files are waiting and will be processed in order.
    </p>
    """


def watch_visibility_note(s):
    if s.get("watch_visible", 0):
        return ""
    if s.get("watch_total", 0):
        return f"""
        <p class="refresh-note">
          {s["watch_total"]} files were visible in /watch at last scan, but none match the allowed media extensions. Check Settings > Media extensions.
        </p>
        """
    return """
    <p class="refresh-note">
      No supported video files were visible in /watch at last scan. Check the mount path, file extensions, and Settings.
    </p>
    """


def health_panel(checks):
    items = "".join(
        f"""
        <article class="health-item {html.escape(check['status'])}">
          <div>{health_badge(check['status'])}<strong>{html.escape(check['name'])}</strong></div>
          <p>{html.escape(check['detail'])}</p>
        </article>
        """
        for check in checks
    )
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>Health Checks</h2>
        <a href="/">Refresh</a>
      </div>
      <div class="health-grid">{items}</div>
    </section>
    """


def health_badge(status):
    labels = {"ok": "OK", "warn": "Warn", "fail": "Fail"}
    css = {"ok": "completed", "warn": "queued", "fail": "failed"}.get(status, "")
    return f"<span class='badge {css}'>{html.escape(labels.get(status, status))}</span>"


def health_badge_class(status):
    return {"ok": "completed", "warn": "queued", "fail": "failed"}.get(status, "")


def queue_panel(rows):
    stages = [
        ("queued", "1", "Queued"),
        ("malware_check", "2", "Malware Check"),
        ("checking", "3", "Checking"),
        ("renaming", "4", "Renaming"),
        ("folder_check", "5", "Folder Check"),
        ("duplicate_check", "6", "Duplicate Check"),
        ("moving", "7", "Transferring"),
        ("completed", "8", "Completed"),
        ("cleanup", "9", "Cleanup"),
    ]
    current = current_pipeline_item(rows)
    if not rows:
        body = "<tr><td colspan='5' class='empty'>No queued files. New downloads will appear here first.</td></tr>"
    else:
        body = "".join(
            f"""
            <tr class="{queue_row_class(row, current)}">
              <td>{html.escape(row.get('media_type') or 'Unknown')}</td>
              <td>{html.escape(display_media_name(row.get('planned_name') or 'Not planned yet'))}</td>
              <td title="{html.escape(row.get('target_path') or '')}">{html.escape(row.get('target_path') or 'Not selected yet')}</td>
              <td>{progress_bar(row.get('transfer_progress') or 0, row.get('transferred_bytes') or 0, row.get('total_bytes') or 0)}</td>
              <td>{queue_reason(row)}</td>
            </tr>
            """
            for row in rows
        )
    timeline = "".join(
        f"<li class='{stage_timeline_class(stage, current)}'><span>{number}</span>{html.escape(label)}</li>"
        for stage, number, label in stages
    )
    focus = pipeline_focus(current)
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>Processing Pipeline</h2>
        <div class="panel-actions">
          <a href="/scan-now">Scan now</a>
          <a href="/requeue-watch">Requeue watch files</a>
        </div>
      </div>
      {focus}
      <ol class="timeline">{timeline}</ol>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Type</th><th>Planned Name</th><th>Destination</th><th>Progress</th><th>Why It Is Waiting</th></tr></thead>
          <tbody>{body}</tbody>
        </table>
      </div>
    </section>
    """


def current_pipeline_item(rows):
    if not rows:
        return None
    priority = {"malware_check": 0, "checking": 1, "renaming": 2, "folder_check": 3, "duplicate_check": 4, "moving": 5, "completed": 6, "cleanup": 7, "queued": 8, "failed": 9, "quarantined": 10}
    return sorted(rows, key=lambda row: (priority.get(row["stage"], 9), row["first_seen"]))[0]


def pipeline_focus(row):
    if not row:
        return "<div class='pipeline-focus idle'><strong>Pipeline idle</strong><span>Waiting for the next detected file.</span></div>"
    return f"""
    <div class="pipeline-focus {html.escape(row['stage'])}">
      <strong>{html.escape(stage_label(row['stage']))}</strong>
      <span>{queue_reason(row)}</span>
    </div>
    """


def stage_label(stage):
    return {
        "queued": "Stage 1: Queued",
        "malware_check": "Stage 2: Malware Check",
        "checking": "Stage 3: Checking",
        "renaming": "Stage 4: Renaming",
        "folder_check": "Stage 5: Folder Check",
        "duplicate_check": "Stage 6: Duplicate Check",
        "moving": "Stage 7: Transferring",
        "completed": "Stage 8: Completed",
        "cleanup": "Stage 9: Cleanup",
        "quarantined": "Quarantined",
        "failed": "Failed",
    }.get(stage, stage or "Unknown")


def queue_row_class(row, current):
    classes = [f"stage-row-{row['stage']}"]
    if current and row["path"] == current["path"]:
        classes.append("pipeline-current")
    return " ".join(classes)


def stage_timeline_class(stage, current):
    if not current:
        return ""
    order = ["queued", "malware_check", "checking", "renaming", "folder_check", "duplicate_check", "moving", "completed", "cleanup"]
    current_index = order.index(current["stage"]) if current["stage"] in order else -1
    stage_index = order.index(stage)
    if stage == current["stage"]:
        return "active"
    if current_index > stage_index:
        return "complete"
    return ""


def queue_reason(row):
    reason = html.escape(row["reason"])
    if row["stage"] == "queued" and row.get("remaining_seconds", 0) > 0:
        return f'Waiting <span class="countdown" data-countdown="{int(row["remaining_seconds"])}">{int(row["remaining_seconds"])}</span>s for file to stay stable before processing'
    return reason


def stage_badge(stage):
    labels = {
        "queued": "Stage 1: Queued",
        "malware_check": "Stage 2: Malware Check",
        "checking": "Stage 3: Checking",
        "renaming": "Stage 4: Renaming",
        "folder_check": "Stage 5: Folder Check",
        "duplicate_check": "Stage 6: Duplicate Check",
        "moving": "Stage 7: Transferring",
        "completed": "Stage 8: Completed",
        "cleanup": "Stage 9: Cleanup",
        "quarantined": "Quarantined",
        "failed": "Failed",
    }
    css = "failed" if stage == "failed" else stage
    return f"<span class='badge {html.escape(css)}'>{html.escape(labels.get(stage, stage or 'Unknown'))}</span>"


def progress_bar(progress, transferred_bytes=0, total_bytes=0):
    progress = max(0, min(100, int(progress or 0)))
    label = f"{progress}%"
    if total_bytes:
        label = f"{progress}% ({format_bytes(transferred_bytes)} / {format_bytes(total_bytes)})"
    return f"""
    <div class="progress" aria-label="Transfer progress {progress}%">
      <span style="width:{progress}%"></span>
    </div>
    <small>{html.escape(label)}</small>
    """


def format_bytes(value):
    value = int(value or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024


def display_media_name(value):
    if not value or value == "Pending" or value == "Not planned yet":
        return value
    path = Path(value)
    if path.suffix.lower() in VIDEO_EXTENSIONS:
        return path.stem
    return value


def log_actions():
    return """
    <section class="panel actions">
      <h2>Log Controls</h2>
      <a href="/export-logs">Download CSV</a>
      <form method="post" action="/clear-logs"><input type="hidden" name="scope" value="movie"><button type="submit">Clear movie logs</button></form>
      <form method="post" action="/clear-logs"><input type="hidden" name="scope" value="tv"><button type="submit">Clear TV logs</button></form>
      <form method="post" action="/clear-logs"><input type="hidden" name="scope" value="system"><button type="submit">Clear system logs</button></form>
      <form method="post" action="/clear-logs"><input type="hidden" name="scope" value="errors"><button type="submit">Clear errors</button></form>
      <form method="post" action="/clear-logs"><input type="hidden" name="scope" value="all"><button type="submit" class="danger">Clear all logs</button></form>
    </section>
    """


def event_table(title, rows):
    body = "".join(
        f"""
        <article class="activity-item">
          <div class="activity-head">
            {status_badge(row['status'])}
            <time>{html.escape(row['created_at'].replace(' UTC', ''))}</time>
          </div>
          <strong title="{html.escape(row['original_path'])}">{html.escape(Path(row['original_path']).name)}</strong>
          <dl>
            <dt>Renamed</dt><dd>{html.escape(display_media_name(row['renamed_to'] or 'Pending'))}</dd>
            <dt>Destination</dt><dd title="{html.escape(row['moved_to'] or '')}">{html.escape(short_path(row['moved_to'] or 'Pending'))}</dd>
            <dt>Note</dt><dd>{html.escape(row['message'] or '')}</dd>
          </dl>
        </article>
        """
        for row in rows[:8]
    )
    if not body:
        body = "<p class='empty'>No activity yet</p>"
    return f"""
    <section class="panel">
      <h2>{html.escape(title)}</h2>
      <div class="activity-list">{body}</div>
    </section>
    """


def short_path(value):
    if value in {"", "Pending"}:
        return value
    path = Path(value)
    parts = path.parts
    if len(parts) <= 4:
        return str(path)
    return f".../{'/'.join(parts[-3:])}"


def status_badge(status):
    if status == "done":
        return "<span class='badge completed'>Done</span>"
    if status == "error":
        return "<span class='badge failed'>Error</span>"
    if status.startswith("stage_"):
        return f"<span class='badge'>{html.escape(status.replace('stage_', '').replace('_', ' ').title())}</span>"
    return f"<span class='badge'>{html.escape(status)}</span>"


def simple_log(rows):
    if not rows:
        return "<p class='empty'>No system events yet</p>"
    return "<ul class='logs'>" + "".join(
        f"<li><strong>{html.escape(row['created_at'])}</strong> {status_badge(row['status'])} {html.escape(row['message'] or row['original_path'])}</li>"
        for row in rows[:20]
    ) + "</ul>"


DASHBOARD_JS = """
(() => {
  const root = document.getElementById('dashboard-root');
  if (!root) return;
  let busy = false;
  let delay = 5000;
  let timer = null;
  let countdownTimer = null;

  async function refreshDashboard() {
    if (busy || document.hidden) {
      schedule();
      return;
    }
    busy = true;
    let scheduled = false;
    try {
      const response = await fetch('/api/dashboard', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      root.innerHTML = data.html;
      const note = document.getElementById('refresh-note');
      if (note) note.textContent = `Dashboard sections updated ${data.updated_at}.`;
      refreshDelayFromState();
      startCountdowns();
      schedule();
      scheduled = true;
    } catch (error) {
      const note = document.getElementById('refresh-note');
      if (note) note.textContent = `Dashboard update failed: ${error.message}. Retrying.`;
      delay = Math.min(delay + 5000, 30000);
    } finally {
      busy = false;
      if (!scheduled) schedule();
    }
  }

  function schedule() {
    window.clearTimeout(timer);
    timer = window.setTimeout(refreshDashboard, delay);
  }

  function refreshDelayFromState() {
    const current = root.querySelector('.pipeline-current');
    const activeStage = current && !current.classList.contains('stage-row-queued');
    delay = activeStage ? 1000 : 5000;
  }

  function startCountdowns() {
    window.clearInterval(countdownTimer);
    countdownTimer = window.setInterval(() => {
      root.querySelectorAll('[data-countdown]').forEach((node) => {
        const current = Math.max(0, parseInt(node.dataset.countdown || '0', 10) - 1);
        node.dataset.countdown = String(current);
        node.textContent = String(current);
      });
    }, 1000);
  }

  refreshDelayFromState();
  startCountdowns();
  schedule();
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshDashboard();
  });
})();
"""


FILE_MANAGEMENT_JS = """
(() => {
  const root = document.getElementById('file-management-root');
  if (!root) return;
  async function refresh() {
    try {
      const response = await fetch('/api/file-management', { cache: 'no-store' });
      const data = await response.json();
      root.innerHTML = data.html;
    } catch (error) {}
    window.setTimeout(refresh, 2000);
  }
  window.setTimeout(refresh, 2000);
})();
"""


DUPLICATES_JS = """
(() => {
  const root = document.getElementById('duplicates-root');
  if (!root) return;
  async function refresh() {
    try {
      const response = await fetch('/api/duplicates', { cache: 'no-store' });
      const data = await response.json();
      root.innerHTML = data.html;
    } catch (error) {}
    window.setTimeout(refresh, 5000);
  }
  window.setTimeout(refresh, 5000);
})();
"""


MALWARE_JS = """
(() => {
  const root = document.getElementById('malware-root');
  if (!root) return;
  async function refresh() {
    try {
      const response = await fetch('/api/malware', { cache: 'no-store' });
      const data = await response.json();
      root.innerHTML = data.html;
    } catch (error) {}
    window.setTimeout(refresh, 3000);
  }
  window.setTimeout(refresh, 3000);
})();
"""


GLOBAL_JS = """
(() => {
  const overlay = document.getElementById('loading-overlay');
  if (!overlay) return;
  let statusTimer = null;

  function setMessage(message) {
    const text = overlay.querySelector('span');
    if (text) text.textContent = message;
  }

  function show(message = 'Gathering data...') {
    window.clearTimeout(statusTimer);
    setMessage(message);
    overlay.classList.add('visible');
    overlay.setAttribute('aria-hidden', 'false');
    statusTimer = window.setTimeout(() => {
      setMessage('Still gathering library data...');
    }, 8000);
  }

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href') || '';
    if (!href || href.startsWith('#') || href === '/export-logs' || href === '/scan-now') return;
    if (link.target && link.target !== '_self') return;
    show(href === '/logout' ? 'Logging out...' : 'Gathering page data...');
  });

  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!form) return;
    const action = form.getAttribute('action') || '';
    if (action === '/login') show('Logging in...');
  });
})();
"""


CSS = """
:root { color-scheme: dark; --bg:#101418; --panel:#181f25; --line:#2a343d; --text:#edf2f4; --muted:#9fb0bd; --accent:#55c2a2; --warn:#f5c542; --danger:#ff6b6b; }
* { box-sizing: border-box; }
body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }
header { display:flex; align-items:center; justify-content:space-between; gap:24px; padding:18px 28px; border-bottom:1px solid var(--line); background:#12181d; position:sticky; top:0; z-index:1; }
h1 { margin:0; font-size:22px; }
h2 { margin:0 0 12px; font-size:16px; }
nav { display:flex; gap:8px; flex-wrap:wrap; }
a, button { color:#07120f; background:var(--accent); border:0; border-radius:6px; padding:8px 11px; text-decoration:none; font-weight:700; cursor:pointer; font-size:13px; }
button.danger { background:var(--danger); color:#190404; }
main { padding:18px; max-width:1800px; margin:0 auto; }
.loading-overlay { position:fixed; inset:0; display:none; place-items:center; z-index:50; background:rgba(10,14,18,.68); backdrop-filter:blur(3px); }
.loading-overlay.visible { display:grid; }
.loading-card { width:min(380px,calc(100vw - 40px)); border:1px solid rgba(85,194,162,.45); border-radius:8px; background:#141b20; padding:20px; box-shadow:0 18px 60px rgba(0,0,0,.42), inset 0 0 0 1px rgba(124,183,255,.08); text-align:center; }
.loading-overlay strong, .loading-overlay span { display:block; }
.loading-overlay strong { font-size:18px; margin-bottom:6px; }
.loading-overlay span { color:var(--muted); }
.loading-orbit { position:relative; width:66px; height:66px; margin:0 auto 14px; border:1px solid rgba(124,183,255,.35); border-radius:50%; animation:loading-spin 1.8s linear infinite; }
.loading-orbit::before { content:""; position:absolute; inset:12px; border-radius:50%; border:1px solid rgba(85,194,162,.35); }
.loading-orbit i { position:absolute; width:10px; height:10px; border-radius:50%; background:var(--accent); box-shadow:0 0 18px rgba(85,194,162,.8); }
.loading-orbit i:nth-child(1) { top:-5px; left:28px; }
.loading-orbit i:nth-child(2) { right:4px; bottom:8px; background:#7cb7ff; box-shadow:0 0 18px rgba(124,183,255,.8); }
.loading-orbit i:nth-child(3) { left:4px; bottom:8px; background:var(--warn); box-shadow:0 0 18px rgba(245,197,66,.6); }
.loading-bars { display:grid; gap:6px; margin-top:16px; }
.loading-bars b { display:block; height:5px; border-radius:999px; background:linear-gradient(90deg, rgba(85,194,162,.15), var(--accent), rgba(124,183,255,.2)); background-size:220% 100%; animation:loading-slide 1.2s ease-in-out infinite; }
.loading-bars b:nth-child(2) { animation-delay:.16s; opacity:.82; }
.loading-bars b:nth-child(3) { animation-delay:.32s; opacity:.65; }
@keyframes loading-spin { to { transform:rotate(360deg); } }
@keyframes loading-slide { from { background-position:0 0; } to { background-position:200% 0; } }
.alert-dot { display:inline-grid; place-items:center; min-width:18px; height:18px; padding:0 5px; margin-left:5px; border-radius:999px; background:var(--danger); color:#190404; font-size:11px; font-weight:900; }
.system-strip { display:grid; grid-template-columns:repeat(7,minmax(120px,1fr)); gap:8px; margin-bottom:12px; }
.system-metric { border:1px solid var(--line); border-radius:8px; padding:9px; background:#141b20; min-width:0; }
.system-metric strong, .system-metric span { display:block; overflow-wrap:anywhere; }
.system-metric strong { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
.system-metric span { font-size:13px; font-weight:800; margin-top:3px; }
.system-metric.ok { border-color:rgba(85,194,162,.45); }
.system-metric.warn { border-color:rgba(245,197,66,.6); }
.system-metric.fail { border-color:rgba(255,107,107,.65); }
.stats { display:grid; grid-template-columns:repeat(4,minmax(120px,1fr)); gap:10px; margin-bottom:12px; }
.mini-stats { grid-template-columns:repeat(4,minmax(150px,1fr)); }
.stats article, .panel, .login { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; }
.stats span { display:block; font-size:26px; font-weight:800; line-height:1; margin-bottom:4px; }
.stats strong, .stats small { display:block; }
.stats small, .empty, td, label, p, .logs { color:var(--muted); }
.refresh-note { margin:-4px 0 12px; font-size:12px; color:var(--muted); }
.columns { display:grid; grid-template-columns:1fr 1fr; gap:12px; align-items:start; }
.panel-title { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:10px; }
.panel-title h2 { margin:0; }
.panel-actions { display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }
.health-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:8px; }
.health-item { border:1px solid var(--line); border-radius:8px; padding:9px; background:#141b20; min-width:0; }
.health-item div { display:flex; align-items:center; gap:7px; margin-bottom:6px; }
.health-item strong { font-size:13px; }
.health-item p { margin:0; font-size:12px; overflow-wrap:anywhere; }
.health-item dl { display:grid; grid-template-columns:80px minmax(0,1fr); gap:4px 8px; margin:8px 0; font-size:12px; }
.health-item dt { color:var(--muted); }
.health-item dd { margin:0; overflow-wrap:anywhere; }
.health-item.ok { border-color:rgba(85,194,162,.55); }
.health-item.warn { border-color:rgba(245,197,66,.6); }
.health-item.fail { border-color:rgba(255,107,107,.65); }
.pipeline-focus { display:grid; grid-template-columns:minmax(160px,auto) minmax(260px,1fr); align-items:center; gap:10px; border:1px solid var(--line); border-radius:8px; padding:10px; margin-bottom:10px; background:#141b20; }
.pipeline-focus strong { overflow-wrap:anywhere; }
.pipeline-focus span:last-child { color:var(--muted); overflow-wrap:anywhere; }
.pipeline-focus.malware_check, .pipeline-focus.checking, .pipeline-focus.renaming, .pipeline-focus.folder_check, .pipeline-focus.duplicate_check, .pipeline-focus.moving, .pipeline-focus.cleanup { border-color:#7cb7ff; box-shadow:0 0 0 1px rgba(124,183,255,.15) inset; }
.pipeline-focus.queued { border-color:rgba(245,197,66,.7); }
.pipeline-focus.completed { border-color:rgba(85,194,162,.7); }
.pipeline-focus.quarantined { border-color:rgba(255,107,107,.75); }
.pipeline-focus.idle { grid-template-columns:minmax(180px,1fr) minmax(260px,2fr); }
.timeline { list-style:none; display:grid; grid-template-columns:repeat(9,1fr); gap:8px; padding:0; margin:0 0 10px; }
.job-timeline { grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); }
.timeline li { border:1px solid var(--line); border-radius:8px; padding:7px 8px; color:var(--muted); font-weight:700; min-width:0; font-size:13px; }
.timeline span { display:inline-grid; place-items:center; width:20px; height:20px; margin-right:6px; border-radius:999px; background:var(--accent); color:#07120f; font-size:11px; }
.timeline li.active { border-color:#7cb7ff; color:var(--text); background:#132130; }
.timeline li.active span { background:#7cb7ff; }
.timeline li.complete { border-color:rgba(85,194,162,.55); color:var(--text); }
.timeline li.complete span { background:var(--accent); }
.actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.actions h2 { margin:0 8px 0 0; }
.actions form { display:block; }
.badge { display:inline-block; white-space:nowrap; border:1px solid var(--line); border-radius:999px; padding:4px 8px; color:var(--text); background:#111920; font-size:12px; font-weight:800; }
.badge.queued { border-color:var(--warn); color:var(--warn); }
.badge.malware_check, .badge.checking, .badge.renaming, .badge.folder_check, .badge.duplicate_check, .badge.moving, .badge.cleanup { border-color:#7cb7ff; color:#7cb7ff; }
.badge.completed { border-color:var(--accent); color:var(--accent); }
.badge.failed, .badge.quarantined { border-color:var(--danger); color:var(--danger); }
.progress { height:8px; width:100%; min-width:80px; overflow:hidden; border-radius:999px; background:#0d1216; border:1px solid var(--line); margin-bottom:4px; }
.progress span { display:block; height:100%; background:var(--accent); transition:width .25s ease; }
.progress + small { display:block; color:var(--muted); font-size:11px; line-height:1.2; }
.table-wrap { overflow:visible; }
table { width:100%; border-collapse:collapse; table-layout:fixed; }
th, td { text-align:left; padding:8px 7px; border-bottom:1px solid var(--line); vertical-align:top; font-size:12px; }
th { color:var(--text); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
td { white-space:normal; overflow-wrap:anywhere; }
tr.pipeline-current td { background:#142231; box-shadow:inset 3px 0 0 #7cb7ff; }
.countdown { display:inline-grid; place-items:center; min-width:28px; padding:2px 6px; border-radius:999px; border:1px solid var(--warn); color:var(--warn); font-weight:800; }
.activity-list { display:grid; gap:8px; }
.activity-item { border:1px solid var(--line); border-radius:8px; padding:10px; min-width:0; background:#141b20; }
.activity-head { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:8px; }
.activity-head time { color:var(--muted); font-size:12px; white-space:nowrap; }
.activity-item strong { display:block; margin-bottom:8px; overflow-wrap:anywhere; font-size:13px; }
.activity-item dl { display:grid; grid-template-columns:70px minmax(0,1fr); gap:4px 8px; margin:0; font-size:12px; }
.activity-item dt { color:var(--muted); }
.activity-item dd { margin:0; overflow-wrap:anywhere; color:var(--text); }
.duplicate-list { display:grid; gap:12px; }
.duplicate-card { border:1px solid var(--line); border-radius:8px; padding:12px; background:#141b20; }
.duplicate-card h3 { margin:0; font-size:14px; overflow-wrap:anywhere; }
.duplicate-files { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.duplicate-file { border:1px solid var(--line); border-radius:8px; padding:10px; min-width:0; }
.duplicate-file strong { display:block; margin-bottom:8px; overflow-wrap:anywhere; }
.duplicate-file dl { display:grid; grid-template-columns:72px minmax(0,1fr); gap:4px 8px; margin:8px 0; font-size:12px; }
.duplicate-file dt { color:var(--muted); }
.duplicate-file dd { margin:0; overflow-wrap:anywhere; }
.panel { margin-bottom:12px; }
.login { max-width:420px; margin:60px auto; }
form { display:grid; gap:14px; }
.inline-form { display:block; }
label { display:grid; gap:7px; font-weight:650; }
input { width:100%; color:var(--text); background:#0f1418; border:1px solid var(--line); border-radius:6px; padding:11px 12px; }
code { background:#0f1418; border:1px solid var(--line); border-radius:5px; padding:2px 5px; color:var(--text); }
.error { color:var(--danger); }
.logs { padding-left:18px; margin:0; }
.logs li { margin-bottom:6px; }
@media (max-width: 1200px) { .health-grid { grid-template-columns:repeat(2,minmax(150px,1fr)); } }
@media (max-width: 900px) { header { align-items:flex-start; flex-direction:column; padding:14px 16px; } main { padding:12px; } .stats, .columns, .timeline, .health-grid, .pipeline-focus, .duplicate-files, .system-strip { grid-template-columns:1fr; } .actions h2 { width:100%; } }
"""


def main():
    init_db()
    threading.Thread(target=scanner_loop, daemon=True).start()
    threading.Thread(target=duplicate_scheduler_loop, daemon=True).start()
    threading.Thread(target=malware_scheduler_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"{APP_NAME} listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
