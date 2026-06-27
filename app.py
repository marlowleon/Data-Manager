#!/usr/bin/env python3
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

from data_manager_config import *
from data_manager_inventory import empty_inventory, scan_media_files
from data_manager_jobs import get_job, start_background_job, update_job
from data_manager_media import *
from data_manager_store import *
from data_manager_utils import *
from data_manager_server import Handler, configure_server, sso_health_check
from data_manager_views import configure_views

scan_event = threading.Event()
inventory_lock = threading.Lock()
pushover_lock = threading.Lock()
pushover_validation_cache = {"checked_at": 0, "settings_key": "", "result": None}
malware_lock = threading.Lock()
malware_definition_cache = {"checked_at": 0, "ok": False, "detail": "Not checked yet"}
clamav_slot_condition = threading.Condition()
clamav_active_scans = 0
tmdb_lock = threading.Lock()
tmdb_validation_cache = {"checked_at": 0, "settings_key": "", "movie": None, "tv": None}
tvmaze_lock = threading.Lock()
tvmaze_cache = {}
tvmaze_backoff_until = 0
preflight_lock = threading.Lock()
preflight_state = {"logged_at": 0, "message": ""}
watch_inventory_cache = {
    "total": 0,
    "supported": 0,
    "ignored_exts": {},
    "samples": [],
    "updated_at": "Never",
}
library_visibility_lock = threading.Lock()
library_visibility_cache = {}


def get_queue():
    settings = get_settings()
    stable_seconds = max(0, int(settings.get("stable_seconds", "30") or "30"))
    display_limit = int_setting(settings, "max_queue_display", MAX_QUEUE_DISPLAY, minimum=1, maximum=500)
    now = time.time()
    with db_lock, db() as conn:
        rows = conn.execute(
            "select * from seen_files where processed = 0 order by first_seen limit ?",
            (display_limit,),
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
    settings = get_settings()
    display_limit = int_setting(settings, "max_queue_display", MAX_QUEUE_DISPLAY, minimum=1, maximum=500)
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
        "display_limit": display_limit,
        "hidden_queue": max(0, queued["total"] - display_limit),
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


def int_setting(settings, key, default, minimum=1, maximum=None):
    try:
        value = int(settings.get(key, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


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
    max_requeue = int_setting(settings, "max_requeue_per_click", MAX_REQUEUE_PER_CLICK, minimum=1, maximum=5000)
    count = 0
    with db_lock, db() as conn:
        for path in watch_folder.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if count >= max_requeue:
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
            f"(limit {max_requeue} per click). {inventory_message(inventory, settings)}"
        ),
    )
    scan_event.set()
    return count


def dashboard_health():
    settings = get_settings()
    checks = [
        access_control_health_check(settings),
        sso_health_check(settings),
        tmdb_health_check(settings),
        tmdb_tv_health_check(settings),
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


def access_control_health_check(settings):
    issues = []
    if SESSION_SECRET == "change-me-in-production" or len(str(SESSION_SECRET)) < 32:
        issues.append("set a long DATA_MANAGER_SESSION_SECRET")
    local_users = get_local_users()
    active_admins = [user for user in local_users if user["role"] == "admin" and int(user["enabled"])]
    if not active_admins:
        issues.append("create at least one enabled admin account")
    active_admin_details = [get_local_user(user["username"]) for user in active_admins]
    if any((user or {}).get("password_hash") in {"", "changeme"} for user in active_admin_details):
        issues.append("change the default admin password")
    if setting_enabled(settings, "viewer_enabled") and not settings.get("viewer_password", "").strip():
        issues.append("set a view-only password or disable the viewer user")
    if issues:
        return {"name": "Access Control", "status": "fail", "detail": "; ".join(issues)}
    return {"name": "Access Control", "status": "ok", "detail": "Role checks and CSRF protection are active"}


def tmdb_api_key(settings=None):
    settings = settings or get_settings()
    return settings.get("tmdb_api_key", "").strip() or TMDB_API_KEY


def cached_tmdb_checks(settings, force=False):
    settings_key = tmdb_api_key(settings)
    now = time.time()
    with tmdb_lock:
        fresh = now - tmdb_validation_cache["checked_at"] < 300
        if (
            not force
            and fresh
            and tmdb_validation_cache["settings_key"] == settings_key
            and tmdb_validation_cache["movie"]
            and tmdb_validation_cache["tv"]
        ):
            return tmdb_validation_cache["movie"], tmdb_validation_cache["tv"]
    movie = uncached_tmdb_movie_health_check(settings)
    tv = uncached_tmdb_tv_health_check(settings)
    with tmdb_lock:
        tmdb_validation_cache.update({
            "checked_at": now,
            "settings_key": settings_key,
            "movie": movie,
            "tv": tv,
        })
    return movie, tv


def tmdb_health_check(settings=None):
    return cached_tmdb_checks(settings or get_settings())[0]


def tmdb_tv_health_check(settings=None):
    return cached_tmdb_checks(settings or get_settings())[1]


def uncached_tmdb_movie_health_check(settings):
    if not tmdb_api_key(settings):
        return {
            "name": "TMDB API",
            "status": "fail",
            "detail": "TMDB API key is missing in Settings",
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


def uncached_tmdb_tv_health_check(settings):
    if not tmdb_api_key(settings):
        return {
            "name": "TMDB TV API",
            "status": "fail",
            "detail": "TMDB API key is missing in Settings",
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


def processing_preflight(settings):
    checks = [
        path_health_check("Watch mount", settings["watch_folder"], needs_write=True),
        path_health_check("Movie mount", settings["movie_folder"], needs_write=True),
        path_health_check("TV mount", settings["tv_folder"], needs_write=True),
        path_health_check("Review mount", settings["review_folder"], needs_write=True),
        path_health_check("Quarantine mount", settings["quarantine_folder"], needs_write=True),
        path_health_check("Database", DB_PATH.parent, needs_write=True),
    ]
    if metadata_enabled(settings) and metadata_required(settings) and settings.get("metadata_provider") == "tmdb":
        movie_check, tv_check = cached_tmdb_checks(settings)
        checks.extend([movie_check, tv_check])
    failures = [check for check in checks if check["status"] == "fail"]
    if failures:
        message = "; ".join(f"{check['name']}: {check['detail']}" for check in failures)
        throttled_preflight_event(message)
        return False
    return True


def throttled_preflight_event(message):
    now = time.time()
    with preflight_lock:
        if preflight_state["message"] == message and now - preflight_state["logged_at"] < 300:
            return
        preflight_state.update({"message": message, "logged_at": now})
    add_event("system", "error", "preflight", message=f"Auto scan paused: {message}")


def tmdb_get(endpoint, params):
    api_key = tmdb_api_key()
    if not api_key:
        return None
    params = dict(params)
    params["api_key"] = api_key
    params.setdefault("language", "en-US")
    url = f"{TMDB_BASE_URL}{endpoint}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def tvmaze_get(endpoint, params, settings=None):
    global tvmaze_backoff_until
    settings = settings or get_settings()
    now = time.time()
    with tvmaze_lock:
        if now < tvmaze_backoff_until:
            remaining = int(tvmaze_backoff_until - now)
            raise RuntimeError(f"TVmaze is rate limited; backing off for {remaining}s")
        cache_key = (endpoint, tuple(sorted((params or {}).items())))
        cached = tvmaze_cache.get(cache_key)
        if cached and now - cached["time"] < 24 * 3600:
            return cached["data"]
    url = f"{TVMAZE_BASE_URL}{endpoint}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            retry_after = exc.headers.get("Retry-After")
            backoff = int_setting(settings, "tvmaze_backoff_seconds", 900, minimum=60, maximum=86400)
            if retry_after and retry_after.isdigit():
                backoff = max(backoff, int(retry_after))
            with tvmaze_lock:
                tvmaze_backoff_until = time.time() + backoff
            raise RuntimeError(f"TVmaze rate limit reached; backing off for {backoff}s") from exc
        raise
    with tvmaze_lock:
        tvmaze_cache[cache_key] = {"time": time.time(), "data": data}
        if len(tvmaze_cache) > 1000:
            oldest = sorted(tvmaze_cache, key=lambda key: tvmaze_cache[key]["time"])[:200]
            for key in oldest:
                tvmaze_cache.pop(key, None)
    return data


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

    needs_episode_name = not (enriched or tv).get("episode_name")
    if setting_enabled(settings, "tvmaze_fallback_enabled") and (source == "filename" or needs_episode_name):
        tvmaze_enriched, tvmaze_source = enrich_tv_with_tvmaze(enriched or tv, settings)
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


def enrich_tv_with_tvmaze(tv, settings):
    try:
        data = []
        for title in tv_title_variants(tv["title"]):
            data = tvmaze_get("/search/shows", {"q": title}, settings=settings)
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
            settings=settings,
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


def library_folder_name(title, year):
    return movie_folder_name(title, year)


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
                f"deleting lower-quality existing video after upgrade verifies"
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
    replacement = handle_conflict_action(plan, settings)
    if transfer_mode == "move":
        transfer_file_with_progress(path, target_file)
    else:
        transfer_file_with_progress(path, target_file)
    set_file_stage(path, "moving", "Transfer 100% complete; verifying destination file")
    verify_target_file(target_file, expected_size)
    if transfer_mode == "move" and path.exists():
        path.unlink()
    sidecars = transfer_sidecars(path, target_dir, target_file.stem, transfer_mode)
    preserved_sidecars = finalize_replacement_conflict(plan, replacement, settings)
    if sidecars:
        add_event(
            plan["media_type"],
            "stage_moving",
            path,
            plan["renamed_to"],
            str(target_file),
            f"Moved {len(sidecars)} subtitle/sidecar file(s) with the media file",
        )
    if preserved_sidecars:
        add_event(
            plan["media_type"],
            "stage_moving",
            path,
            plan["renamed_to"],
            str(target_file),
            f"Preserved {len(preserved_sidecars)} subtitle/sidecar file(s) from the replaced lower-quality copy",
        )
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
        return None
    existing = plan.get("existing_duplicate")
    if not existing or not Path(existing).exists():
        return None
    existing = Path(existing)
    target_file = Path(plan["target_file"])
    delete_path = existing
    if existing.resolve() == target_file.resolve():
        hold_path = unique_path(existing.with_name(f".{existing.stem}.data-manager-replace{existing.suffix.lower()}"))
        shutil.move(str(existing), str(hold_path))
        delete_path = hold_path
    return {"delete_path": delete_path, "sidecar_source": existing}


def finalize_replacement_conflict(plan, replacement, settings):
    if not replacement:
        return []
    delete_path = Path(replacement["delete_path"])
    sidecar_source = Path(replacement["sidecar_source"])
    target_file = Path(plan["target_file"])
    sidecars = transfer_sidecars(sidecar_source, target_file.parent, target_file.stem, "move")
    if delete_path.exists():
        delete_path.unlink()
    sidecar_note = f" and preserved {len(sidecars)} sidecar file(s)" if sidecars else ""
    add_event(
        plan["media_type"],
        "stage_duplicate_check",
        sidecar_source,
        moved_to=str(target_file),
        message=f"Smart conflict: deleted lower-quality existing video after upgrade verification{sidecar_note}: {sidecar_source}",
    )
    notify_duplicate(settings, plan["duplicate_status"], sidecar_source, target_file)
    return sidecars


def transfer_file_with_progress(source, target):
    total = source.stat().st_size
    transferred = 0
    settings = get_settings()
    chunk_size = max(
        1024 * 1024,
        int_setting(settings, "transfer_chunk_size", TRANSFER_CHUNK_SIZE, minimum=1024 * 1024, maximum=64 * 1024 * 1024),
    )
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
    transferred = []
    for sibling in source_video.parent.iterdir():
        if sibling == source_video or sibling.suffix.lower() not in SIDE_EXTENSIONS:
            continue
        target = sidecar_target_path(source_video, sibling, target_dir, target_stem)
        if not target:
            continue
        target = unique_path(target)
        if transfer_mode == "move":
            shutil.move(str(sibling), str(target))
        else:
            shutil.copy2(str(sibling), str(target))
        transferred.append((sibling, target))
    return transferred


def sidecar_target_path(source_video, sidecar, target_dir, target_stem):
    descriptor = sidecar_descriptor(source_video.stem, sidecar.stem)
    if descriptor is None:
        return None
    return Path(target_dir) / f"{target_stem}{descriptor}{sidecar.suffix.lower()}"


def sidecar_descriptor(video_stem, sidecar_stem):
    video_raw = str(video_stem).strip()
    sidecar_raw = str(sidecar_stem).strip()
    if not video_raw or not sidecar_raw:
        return None

    video_lower = video_raw.lower()
    sidecar_lower = sidecar_raw.lower()
    if sidecar_lower == video_lower:
        return ""

    if sidecar_lower.startswith(video_lower):
        suffix = sidecar_raw[len(video_raw):]
        if not suffix or suffix[0] in ".-_ ":
            descriptor = clean_sidecar_descriptor(suffix)
            return descriptor

    video_norm = normalize_sidecar_stem(video_raw)
    sidecar_norm = normalize_sidecar_stem(sidecar_raw)
    if sidecar_norm == video_norm:
        return ""

    if sidecar_norm.startswith(f"{video_norm} "):
        tail = sidecar_norm[len(video_norm):].strip()
        descriptor = clean_sidecar_descriptor(tail)
        if descriptor is not None:
            return descriptor

    return None


def normalize_sidecar_stem(value):
    value = re.sub(r"[._-]+", " ", str(value).lower())
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def clean_sidecar_descriptor(value):
    parts = [part.lower() for part in re.split(r"[^A-Za-z0-9]+", str(value)) if part]
    if not parts:
        return ""
    allowed_words = {
        "english", "spanish", "french", "german", "italian", "portuguese",
        "japanese", "korean", "chinese",
        "forced", "foreign", "sdh", "hi", "cc", "default", "commentary", "signs", "songs",
    }
    if len(parts) > 4 or any(not sidecar_descriptor_part_allowed(part, allowed_words) for part in parts):
        return None
    return "." + ".".join(parts)


def sidecar_descriptor_part_allowed(part, allowed_words):
    return (
        part in allowed_words
        or bool(re.fullmatch(r"[a-z]{2,3}", part))
        or bool(re.fullmatch(r"\d{1,2}", part))
    )


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


def malware_scan_limit(settings):
    return int_setting(settings, "malware_scan_workers", MALWARE_SCAN_WORKERS, minimum=1, maximum=8)


def malware_scan_timeout(settings):
    return int_setting(settings, "malware_scan_timeout", MALWARE_SCAN_TIMEOUT, minimum=30, maximum=86400)


def acquire_clamav_slot(settings):
    global clamav_active_scans
    limit = malware_scan_limit(settings)
    with clamav_slot_condition:
        while clamav_active_scans >= limit:
            clamav_slot_condition.wait(timeout=5)
        clamav_active_scans += 1
    return limit


def release_clamav_slot():
    global clamav_active_scans
    with clamav_slot_condition:
        clamav_active_scans = max(0, clamav_active_scans - 1)
        clamav_slot_condition.notify_all()


def clamscan_failure_detail(returncode, output, timeout, limit):
    if returncode == -9:
        return (
            "clamscan was killed with SIGKILL (-9). This usually means Docker or Unraid killed "
            "the scan for memory pressure. Set Malware scan workers to 1, reduce new-file "
            "workers during big imports, or increase the container memory limit."
        )
    if returncode < 0:
        return f"clamscan was killed by signal {-returncode}. Output: {output[:300] or 'none'}"
    return output or f"clamscan exited with {returncode} after timeout={timeout}s limit={limit}"


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
    timeout = malware_scan_timeout(settings)
    limit = acquire_clamav_slot(settings)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError(
            f"clamscan timed out after {timeout} seconds. Increase Malware scan timeout seconds "
            "or scan fewer/lower-size files at once."
        ) from exc
    finally:
        release_clamav_slot()
    output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    infected = result.returncode == 1
    if result.returncode not in {0, 1}:
        detail = clamscan_failure_detail(result.returncode, output, timeout, limit)
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
    if not processing_preflight(settings):
        return
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

        max_ready = int_setting(settings, "max_ready_per_scan", MAX_READY_PER_SCAN, minimum=1, maximum=20)
        ready = conn.execute(
            "select * from seen_files where processed = 0 and ? - first_seen >= ? order by first_seen limit ?",
            (now, stable_seconds, max_ready),
        ).fetchall()

    update_watch_inventory_cache(inventory)

    max_new_events = int_setting(settings, "max_new_file_events_per_scan", MAX_NEW_FILE_EVENTS_PER_SCAN, minimum=0, maximum=5000)
    for path in new_files[:max_new_events]:
        add_event("system", "stage_queued", path, message="Stage 1: detected and queued")
    if len(new_files) > max_new_events:
        add_event(
            "system",
            "stage_queued",
            watch_folder,
            message=f"Stage 1: detected {len(new_files)} new files; logging first {max_new_events}",
        )

    if not ready:
        return

    def process_ready_row(row):
        path = Path(row["path"])
        try:
            if not path.exists():
                set_file_stage(path, "failed", "File disappeared before processing", last_error="File disappeared before processing")
                add_event("system", "error", path, message="File disappeared before processing")
                notify_failure(settings, path, "File disappeared before processing")
                mark_processed(path)
                return
            current = path.stat()
            if current.st_size != row["size"] or current.st_mtime != row["mtime"]:
                set_file_stage(path, "queued", "File is still changing; waiting for it to finish downloading")
                reset_seen(path, current)
                return
            process_file(path, settings)
            mark_processed(path)
        except Exception as exc:
            set_file_stage(path, "failed", f"Processing failed: {exc}", last_error=str(exc))
            add_event("system", "error", path, message=str(exc))
            notify_failure(settings, path, str(exc))
            mark_processed(path)

    max_workers = min(len(ready), int_setting(settings, "max_ready_per_scan", MAX_READY_PER_SCAN, minimum=1, maximum=20))
    add_event("system", "stage_queued", watch_folder, message=f"Processing {len(ready)} ready file(s) with {max_workers} worker(s)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_ready_row, row) for row in ready]
        for future in concurrent.futures.as_completed(futures):
            future.result()


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


def empty_library_inventory(root):
    return empty_inventory(root)


def media_files(root, settings, update_inventory=False):
    root = Path(root)
    cache_key = (str(root), settings.get("movie_extensions", ""))
    files, inventory = scan_media_files(root, extension_set(settings))
    if update_inventory:
        set_library_inventory_cache(cache_key, inventory)
    return files


def set_library_inventory_cache(cache_key, inventory):
    cached_at = time.time()
    inventory = dict(inventory)
    inventory["cached_at_label"] = now_iso()
    inventory["cache_only"] = False
    with library_visibility_lock:
        library_visibility_cache[cache_key] = {"cached_at": cached_at, "inventory": inventory}


def library_inventory(root, settings):
    root = Path(root)
    cache_key = (str(root), settings.get("movie_extensions", ""))
    with library_visibility_lock:
        cached = library_visibility_cache.get(cache_key)
        if cached:
            inventory = dict(cached["inventory"])
            inventory.setdefault("cached_at_label", datetime.fromtimestamp(cached["cached_at"], timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
            inventory.setdefault("cache_only", False)
            return inventory
    return empty_library_inventory(root)


def refresh_library_inventory(root, settings):
    return library_inventory_from_scan(root, settings)


def library_inventory_from_scan(root, settings):
    files = media_files(root, settings, update_inventory=True)
    inventory = library_inventory(root, settings)
    inventory["files_seen"] = len(files)
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
    files = media_files(settings["movie_folder"], settings, update_inventory=True)
    run_manual_scan("movie", files, settings)


def manual_scan_tv_job():
    settings = get_settings()
    files = media_files(settings["tv_folder"], settings, update_inventory=True)
    run_manual_scan("tv", files, settings)


def manual_scan_all_job():
    settings = get_settings()
    files = (
        media_files(settings["movie_folder"], settings, update_inventory=True)
        + media_files(settings["tv_folder"], settings, update_inventory=True)
    )
    run_manual_scan("all", files, settings)


def run_manual_scan(kind, files, settings):
    total = len(files)
    workers = min(total or 1, int_setting(settings, "file_management_workers", FILE_MANAGEMENT_WORKERS, minimum=1, maximum=12))
    update_job(
        "file_management",
        total=total,
        workers=workers,
        stage="Inventory",
        message=f"Found {total} files to scan. File Management will use {workers} worker(s).",
        activity=f"Inventory complete: {total} files queued for {kind} scan with {workers} worker(s)",
    )
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
        persist_job_stat("file_management")
        add_event("system", "error", "file-management", message=message)
        return
    counters = {"changed": 0, "failed": 0, "processed": 0}

    def scan_one(path):
        try:
            if kind == "movie" and parse_tv(path):
                return "skipped", f"Skipped TV-looking file during movie scan: {path.name}", None
            if kind == "tv" and not parse_tv(path):
                return "skipped", f"Skipped non-TV file during TV scan: {path.name}", None
            before = str(path)
            target = manual_library_target(path, settings)
            if target and path.resolve() != target.resolve():
                target.parent.mkdir(parents=True, exist_ok=True)
                final_target = unique_path(target)
                shutil.move(str(path), str(final_target))
                return "changed", f"Changed: {before} -> {final_target}", final_target
            return "ok", f"Already correct: {path}", target
        except Exception as exc:
            add_event("system", "error", path, message=f"Manual library scan failed: {exc}")
            return "failed", f"Failed: {path} - {exc}", None

    update_job(
        "file_management",
        stage="Identify",
        message=f"Reading filenames, metadata provider matches, and quality for {total} file(s)",
        activity="Identify: parsing filenames, metadata, and quality",
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_one, path): path for path in files}
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            status, activity, target = future.result()
            counters["processed"] += 1
            if status == "changed":
                counters["changed"] += 1
            elif status == "failed":
                counters["failed"] += 1
            stage = "Move/Rename" if status == "changed" else "Verify"
            progress = int((counters["processed"] / total) * 100)
            update_job(
                "file_management",
                stage=stage,
                progress=progress,
                processed=counters["processed"],
                changed=counters["changed"],
                failed=counters["failed"],
                current_folder=str(Path(target).parent) if target else str(path.parent),
                current_file=Path(target).name if target else path.name,
                workers=workers,
                last_error=activity if status == "failed" else "",
                message=(
                    f"Processed {counters['processed']} of {total} with {workers} worker(s). "
                    f"Renamed/moved {counters['changed']}; failed {counters['failed']}."
                ),
                activity=activity,
            )
    update_job(
        "file_management",
        running=False,
        stage="Complete",
        progress=100,
        processed=total,
        changed=counters["changed"],
        failed=counters["failed"],
        last_success_at=now_iso() if counters["failed"] == 0 else "",
        message=f"Manual scan complete. Renamed/moved {counters['changed']}; failed {counters['failed']}",
        activity=f"Manual scan complete: {counters['changed']} changed, {counters['failed']} failed",
    )
    persist_job_stat("file_management")
    add_event("system", "done", "file-management", message=f"Manual {kind} scan complete: {counters['changed']} changed, {counters['failed']} failed")
    notify_scan_complete(settings, "File Management", f"Manual {kind} scan complete: {counters['changed']} changed, {counters['failed']} failed")


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
    movie_files = media_files(settings["movie_folder"], settings, update_inventory=True)
    tv_files = media_files(settings["tv_folder"], settings, update_inventory=True)
    files = movie_files + tv_files
    total = len(files)
    workers = int_setting(settings, "duplicate_scan_workers", MEDIA_SCAN_WORKERS, minimum=1, maximum=12)
    update_job(
        "duplicate_checker",
        total=total,
        workers=workers,
        stage="Inventory",
        message=f"Found {total} library files. Duplicate indexing will use {workers} worker(s).",
        activity=f"Inventory: {len(movie_files)} movie files, {len(tv_files)} TV files, {workers} worker(s)",
    )
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
        persist_job_stat("duplicate_checker")
        add_event("system", "error", "duplicate-checker", message=message)
        return
    groups = {}
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
                stage="Fingerprint",
                current_folder=str(path.parent),
                current_file=path.name,
                progress=progress,
                processed=index,
                workers=workers,
                message=f"Fingerprint/indexed {index} of {total} files with {workers} worker(s). Current: {path.name}",
                activity=f"Fingerprint: {path.name}",
            )
    findings = []
    update_job("duplicate_checker", stage="Group Matches", progress=75, message=f"Grouping {len(groups)} media keys and finding duplicates", activity=f"Grouping {len(groups)} media keys")
    for key, paths in groups.items():
        if len(paths) < 2:
            continue
        sorted_paths = sorted(paths, key=lambda item: quality_score(item), reverse=True)
        keep = sorted_paths[0]
        for duplicate in sorted_paths[1:]:
            findings.append((key, keep, duplicate))
            update_job("duplicate_checker", activity=f"Duplicate found: keep {keep.name}; review {duplicate.name}")
    update_job("duplicate_checker", stage="Save Results", progress=90, message=f"Saving {len(findings)} duplicate pair(s)")
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
    persist_job_stat("duplicate_checker")
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
    run_malware_library_scan("movies", media_files(settings["movie_folder"], settings, update_inventory=True), settings)


def malware_scan_tv_job():
    settings = get_settings()
    run_malware_library_scan("tv", media_files(settings["tv_folder"], settings, update_inventory=True), settings)


def malware_scan_all_job():
    settings = get_settings()
    files = (
        media_files(settings["movie_folder"], settings, update_inventory=True)
        + media_files(settings["tv_folder"], settings, update_inventory=True)
    )
    run_malware_library_scan("all", files, settings)


def run_malware_library_scan(kind, files, settings):
    total = len(files)
    workers = malware_scan_limit(settings)
    update_job(
        "malware_scanner",
        total=total,
        workers=workers,
        stage="Inventory",
        message=f"Found {total} files to scan. ClamAV will use up to {workers} worker(s).",
        activity=f"Inventory complete: {total} files, up to {workers} ClamAV worker(s)",
    )
    if not malware_enabled(settings):
        message = "Malware scanning is disabled in Settings"
        update_job("malware_scanner", running=False, stage="Complete", progress=100, message=message, activity=message)
        persist_job_stat("malware_scanner")
        add_event("system", "error", "malware-scanner", message=message)
        return
    if total == 0:
        message = "No supported video files found for malware scan"
        update_job("malware_scanner", running=False, stage="Complete", progress=100, processed=0, total=0, message=message, activity=message)
        persist_job_stat("malware_scanner")
        add_event("system", "done", "malware-scanner", message=message)
        return
    definitions_ok, definition_detail = ensure_malware_definitions(settings, force=False)
    update_job("malware_scanner", stage="Update Definitions", message=definition_detail, activity=f"Definitions: {definition_detail}")
    if not definitions_ok:
        message = f"Cannot run malware scan: {definition_detail}"
        update_job("malware_scanner", running=False, stage="Failed", progress=100, failed=total, last_error=message, message=message, activity=message)
        persist_job_stat("malware_scanner")
        add_event("system", "error", "malware-scanner", message=message)
        notify_failure(settings, "malware-scanner", message)
        return

    infected = 0
    quarantined = 0
    failed = 0
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
                    stage = "Quarantine"
                else:
                    activity = f"Clean: {path.name}"
                    stage = "ClamAV Scan"
            except Exception as exc:
                failed += 1
                activity = f"Failed: {path.name} - {exc}"
                stage = "ClamAV Scan"
                add_event("system", "error", path, message=f"Malware scan failed: {exc}")
            progress = int((index / total) * 100)
            update_job(
                "malware_scanner",
                stage=stage,
                current_folder=str(path.parent),
                current_file=path.name,
                progress=progress,
                processed=index,
                infected=infected,
                quarantined=quarantined,
                failed=failed,
                workers=workers,
                message=f"Scanned {index} of {total} with {workers} worker(s). Infected {infected}; quarantined {quarantined}; failed {failed}. Current: {path.name}",
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
    persist_job_stat("malware_scanner")
    add_event("system", "done" if failed == 0 else "error", "malware-scanner", message=message)
    notify_scan_complete(settings, "Malware Scan", message)


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


def persist_job_stat(name):
    save_job_stat(name, get_job(name))


def is_critical_alert(row):
    if row["status"] != "error":
        return False
    text = f"{row['media_type']} {row['original_path']} {row['message'] or ''}".lower()
    critical_terms = [
        "preflight", "mount", "watch folder", "database", "tmdb", "api key",
        "connection failed", "metadata provider down", "pushover", "clamav",
        "malware quarantined", "high cpu", "memory", "not writable",
    ]
    return any(term in text for term in critical_terms)


def alert_count():
    return sum(1 for row in get_events(300) if is_critical_alert(row))


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


def schedule_due(settings, prefix, default_hour, last_run_key):
    schedule = settings.get(f"{prefix}_schedule", "daily").lower()
    if schedule == "disabled":
        return False, last_run_key
    local = time.localtime()
    hour = int_setting(settings, f"{prefix}_scan_hour" if prefix == "duplicate" else "malware_daily_hour", default_hour, minimum=0, maximum=23)
    if local.tm_hour != hour:
        return False, last_run_key
    if schedule == "weekly":
        day = int_setting(settings, f"{prefix}_schedule_day", 0, minimum=0, maximum=6)
        if local.tm_wday != day:
            return False, last_run_key
        key = time.strftime("%Y-%m-%d", local)
    elif schedule == "monthly":
        day = int_setting(settings, f"{prefix}_schedule_day_of_month", 1, minimum=1, maximum=31)
        if local.tm_mday != day:
            return False, last_run_key
        key = time.strftime("%Y-%m", local)
    else:
        key = time.strftime("%Y-%m-%d", local)
    return key != last_run_key, key


def duplicate_scheduler_loop():
    last_run_key = None
    while True:
        settings = get_settings()
        due, key = schedule_due(settings, "duplicate", DUPLICATE_SCAN_HOUR, last_run_key)
        if due:
            if start_background_job("duplicate_checker", "Scheduled Duplicate Scan", duplicate_scan_job):
                last_run_key = key
        time.sleep(60)


def malware_scheduler_loop():
    last_run_key = None
    while True:
        settings = get_settings()
        due, key = schedule_due(settings, "malware", MALWARE_SCAN_HOUR, last_run_key)
        if malware_enabled(settings) and due:
            if start_background_job("malware_scanner", "Scheduled Malware Scan", malware_scan_all_job):
                last_run_key = key
        time.sleep(60)


def configure_runtime_contexts():
    configure_views({
        "alert_count": alert_count,
        "clamav_health_check": clamav_health_check,
        "container_cpu_percent": container_cpu_percent,
        "container_memory_percent": container_memory_percent,
        "dashboard_health": dashboard_health,
        "duplicate_status_counts": duplicate_status_counts,
        "get_duplicate_results": get_duplicate_results,
        "get_queue": get_queue,
        "library_inventory": library_inventory,
        "path_health_check": path_health_check,
        "resource_health_check": resource_health_check,
        "stats": stats,
    })
    configure_server({
        "alert_count": alert_count,
        "delete_duplicate_file": delete_duplicate_file,
        "duplicate_scan_job": duplicate_scan_job,
        "malware_scan_all_job": malware_scan_all_job,
        "malware_scan_movies_job": malware_scan_movies_job,
        "malware_scan_tv_job": malware_scan_tv_job,
        "manual_scan_all_job": manual_scan_all_job,
        "manual_scan_movies_job": manual_scan_movies_job,
        "manual_scan_tv_job": manual_scan_tv_job,
        "requeue_watch_files": requeue_watch_files,
        "scan_now": scan_event.set,
        "test_pushover": test_pushover,
    })


def main():
    init_db()
    configure_runtime_contexts()
    threading.Thread(target=scanner_loop, daemon=True).start()
    threading.Thread(target=duplicate_scheduler_loop, daemon=True).start()
    threading.Thread(target=malware_scheduler_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"{APP_NAME} listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
