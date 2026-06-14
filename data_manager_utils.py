import os
import re
import time
import threading
from pathlib import Path
from datetime import datetime, timezone


resource_lock = threading.Lock()
last_cpu_sample = {"time": time.time(), "usage_usec": None}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def setting_enabled(settings, key):
    return settings.get(key, "no").lower() in {"yes", "true", "1", "on"}


def safe_name(name):
    value = re.sub(r'[<>:"/\\|?*]', " ", str(name))
    value = re.sub(r"\s+", " ", value).strip(" .")
    return value[:180] or "Unknown"


def unique_path(path):
    path = Path(path)
    if not path.exists():
        return path
    counter = 2
    while True:
        candidate = path.with_name(f"{path.stem} ({counter}){path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def format_bytes(value):
    value = int(value or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024


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


def format_elapsed(seconds):
    seconds = int(seconds or 0)
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


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
