import os
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
FFPROBE_TIMEOUT = int(os.environ.get("DATA_MANAGER_FFPROBE_TIMEOUT", "20"))
MEDIA_SCAN_WORKERS = int(os.environ.get("DATA_MANAGER_MEDIA_SCAN_WORKERS", "2"))
FILE_MANAGEMENT_WORKERS = int(os.environ.get("DATA_MANAGER_FILE_MANAGEMENT_WORKERS", "6"))
MALWARE_SCAN_HOUR = int(os.environ.get("DATA_MANAGER_MALWARE_SCAN_HOUR", "12"))
MALWARE_SCAN_TIMEOUT = int(os.environ.get("DATA_MANAGER_MALWARE_SCAN_TIMEOUT", "900"))
MALWARE_SCAN_WORKERS = int(os.environ.get("DATA_MANAGER_MALWARE_SCAN_WORKERS", "2"))

VIDEO_EXTENSIONS = {
    ".3g2", ".3gp", ".avi", ".flv", ".m2ts", ".m4v", ".mkv", ".mov",
    ".mp4", ".mpeg", ".mpg", ".mts", ".ts", ".vob", ".webm", ".wmv",
}
SIDE_EXTENSIONS = {
    ".srt", ".str", ".ass", ".ssa", ".sub", ".idx", ".vtt", ".sup", ".smi", ".mks", ".ttml", ".dfxp",
    ".nfo", ".jpg", ".jpeg", ".png",
}
IGNORED_WORDS = {
    "1080p", "2160p", "720p", "480p", "bluray", "blu-ray", "webrip",
    "webdl", "web-dl", "hdtv", "hdrip", "dvdrip", "x264", "x265",
    "h264", "h265", "hevc", "aac", "dts", "yify", "rarbg", "proper",
    "repack", "extended", "remastered", "uhd", "hdr", "10bit",
    "bdrip", "brrip", "ita", "eng", "multi", "dual", "audio",
    "itvx", "web", "dl", "web dl", "aac2", "aac2 0", "h 264", "rawr",
}
DEFAULT_SETTINGS = {
    "admin_user": ADMIN_USER,
    "admin_password": ADMIN_PASSWORD,
    "sso_enabled": "no",
    "sso_provider_name": "Authentik",
    "sso_client_id": "",
    "sso_client_secret": "",
    "sso_authorize_url": "",
    "sso_token_url": "",
    "sso_userinfo_url": "",
    "sso_redirect_uri": "",
    "sso_scope": "openid email profile",
    "sso_allowed_users": "",
    "sso_allowed_domains": "",
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
    "tmdb_api_key": TMDB_API_KEY,
    "tvmaze_fallback_enabled": "yes",
    "tvmaze_backoff_seconds": "900",
    "transfer_mode": "move",
    "max_ready_per_scan": str(MAX_READY_PER_SCAN),
    "file_management_workers": str(FILE_MANAGEMENT_WORKERS),
    "duplicate_scan_workers": str(MEDIA_SCAN_WORKERS),
    "duplicate_schedule": "daily",
    "duplicate_scan_hour": str(DUPLICATE_SCAN_HOUR),
    "duplicate_schedule_day": "0",
    "duplicate_schedule_day_of_month": "1",
    "malware_scan_workers": str(MALWARE_SCAN_WORKERS),
    "ffprobe_timeout": str(FFPROBE_TIMEOUT),
    "transfer_chunk_size": str(TRANSFER_CHUNK_SIZE),
    "max_queue_display": str(MAX_QUEUE_DISPLAY),
    "max_new_file_events_per_scan": str(MAX_NEW_FILE_EVENTS_PER_SCAN),
    "max_requeue_per_click": str(MAX_REQUEUE_PER_CLICK),
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
    "malware_schedule": "daily",
    "malware_daily_hour": str(MALWARE_SCAN_HOUR),
    "malware_schedule_day": "0",
    "malware_schedule_day_of_month": "1",
}
