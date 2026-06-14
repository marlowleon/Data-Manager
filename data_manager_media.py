import json
import re
import subprocess
import threading
from pathlib import Path

from data_manager_config import FFPROBE_TIMEOUT, IGNORED_WORDS, SIDE_EXTENSIONS, VIDEO_EXTENSIONS
from data_manager_utils import safe_name


media_info_lock = threading.Lock()
media_info_cache = {}


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


def strip_media_type(name):
    cleaned = str(name).strip()
    for extension in VIDEO_EXTENSIONS:
        if cleaned.lower().endswith(extension):
            cleaned = cleaned[: -len(extension)].strip()
    cleaned = re.sub(r"\b(mkv|mp4|avi|mov|wmv|webm|m4v)\b$", "", cleaned, flags=re.I).strip()
    return cleaned


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
