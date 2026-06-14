import html
from datetime import datetime, timezone
from pathlib import Path

from data_manager_config import DEFAULT_SETTINGS, DUPLICATE_SCAN_HOUR, MALWARE_SCAN_HOUR, VIDEO_EXTENSIONS
from data_manager_jobs import get_job
from data_manager_media import media_info
from data_manager_store import get_events, get_settings
from data_manager_utils import (
    format_audio_channels,
    format_bitrate,
    format_bytes,
    format_duration,
    format_elapsed,
)

_view_context = {}


def configure_views(context):
    _view_context.update(context)


def _context_call(name, *args, **kwargs):
    if name not in _view_context:
        raise RuntimeError(f"View context missing {name}")
    return _view_context[name](*args, **kwargs)


def get_queue():
    return _context_call("get_queue")


def stats():
    return _context_call("stats")


def dashboard_health():
    return _context_call("dashboard_health")


def library_inventory(*args, **kwargs):
    return _context_call("library_inventory", *args, **kwargs)


def clamav_health_check(*args, **kwargs):
    return _context_call("clamav_health_check", *args, **kwargs)


def path_health_check(*args, **kwargs):
    return _context_call("path_health_check", *args, **kwargs)


def get_duplicate_results():
    return _context_call("get_duplicate_results")


def duplicate_status_counts():
    return _context_call("duplicate_status_counts")


def alert_count():
    return _context_call("alert_count")


def container_cpu_percent():
    return _context_call("container_cpu_percent")


def container_memory_percent():
    return _context_call("container_memory_percent")


def resource_health_check(*args, **kwargs):
    return _context_call("resource_health_check", *args, **kwargs)


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
    {scan_stage_panel(job, ["Starting", "Inventory", "Identify", "Move/Rename", "Verify", "Complete"])}
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
      <p>Automatic duplicate scans run daily at {int(settings.get('duplicate_scan_hour', DUPLICATE_SCAN_HOUR)):02d}:00 server time. Results stay here until resolved or the next scan refreshes open results.</p>
    </section>
    {library_visibility_panel(settings)}
    {duplicate_health(job, counts)}
    {scan_stage_panel(job, ["Starting", "Inventory", "Fingerprint", "Group Matches", "Save Results", "Complete"])}
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
    {scan_stage_panel(job, ["Starting", "Inventory", "Update Definitions", "ClamAV Scan", "Quarantine", "Complete"])}
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
        <dt>Updated</dt><dd>{html.escape(inventory.get('cached_at_label') or 'Not scanned yet')}</dd>
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
    settings = get_settings()
    hour = settings.get("duplicate_scan_hour", str(DUPLICATE_SCAN_HOUR))
    return f"""
    <section class="stats mini-stats">
      {stat_card("Status", status, job.get("stage") or "Idle")}
      {stat_card("Last Scan", last_success, f"Daily at {hour}:00")}
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
        <span>{html.escape(job.get('current_folder') or 'No active folder')}<br>{html.escape(job.get('message') or '')}</span>
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
    elapsed = job_elapsed_seconds(job)
    processed = int(job.get("processed") or 0)
    rate = f"{processed / elapsed:.2f} files/sec" if elapsed and processed else "Waiting"
    workers = int(job.get("workers") or 0)
    return f"""
    <section class="panel">
      <div class="panel-title">
        <h2>{html.escape(title)}</h2>
        <span class="badge {'moving' if job.get('running') else 'completed'}">{'Running' if job.get('running') else 'Idle'}</span>
      </div>
      <div class="progress"><span style="width:{progress}%"></span></div>
      <p>{html.escape(job.get('message') or '')}</p>
      <p class="refresh-note">Processed {processed} of {int(job.get('total') or 0)}. Workers: {workers or 'n/a'}. Rate: {html.escape(rate)}. Elapsed: {format_elapsed(elapsed)}. Last update: {html.escape(job.get('updated_at') or 'Never')}.</p>
    </section>
    """


def job_elapsed_seconds(job):
    started = job.get("started_at")
    if not started:
        return 0
    try:
        start = datetime.strptime(started, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0
    return max(0, int((datetime.now(timezone.utc) - start).total_seconds()))


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
        "admin_user": "Admin username",
        "admin_password": "Admin password",
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
        "tmdb_api_key": "TMDB API key",
        "tvmaze_fallback_enabled": "Use TVmaze fallback for TV episode names",
        "tvmaze_backoff_seconds": "TVmaze 429 backoff seconds",
        "transfer_mode": "Transfer mode (copy or move)",
        "max_ready_per_scan": "New-file workers",
        "file_management_workers": "File management workers",
        "duplicate_scan_workers": "Duplicate checker workers",
        "duplicate_scan_hour": "Daily duplicate scan hour",
        "malware_scan_workers": "Malware scan workers",
        "ffprobe_timeout": "ffprobe timeout seconds",
        "transfer_chunk_size": "Transfer chunk bytes",
        "max_queue_display": "Dashboard queue display limit",
        "max_new_file_events_per_scan": "New-file log event limit",
        "max_requeue_per_click": "Manual requeue limit",
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


SETTINGS_SECTIONS = [
    ("Admin Account", ["admin_user", "admin_password"]),
    ("Media Paths", ["watch_folder", "movie_folder", "tv_folder", "review_folder", "quarantine_folder"]),
    ("Processing", [
        "poll_interval", "stable_seconds", "transfer_mode", "movie_extensions",
        "max_ready_per_scan", "file_management_workers", "duplicate_scan_workers",
        "duplicate_scan_hour", "max_queue_display", "max_requeue_per_click",
        "max_new_file_events_per_scan",
    ]),
    ("Metadata And Quality", ["metadata_provider", "metadata_enabled", "metadata_required", "tmdb_api_key", "tvmaze_fallback_enabled", "tvmaze_backoff_seconds", "ffprobe_timeout"]),
    ("Pushover", ["pushover_enabled", "pushover_app_token", "pushover_user_key", "pushover_device"]),
    ("Notification Toggles", [
        "notify_success", "notify_failure", "notify_duplicate", "notify_scan_complete",
        "notify_mount_unavailable", "notify_metadata_down", "notify_malware",
    ]),
    ("Malware Scanner", ["malware_enabled", "malware_update_definitions", "malware_daily_hour", "malware_scan_workers"]),
    ("Advanced Transfer", ["transfer_chunk_size"]),
]


SELECT_OPTIONS = {
    "metadata_provider": ["tmdb"],
    "transfer_mode": ["move", "copy"],
}


YES_NO_SETTINGS = {
    "metadata_enabled", "metadata_required", "tvmaze_fallback_enabled", "pushover_enabled", "notify_success",
    "notify_failure", "notify_duplicate", "notify_scan_complete",
    "notify_mount_unavailable", "notify_metadata_down", "notify_malware",
    "malware_enabled", "malware_update_definitions",
}


NUMBER_SETTINGS = {
    "poll_interval", "stable_seconds", "max_ready_per_scan", "file_management_workers",
    "duplicate_scan_workers", "duplicate_scan_hour", "malware_scan_workers", "tvmaze_backoff_seconds",
    "malware_daily_hour", "ffprobe_timeout", "transfer_chunk_size",
    "max_queue_display", "max_new_file_events_per_scan", "max_requeue_per_click",
}


def settings_form(settings):
    rendered_keys = set()
    sections = []
    for title, keys in SETTINGS_SECTIONS:
        fields = []
        for key in keys:
            if key not in DEFAULT_SETTINGS:
                continue
            rendered_keys.add(key)
            fields.append(settings_field(key, settings.get(key, DEFAULT_SETTINGS[key])))
        if fields:
            sections.append(f"""
            <section class="settings-section">
              <h3>{html.escape(title)}</h3>
              <div class="settings-grid">{''.join(fields)}</div>
            </section>
            """)
    remaining = [
        settings_field(key, settings.get(key, DEFAULT_SETTINGS[key]))
        for key in DEFAULT_SETTINGS
        if key not in rendered_keys
    ]
    if remaining:
        sections.append(f"""
        <section class="settings-section">
          <h3>Other</h3>
          <div class="settings-grid">{''.join(remaining)}</div>
        </section>
        """)
    return "\n".join(sections)


def settings_field(key, value):
    label = html.escape(label_for(key))
    escaped_key = html.escape(key)
    escaped_value = html.escape(value)
    if key in YES_NO_SETTINGS:
        options = "".join(
            f"<option value='{option}' {'selected' if str(value).lower() == option else ''}>{option.title()}</option>"
            for option in ["yes", "no"]
        )
        return f"<label>{label}<select name='{escaped_key}'>{options}</select></label>"
    if key in SELECT_OPTIONS:
        options = "".join(
            f"<option value='{html.escape(option)}' {'selected' if value == option else ''}>{html.escape(option)}</option>"
            for option in SELECT_OPTIONS[key]
        )
        return f"<label>{label}<select name='{escaped_key}'>{options}</select></label>"
    input_type = "password" if key in {"admin_password", "tmdb_api_key", "pushover_app_token", "pushover_user_key"} else "text"
    if key in NUMBER_SETTINGS:
        input_type = "number"
    autocomplete = "off" if input_type == "password" else ""
    return (
        f"<label>{label}"
        f"<input name='{escaped_key}' type='{input_type}' value='{escaped_value}' autocomplete='{autocomplete}'>"
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
