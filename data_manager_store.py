import csv
import io
import sqlite3
import threading

from data_manager_config import DB_PATH, DEFAULT_SETTINGS
from data_manager_utils import now_iso


db_lock = threading.Lock()


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
            create table if not exists job_stats (
                job_name text primary key,
                updated_at text not null,
                last_started_at text,
                last_completed_at text,
                last_success_at text,
                last_status text,
                message text,
                total integer not null default 0,
                processed integer not null default 0,
                changed integer not null default 0,
                failed integer not null default 0,
                open_count integer not null default 0,
                resolved_count integer not null default 0,
                infected integer not null default 0,
                quarantined integer not null default 0
            );
            create table if not exists local_users (
                username text primary key,
                password_hash text not null,
                role text not null default 'viewer',
                enabled integer not null default 1,
                created_at text not null,
                updated_at text not null
            );
            """
        )
        ensure_duplicate_schema(conn)
        migrate_seen_files(conn)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "insert or ignore into settings (key, value) values (?, ?)",
                (key, value),
            )
        conn.execute(
            "insert or ignore into settings (key, value) values ('sso_client_id_in_body', 'yes')"
        )
        conn.execute(
            "update settings set value = 'move' where key = 'transfer_mode' and value = 'copy'"
        )
        ensure_default_local_users(conn)
        conn.commit()


def ensure_duplicate_schema(conn):
    columns = {row["name"] for row in conn.execute("pragma table_info(duplicate_results)").fetchall()}
    required = {"title", "item_key", "file_a", "file_b", "size_a", "size_b", "quality_a", "quality_b", "recommendation"}
    if required.issubset(columns):
        return
    conn.execute("drop table if exists duplicate_results")
    conn.execute(
        """
        create table duplicate_results (
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
        )
        """
    )


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


def ensure_default_local_users(conn):
    existing = conn.execute("select count(*) as total from local_users").fetchone()["total"]
    if existing:
        return
    settings = {
        row["key"]: row["value"]
        for row in conn.execute("select key, value from settings").fetchall()
    }
    admin_user = settings.get("admin_user") or DEFAULT_SETTINGS["admin_user"]
    admin_password = settings.get("admin_password") or DEFAULT_SETTINGS["admin_password"]
    if admin_user and admin_password:
        upsert_local_user_conn(conn, admin_user, admin_password, "admin", True)
    viewer_enabled = str(settings.get("viewer_enabled", "no")).lower() in {"yes", "true", "1", "on"}
    viewer_user = settings.get("viewer_user") or DEFAULT_SETTINGS.get("viewer_user", "viewer")
    viewer_password = settings.get("viewer_password") or ""
    if viewer_enabled and viewer_user and viewer_password:
        upsert_local_user_conn(conn, viewer_user, viewer_password, "viewer", True)


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


def get_local_users():
    with db_lock, db() as conn:
        return conn.execute(
            "select username, role, enabled, created_at, updated_at from local_users order by role, username"
        ).fetchall()


def get_local_user(username):
    with db_lock, db() as conn:
        row = conn.execute(
            "select username, password_hash, role, enabled, created_at, updated_at from local_users where lower(username) = lower(?)",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def upsert_local_user(username, password_hash, role, enabled=True):
    with db_lock, db() as conn:
        upsert_local_user_conn(conn, username, password_hash, role, enabled)
        conn.commit()


def upsert_local_user_conn(conn, username, password_hash, role, enabled=True):
    timestamp = now_iso()
    conn.execute(
        """
        insert into local_users (username, password_hash, role, enabled, created_at, updated_at)
        values (?, ?, ?, ?, ?, ?)
        on conflict(username) do update set
            password_hash = case when excluded.password_hash = '' then local_users.password_hash else excluded.password_hash end,
            role = excluded.role,
            enabled = excluded.enabled,
            updated_at = excluded.updated_at
        """,
        (username.strip(), password_hash, role, 1 if enabled else 0, timestamp, timestamp),
    )


def delete_local_user(username):
    with db_lock, db() as conn:
        conn.execute("delete from local_users where lower(username) = lower(?)", (username,))
        conn.commit()


def active_admin_count(exclude_username=""):
    with db_lock, db() as conn:
        row = conn.execute(
            """
            select count(*) as total
            from local_users
            where role = 'admin'
              and enabled = 1
              and lower(username) != lower(?)
            """,
            (exclude_username,),
        ).fetchone()
    return row["total"]


def save_job_stat(job_name, job):
    with db_lock, db() as conn:
        conn.execute(
            """
            insert into job_stats
            (job_name, updated_at, last_started_at, last_completed_at, last_success_at, last_status, message,
             total, processed, changed, failed, open_count, resolved_count, infected, quarantined)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(job_name) do update set
                updated_at = excluded.updated_at,
                last_started_at = excluded.last_started_at,
                last_completed_at = excluded.last_completed_at,
                last_success_at = excluded.last_success_at,
                last_status = excluded.last_status,
                message = excluded.message,
                total = excluded.total,
                processed = excluded.processed,
                changed = excluded.changed,
                failed = excluded.failed,
                open_count = excluded.open_count,
                resolved_count = excluded.resolved_count,
                infected = excluded.infected,
                quarantined = excluded.quarantined
            """,
            (
                job_name,
                now_iso(),
                job.get("started_at") or "",
                job.get("updated_at") or now_iso(),
                job.get("last_success_at") or "",
                "running" if job.get("running") else (job.get("stage") or "Complete"),
                job.get("message") or "",
                int(job.get("total") or 0),
                int(job.get("processed") or 0),
                int(job.get("changed") or 0),
                int(job.get("failed") or 0),
                int(job.get("open_count") or 0),
                int(job.get("resolved_count") or 0),
                int(job.get("infected") or 0),
                int(job.get("quarantined") or 0),
            ),
        )
        conn.commit()


def get_job_stat(job_name):
    with db_lock, db() as conn:
        row = conn.execute("select * from job_stats where job_name = ?", (job_name,)).fetchone()
    return dict(row) if row else {}


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
