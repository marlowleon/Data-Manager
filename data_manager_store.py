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
            "update settings set value = 'move' where key = 'transfer_mode' and value = 'copy'"
        )
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
