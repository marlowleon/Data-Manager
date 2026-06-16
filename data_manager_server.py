import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from data_manager_assets import CSS, DASHBOARD_JS, DUPLICATES_JS, FILE_MANAGEMENT_JS, GLOBAL_JS, MALWARE_JS
from data_manager_config import ADMIN_PASSWORD, ADMIN_USER, APP_NAME, APP_VERSION, DEFAULT_SETTINGS, SESSION_SECRET
from data_manager_jobs import start_background_job
from data_manager_store import (
    active_admin_count,
    add_event,
    clear_events,
    delete_local_user,
    export_events,
    get_events,
    get_local_user,
    get_local_users,
    get_settings,
    save_settings,
    upsert_local_user,
)
from data_manager_utils import now_iso, setting_enabled
from data_manager_views import (
    dashboard_content,
    dashboard_error_panel,
    duplicates_content,
    file_management_content,
    log_actions,
    malware_content,
    organized_log_table,
    settings_form,
    system_status_strip,
    user_accounts_panel,
)

_server_context = {}
sso_health_lock = threading.Lock()
sso_health_cache = {"checked_at": 0, "settings_key": "", "result": None}
VALID_ROLES = {"admin", "viewer"}
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
LOCAL_PASSWORD_SETTINGS = {"admin_password", "viewer_password"}
SECRET_SETTINGS = {
    "admin_password",
    "viewer_password",
    "tmdb_api_key",
    "pushover_app_token",
    "pushover_user_key",
    "sso_client_secret",
}


def configure_server(context):
    _server_context.update(context)


def _context_call(name, *args, **kwargs):
    if name not in _server_context:
        raise RuntimeError(f"Server context missing {name}")
    return _server_context[name](*args, **kwargs)


def sign(value):
    signature = hmac.new(SESSION_SECRET.encode(), value.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(value.encode() + b"." + signature).decode()


def verify_signed(cookie):
    try:
        raw = base64.urlsafe_b64decode(cookie.encode())
        value, signature = raw.rsplit(b".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), value, hashlib.sha256).digest()
        if hmac.compare_digest(signature, expected):
            return value.decode()
    except Exception:
        return None
    return None


def normalize_role(role):
    value = str(role or "").strip().lower().replace("-", "_")
    if value in {"viewer", "view", "view_only", "readonly", "read_only"}:
        return "viewer"
    return "admin"


def hash_password(password):
    salt = secrets.token_urlsafe(18)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 260000)
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{PASSWORD_HASH_PREFIX}${salt}${encoded}"


def verify_password(candidate, stored):
    stored = str(stored or "")
    if stored.startswith(f"{PASSWORD_HASH_PREFIX}$"):
        try:
            _, salt, encoded = stored.split("$", 2)
            digest = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt.encode("utf-8"), 260000)
            expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            return hmac.compare_digest(expected, encoded)
        except Exception:
            return False
    return hmac.compare_digest(candidate, stored)


def prepare_settings_values(form):
    current = get_settings()
    values = dict(form)
    for key in SECRET_SETTINGS:
        submitted = str(values.get(key, "")).strip()
        if not submitted:
            values[key] = current.get(key, DEFAULT_SETTINGS.get(key, ""))
        elif key in LOCAL_PASSWORD_SETTINGS:
            values[key] = hash_password(submitted)
    values["sso_default_role"] = normalize_role(values.get("sso_default_role", "admin"))
    return values


def clean_username(username):
    value = str(username or "").strip()
    if not value:
        raise ValueError("Username is required")
    if len(value) > 80:
        raise ValueError("Username must be 80 characters or fewer")
    if not re.match(r"^[A-Za-z0-9_.@-]+$", value):
        raise ValueError("Username can only contain letters, numbers, dot, underscore, dash, and @")
    return value


def save_local_account(form):
    username = clean_username(form.get("username", ""))
    role = normalize_role(form.get("role", "viewer"))
    enabled = setting_enabled({"enabled": form.get("enabled", "yes")}, "enabled")
    password = str(form.get("password", "")).strip()
    existing = get_local_user(username)
    if not existing and not password:
        raise ValueError("Password is required for a new account")
    if existing and existing["role"] == "admin" and (role != "admin" or not enabled) and active_admin_count(username) < 1:
        raise ValueError("Cannot remove or disable the last active admin account")
    password_hash = hash_password(password) if password else ""
    upsert_local_user(username, password_hash, role, enabled)
    add_event("system", "done", "user-management", message=f"Saved local account {username} as {role}")


def remove_local_account(form):
    username = clean_username(form.get("username", ""))
    existing = get_local_user(username)
    if not existing:
        raise ValueError("Account not found")
    if existing["role"] == "admin" and int(existing["enabled"]) and active_admin_count(username) < 1:
        raise ValueError("Cannot delete the last active admin account")
    delete_local_user(username)
    add_event("system", "done", "user-management", message=f"Deleted local account {username}")


def make_session(identity, role, auth_type):
    payload = {
        "v": 1,
        "user": str(identity),
        "role": normalize_role(role),
        "auth": str(auth_type),
        "csrf": secrets.token_urlsafe(32),
    }
    return sign(json.dumps(payload, separators=(",", ":")))


def legacy_csrf_token(value):
    return hmac.new(SESSION_SECRET.encode(), f"csrf:{value}".encode(), hashlib.sha256).hexdigest()


def inject_csrf_tokens(content, token):
    if not token:
        return content
    escaped_token = html.escape(token, quote=True)

    def add_token(match):
        return f'{match.group(1)}<input type="hidden" name="csrf_token" value="{escaped_token}">'

    return re.sub(r'(<form\b(?=[^>]*\bmethod=["\']post["\'])[^>]*>)', add_token, content, flags=re.IGNORECASE)


class _ScanEventProxy:
    def set(self):
        return _context_call("scan_now")


scan_event = _ScanEventProxy()


def requeue_watch_files():
    return _context_call("requeue_watch_files")


def test_pushover():
    return _context_call("test_pushover")


def test_sso_client_credentials():
    settings = get_settings()
    try:
        token_data = fetch_sso_client_credentials(settings)
    except Exception as exc:
        if sso_credentials_were_accepted(exc):
            message = (
                "SSO credentials were accepted by the token endpoint. "
                f"Provider rejected the diagnostic grant, which is okay for browser SSO: {exc}"
            )
            add_event(
                "system",
                "done",
                "sso-test",
                message=message,
            )
            cache_sso_health_result(settings, {"name": "SSO", "status": "ok", "detail": "Client credentials accepted by token endpoint"})
            return True
        message = f"SSO credential test failed: {exc}"
        add_event("system", "error", "sso-test", message=message)
        cache_sso_health_result(settings, {"name": "SSO", "status": "fail", "detail": message[:220]})
        return False
    token_type = token_data.get("token_type", "token")
    add_event("system", "done", "sso-test", message=f"SSO credential test succeeded; provider returned {token_type}")
    cache_sso_health_result(settings, {"name": "SSO", "status": "ok", "detail": "Token endpoint accepted the configured client"})
    return True


def sso_health_settings_key(settings):
    return "|".join([
        settings.get("sso_client_id", "").strip(),
        secret_fingerprint(settings.get("sso_client_secret", "").strip()),
        settings.get("sso_client_auth_method", "client_secret_basic"),
        "body" if setting_enabled(settings, "sso_client_id_in_body") else "no-body",
        "pkce" if setting_enabled(settings, "sso_pkce_enabled") else "no-pkce",
        settings.get("sso_token_url", "").strip(),
        normalize_sso_redirect_uri_value(settings.get("sso_redirect_uri", "")),
    ])


def cache_sso_health_result(settings, result):
    with sso_health_lock:
        sso_health_cache.update({
            "checked_at": time.time(),
            "settings_key": sso_health_settings_key(settings),
            "result": result,
        })


def sso_health_check(settings, force=False):
    if not setting_enabled(settings, "sso_enabled"):
        return {"name": "SSO", "status": "warn", "detail": "Single sign-on is disabled"}
    missing = [
        key for key in ["sso_client_id", "sso_authorize_url", "sso_token_url", "sso_userinfo_url"]
        if not settings.get(key, "").strip()
    ]
    if settings.get("sso_client_auth_method", "client_secret_basic") != "none" and not settings.get("sso_client_secret", "").strip():
        missing.append("sso_client_secret")
    if missing:
        return {"name": "SSO", "status": "fail", "detail": f"Missing settings: {', '.join(missing)}"}

    settings_key = sso_health_settings_key(settings)
    now = time.time()
    with sso_health_lock:
        cached = sso_health_cache["result"]
        fresh = now - sso_health_cache["checked_at"] < 300
        if cached and fresh and sso_health_cache["settings_key"] == settings_key and not force:
            return cached

    try:
        fetch_sso_client_credentials(settings)
        result = {"name": "SSO", "status": "ok", "detail": "Token endpoint accepted the configured client"}
    except Exception as exc:
        if sso_credentials_were_accepted(exc):
            result = {
                "name": "SSO",
                "status": "ok",
                "detail": "Client credentials accepted; diagnostic authorization code was rejected as expected",
            }
        else:
            detail = str(exc)
            if len(detail) > 220:
                detail = detail[:220] + "..."
            result = {"name": "SSO", "status": "fail", "detail": f"SSO validation failed: {detail}"}

    cache_sso_health_result(settings, result)
    return result


def manual_scan_movies_job():
    return _context_call("manual_scan_movies_job")


def manual_scan_tv_job():
    return _context_call("manual_scan_tv_job")


def manual_scan_all_job():
    return _context_call("manual_scan_all_job")


def duplicate_scan_job():
    return _context_call("duplicate_scan_job")


def malware_scan_movies_job():
    return _context_call("malware_scan_movies_job")


def malware_scan_tv_job():
    return _context_call("malware_scan_tv_job")


def malware_scan_all_job():
    return _context_call("malware_scan_all_job")


def delete_duplicate_file(*args, **kwargs):
    return _context_call("delete_duplicate_file", *args, **kwargs)


def alert_count():
    return _context_call("alert_count")


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


def sso_ready(settings):
    required = [
        "sso_client_id",
        "sso_authorize_url",
        "sso_token_url",
        "sso_userinfo_url",
    ]
    if settings.get("sso_client_auth_method", "client_secret_basic") != "none":
        required.append("sso_client_secret")
    return setting_enabled(settings, "sso_enabled") and all(settings.get(key, "").strip() for key in required)


def sso_use_pkce(settings):
    return (
        setting_enabled(settings, "sso_pkce_enabled")
        and settings.get("sso_client_auth_method", "client_secret_basic") == "none"
    )


def sso_redirect_uri(settings, handler):
    configured = settings.get("sso_redirect_uri", "").strip()
    if configured:
        return normalize_sso_redirect_uri_value(configured)
    proto = handler.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip() or "http"
    host = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host", "")
    return f"{proto}://{host}/sso/callback"


def normalize_sso_redirect_uri_value(value):
    value = str(value or "").strip()
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme and parsed.netloc and parsed.path.rstrip("/") in {"", "/"}:
        return urllib.parse.urlunparse(parsed._replace(path="/sso/callback", params="", query="", fragment=""))
    return value


def fetch_sso_userinfo(settings, code, redirect_uri):
    auth_method = settings.get("sso_client_auth_method", "client_secret_basic")
    client_id = settings["sso_client_id"].strip()
    client_secret = settings.get("sso_client_secret", "").strip()
    token_data = fetch_sso_token(
        settings,
        code,
        redirect_uri,
        client_id,
        client_secret,
        auth_method,
        settings.get("_sso_code_verifier", ""),
    )
    access_token = token_data.get("access_token")
    if not access_token:
        raise ValueError("Provider did not return an access token")
    userinfo_request = urllib.request.Request(
        settings["sso_userinfo_url"].strip(),
        headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
    )
    return open_json(userinfo_request, "SSO userinfo request")


def fetch_sso_token(settings, code, redirect_uri, client_id, client_secret, auth_method, code_verifier=""):
    token_values = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if code_verifier:
        token_values["code_verifier"] = code_verifier
    return fetch_sso_token_with_values(settings, token_values, client_id, client_secret, auth_method, f"SSO token exchange using {auth_method}")


def fetch_sso_client_credentials(settings):
    auth_method = settings.get("sso_client_auth_method", "client_secret_basic")
    client_id = settings.get("sso_client_id", "").strip()
    client_secret = settings.get("sso_client_secret", "").strip()
    methods = [auth_method]
    if auth_method == "client_secret_basic":
        methods.extend(["client_secret_post", "none"])
    elif auth_method == "client_secret_post":
        methods.extend(["client_secret_basic", "none"])
    elif auth_method == "none":
        methods.extend(["client_secret_basic", "client_secret_post"])
    methods = list(dict.fromkeys(methods))
    errors = []
    for method in methods:
        try:
            return fetch_sso_token_with_values(
                settings,
                {
                    "grant_type": "authorization_code",
                    "code": "data-manager-diagnostic-invalid-code",
                    "redirect_uri": normalize_sso_redirect_uri_value(settings.get("sso_redirect_uri", "")),
                },
                client_id,
                client_secret,
                method,
                f"SSO authorization-code credential test using {method}",
            )
        except ValueError as exc:
            errors.append(f"{method}: {exc}")
            if "invalid_client" not in str(exc):
                raise
    raise ValueError("all client auth methods failed. " + " | ".join(errors))


def sso_credentials_were_accepted(exc):
    text = str(exc).lower()
    accepted_after_auth_errors = [
        "invalid_grant",
        "unsupported_grant_type",
        "invalid_scope",
        "unauthorized_client",
    ]
    return "invalid_client" not in text and any(error in text for error in accepted_after_auth_errors)


def fetch_sso_token_with_values(settings, token_values, client_id, client_secret, auth_method, label):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if setting_enabled(settings, "sso_client_id_in_body") or auth_method in {"client_secret_post", "none"}:
        token_values["client_id"] = client_id
    if auth_method == "client_secret_basic":
        basic_id = urllib.parse.quote(client_id, safe="")
        basic_secret = urllib.parse.quote(client_secret, safe="")
        token = base64.b64encode(f"{basic_id}:{basic_secret}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    elif auth_method == "client_secret_post":
        token_values["client_secret"] = client_secret
    token_payload = urllib.parse.urlencode(token_values).encode("utf-8")
    token_request = urllib.request.Request(
        settings["sso_token_url"].strip(),
        data=token_payload,
        headers=headers,
        method="POST",
    )
    return open_json(token_request, label)


def open_json(request, label):
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        if len(detail) > 800:
            detail = detail[:800] + "..."
        raise ValueError(f"{label} failed: HTTP {exc.code} {exc.reason}: {detail}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} failed: provider returned invalid JSON") from exc


def sso_diagnostics(settings, handler):
    redirect_uri = sso_redirect_uri(settings, handler)
    client_id = settings.get("sso_client_id", "").strip()
    client_secret = settings.get("sso_client_secret", "").strip()
    latest_test = latest_sso_test_result()
    latest_login = latest_sso_login_result()
    latest_status = latest_test["status"] if latest_test else "not run"
    latest_message = latest_test["message"] if latest_test else "Click Test SSO Credentials to run a token endpoint check."
    latest_time = latest_test["created_at"] if latest_test else "Never"
    latest_login_status = latest_login["status"] if latest_login else "not run"
    latest_login_message = latest_login["message"] if latest_login else "No browser SSO login result recorded yet."
    latest_login_time = latest_login["created_at"] if latest_login else "Never"
    rows = [
        ("Enabled", "yes" if setting_enabled(settings, "sso_enabled") else "no"),
        ("Ready", "yes" if sso_ready(settings) else "no"),
        ("Latest credential test", latest_status),
        ("Latest credential test time", latest_time),
        ("Latest credential test detail", latest_message),
        ("Latest browser login", latest_login_status),
        ("Latest browser login time", latest_login_time),
        ("Latest browser login detail", latest_login_message),
        ("Client auth method", settings.get("sso_client_auth_method", "client_secret_basic")),
        ("Browser login auth retries", "no"),
        ("Token request client_id in body", "yes" if setting_enabled(settings, "sso_client_id_in_body") else "only for client_secret_post/public"),
        ("PKCE setting", "yes" if setting_enabled(settings, "sso_pkce_enabled") else "no"),
        ("PKCE used for login", "yes" if sso_use_pkce(settings) else "no"),
        ("Client ID length", str(len(client_id))),
        ("Client ID preview", preview_secret(client_id)),
        ("Client secret length", str(len(client_secret))),
        ("Client secret fingerprint", secret_fingerprint(client_secret)),
        ("Redirect URI used", redirect_uri),
        ("Authorize URL", settings.get("sso_authorize_url", "")),
        ("Token URL", settings.get("sso_token_url", "")),
        ("Userinfo URL", settings.get("sso_userinfo_url", "")),
    ]
    body = "".join(
        f"<tr><th>{html.escape(label)}</th><td>{html.escape(value)}</td></tr>"
        for label, value in rows
    )
    result_class = "completed" if latest_test and latest_test["status"] == "done" else "failed" if latest_test else "queued"
    result_label = "Pass" if latest_test and latest_test["status"] == "done" else "Fail" if latest_test else "Not Run"
    return f"""
    <section class="panel" id="sso-diagnostics">
      <div class="panel-title"><h2>SSO Diagnostics</h2><span class="badge {result_class}">{result_label}</span></div>
      <p>These are the effective SSO values Data Manager is using. The secret is never displayed, only its length.</p>
      <div class="table-wrap">
        <table><tbody>{body}</tbody></table>
      </div>
    </section>
    """


def latest_sso_test_result():
    for row in get_events(200):
        if row["media_type"] == "system" and row["original_path"] == "sso-test":
            return dict(row)
    return None


def latest_sso_login_result():
    for row in get_events(200):
        if row["media_type"] == "system" and row["original_path"] == "sso":
            return dict(row)
    return None


def sso_failure_context(settings, handler):
    values = {
        "client_id": preview_secret(settings.get("sso_client_id", "").strip()),
        "client_id_length": len(settings.get("sso_client_id", "").strip()),
        "secret_length": len(settings.get("sso_client_secret", "").strip()),
        "secret_fingerprint": secret_fingerprint(settings.get("sso_client_secret", "").strip()),
        "auth_method": settings.get("sso_client_auth_method", "client_secret_basic"),
        "auth_retries": "no",
        "client_id_in_body": "yes" if setting_enabled(settings, "sso_client_id_in_body") else "only_for_post_or_public",
        "pkce_setting": "yes" if setting_enabled(settings, "sso_pkce_enabled") else "no",
        "pkce_used": "yes" if sso_use_pkce(settings) else "no",
        "redirect_uri": sso_redirect_uri(settings, handler),
        "token_url": settings.get("sso_token_url", ""),
    }
    return "; ".join(f"{key}={value}" for key, value in values.items())


def preview_secret(value):
    value = str(value or "")
    if not value:
        return "(empty)"
    if len(value) <= 10:
        return value[0] + "*" * max(0, len(value) - 2) + value[-1]
    return f"{value[:6]}...{value[-4:]}"


def secret_fingerprint(value):
    value = str(value or "")
    if not value:
        return "(empty)"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def sso_identity(settings, userinfo):
    for key in ("email", "preferred_username", "username", "sub"):
        value = str(userinfo.get(key) or "").strip()
        if value:
            return value
    return ""


def sso_identity_allowed(settings, identity):
    identity_lower = identity.lower()
    users = csv_setting(settings.get("sso_allowed_users", ""))
    domains = csv_setting(settings.get("sso_allowed_domains", ""))
    if users and identity_lower in users:
        return True
    if domains and "@" in identity_lower:
        domain = identity_lower.rsplit("@", 1)[1]
        if domain in domains:
            return True
    if users or domains:
        return False
    return True


def sso_role_for_identity(settings, identity):
    identity_lower = str(identity or "").strip().lower()
    if not identity_lower:
        return "viewer"
    admin_users = csv_setting(settings.get("sso_admin_users", ""))
    viewer_users = csv_setting(settings.get("sso_viewer_users", ""))
    if identity_lower in admin_users:
        return "admin"
    if identity_lower in viewer_users:
        return "viewer"
    return normalize_role(settings.get("sso_default_role", "admin"))


def csv_setting(value):
    return {item.strip().lower() for item in str(value).split(",") if item.strip()}


def parse_sso_state(cookie_value):
    signed = verify_signed(cookie_value)
    if not signed:
        return {}
    try:
        data = json.loads(signed)
    except json.JSONDecodeError:
        return {"state": signed}
    if not isinstance(data, dict):
        return {}
    return {
        "state": str(data.get("state", "")),
        "code_verifier": str(data.get("code_verifier", "")),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urllib.parse.urlparse(self.path).path
        if route == "/login":
            self.render_login()
        elif route == "/sso/login":
            self.start_sso_login()
        elif route == "/sso/callback":
            self.finish_sso_login()
        elif route == "/logout":
            self.redirect("/login", clear_cookie=True)
        elif not self.authenticated():
            self.redirect("/login")
        elif route == "/":
            self.render_dashboard()
        elif route == "/api/dashboard":
            self.render_dashboard_api()
        elif route == "/settings":
            if self.is_admin():
                self.render_settings()
            else:
                self.forbidden("Admin access is required for Settings.")
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
            if self.is_admin():
                scan_event.set()
                self.redirect("/")
            else:
                self.forbidden("Admin access is required to start scans.")
        elif route == "/requeue-watch":
            if self.is_admin():
                requeue_watch_files()
                self.redirect("/")
            else:
                self.forbidden("Admin access is required to requeue files.")
        elif route == "/export-logs":
            self.render_log_export()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path
        form = self.form()
        if route == "/login":
            settings = get_settings()
            admin_user = settings.get("admin_user") or ADMIN_USER
            admin_password = settings.get("admin_password") or ADMIN_PASSWORD
            viewer_user = settings.get("viewer_user", "viewer")
            viewer_password = settings.get("viewer_password", "")
            username = form.get("username", "")
            password = form.get("password", "")
            local_user = get_local_user(username)
            if local_user and int(local_user["enabled"]) and verify_password(password, local_user["password_hash"]):
                self.redirect("/", cookie=make_session(local_user["username"], local_user["role"], "local"))
            elif hmac.compare_digest(username, admin_user) and verify_password(password, admin_password):
                self.redirect("/", cookie=make_session(admin_user, "admin", "local"))
            elif (
                setting_enabled(settings, "viewer_enabled")
                and viewer_user
                and viewer_password
                and hmac.compare_digest(username, viewer_user)
                and verify_password(password, viewer_password)
            ):
                self.redirect("/", cookie=make_session(viewer_user, "viewer", "local"))
            else:
                self.render_login("Invalid username or password")
        elif not self.authenticated():
            self.send_error(HTTPStatus.FORBIDDEN)
        elif not self.csrf_valid(form):
            self.forbidden("Security check failed. Refresh the page and try again.")
        elif not self.is_admin():
            self.forbidden("Admin access is required for this action.")
        elif route == "/settings":
            save_settings(prepare_settings_values(form))
            scan_event.set()
            self.redirect("/settings")
        elif route == "/users/save":
            try:
                save_local_account(form)
            except ValueError as exc:
                add_event("system", "error", "user-management", message=str(exc))
            self.redirect("/settings#user-management")
        elif route == "/users/delete":
            try:
                remove_local_account(form)
            except ValueError as exc:
                add_event("system", "error", "user-management", message=str(exc))
            self.redirect("/settings#user-management")
        elif route == "/test-pushover":
            test_pushover()
            self.redirect("/settings")
        elif route == "/test-sso":
            test_sso_client_credentials()
            self.redirect("/settings#sso-diagnostics")
        elif route == "/file-management/run":
            scan_type = form.get("scan_type", "all")
            target = {"movies": manual_scan_movies_job, "tv": manual_scan_tv_job}.get(scan_type, manual_scan_all_job)
            start_background_job("file_management", f"Manual {scan_type} scan", target)
            self.redirect("/file-management")
        elif route == "/duplicates/run":
            start_background_job("duplicate_checker", "Manual Duplicate Scan", duplicate_scan_job)
            self.redirect("/duplicates")
        elif route == "/malware/run":
            scan_type = form.get("scan_type", "all")
            target = {"movies": malware_scan_movies_job, "tv": malware_scan_tv_job}.get(scan_type, malware_scan_all_job)
            start_background_job("malware_scanner", f"Manual {scan_type} malware scan", target)
            self.redirect("/malware")
        elif route == "/duplicates/delete":
            delete_duplicate_file(int(form.get("id", "0") or "0"), form.get("side", "b"))
            self.redirect("/duplicates")
        elif route == "/clear-logs":
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
        return self.current_session() is not None

    def is_admin(self):
        session = self.current_session()
        return bool(session and session["role"] == "admin")

    def current_session(self):
        settings = get_settings()
        admin_user = settings.get("admin_user") or ADMIN_USER
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            key, _, value = item.strip().partition("=")
            if key != "dm_session":
                continue
            session_user = verify_signed(value)
            if not session_user:
                continue
            try:
                payload = json.loads(session_user)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                auth_type = str(payload.get("auth") or "local")
                if auth_type == "sso" and not setting_enabled(settings, "sso_enabled"):
                    return None
                if auth_type == "local":
                    user_row = get_local_user(str(payload.get("user") or ""))
                    if user_row and not int(user_row["enabled"]):
                        return None
                    if user_row:
                        payload["role"] = user_row["role"]
                role = normalize_role(payload.get("role", "viewer"))
                return {
                    "user": str(payload.get("user") or ""),
                    "role": role,
                    "auth": auth_type,
                    "csrf": str(payload.get("csrf") or legacy_csrf_token(session_user)),
                }
            if session_user == admin_user:
                return {"user": session_user, "role": "admin", "auth": "local", "csrf": legacy_csrf_token(session_user)}
            if session_user.startswith("sso:") and setting_enabled(settings, "sso_enabled"):
                identity = session_user[4:]
                return {
                    "user": identity,
                    "role": sso_role_for_identity(settings, identity),
                    "auth": "sso",
                    "csrf": legacy_csrf_token(session_user),
                }
        return None

    def csrf_valid(self, form):
        session = self.current_session()
        if not session:
            return False
        return hmac.compare_digest(form.get("csrf_token", ""), session.get("csrf", ""))

    def cookie_value(self, name):
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            key, _, value = item.strip().partition("=")
            if key == name:
                return value
        return ""

    def redirect(self, location, cookie=None, clear_cookie=False, clear_sso_state=False):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", f"dm_session={cookie}; HttpOnly; SameSite=Lax; Path=/")
        if clear_sso_state:
            self.send_header("Set-Cookie", "dm_sso_state=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
        if clear_cookie:
            self.send_header("Set-Cookie", "dm_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
            self.send_header("Set-Cookie", "dm_sso_state=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def forbidden(self, message="Forbidden"):
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Forbidden - {APP_NAME}</title><style>{CSS}</style></head>
        <body><header><h1>{APP_NAME}<span class="app-version">v{html.escape(APP_VERSION)}</span></h1><nav><a href="/">Dashboard</a><a href="/logout">Logout</a></nav></header>
        <main><section class="panel"><h2>Access denied</h2><p class="error">{html.escape(message)}</p></section></main></body></html>""".encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def page(self, title, content):
        nav = ""
        session = self.current_session()
        if session:
            alerts = alert_count()
            alert_label = f"Alerts <span class='alert-dot'>{alerts}</span>" if alerts else "Alerts"
            admin_links = """
              <a href="/settings">Settings</a>
              <a href="/scan-now">Scan now</a>
            """ if session["role"] == "admin" else ""
            role_label = "Admin" if session["role"] == "admin" else "View-only"
            nav = """
            <nav>
              <a href="/">Dashboard</a>
              <a href="/file-management">File Management</a>
              <a href="/duplicates">Duplicate Checker</a>
              <a href="/malware">Malware Checks</a>
              <a href="/alerts">{alert_label}</a>
              <a href="/logs">Logs</a>
              {admin_links}
              <span class="role-pill">{role_label}</span>
              <a href="/logout">Logout</a>
            </nav>
            """.format(alert_label=alert_label, admin_links=admin_links, role_label=role_label)
            content = self.protect_forms(content)
        body = f"""<!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{html.escape(title)} - {APP_NAME}</title>
          <style>{CSS}</style>
        </head>
        <body>
          <header><h1>{APP_NAME}<span class="app-version">v{html.escape(APP_VERSION)}</span></h1>{nav}</header>
          <main>{system_status_strip() if session else ""}{content}</main>
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

    def protect_forms(self, content):
        session = self.current_session()
        return inject_csrf_tokens(content, session.get("csrf", "")) if session else content

    def render_login(self, error=""):
        message = f"<p class='error'>{html.escape(error)}</p>" if error else ""
        settings = get_settings()
        sso_actions = ""
        form_class = "login-form"
        if sso_ready(settings):
            provider = html.escape(settings.get("sso_provider_name") or "SSO")
            form_class = "login-form local-login-collapsed"
            sso_actions = f"""
            <div class="login-actions">
              <a class="sso-button" href="/sso/login">
                <span>{provider}</span>
                <strong>Continue with SSO</strong>
              </a>
              <button class="local-login-button" type="button" data-local-login-toggle>
                <span>Local</span>
                <strong>Local Login</strong>
              </button>
            </div>
            """
        self.page("Login", f"""
        <section class="login-shell">
          <div class="login-brand">
            <span class="login-kicker">Access Node</span>
            <h2>{APP_NAME}</h2>
            <p>Authentication gateway online. Session handoff encrypted. Operator access required.</p>
            <div class="login-terminal">
              <span>AUTH: READY</span>
              <span>SCAN: ACTIVE</span>
              <span>VAULT: LOCKED</span>
            </div>
          </div>
          <div class="login">
            <div class="login-title">
              <span class="badge completed">Secure</span>
              <h2>Authenticate</h2>
            </div>
            {message}
            {sso_actions}
            <form method="post" action="/login" class="{form_class}">
              <label>Username <input name="username" autocomplete="username" required></label>
              <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
              <button type="submit">Log in</button>
            </form>
          </div>
        </section>
        """)

    def start_sso_login(self):
        settings = get_settings()
        if not sso_ready(settings):
            self.render_login("SSO is not fully configured yet")
            return
        state = secrets.token_urlsafe(24)
        sso_state = {"state": state}
        params = {
            "response_type": "code",
            "client_id": settings["sso_client_id"].strip(),
            "redirect_uri": sso_redirect_uri(settings, self),
            "scope": settings.get("sso_scope", "openid email profile").strip() or "openid email profile",
            "state": state,
        }
        if sso_use_pkce(settings):
            verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("ascii").rstrip("=")
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
            sso_state["code_verifier"] = verifier
        authorize_url = settings["sso_authorize_url"].strip()
        separator = "&" if "?" in authorize_url else "?"
        location = authorize_url + separator + urllib.parse.urlencode(params)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", f"dm_sso_state={sign(json.dumps(sso_state))}; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()

    def finish_sso_login(self):
        settings = get_settings()
        if not sso_ready(settings):
            self.render_login("SSO is not fully configured yet")
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if query.get("error"):
            self.render_login(f"SSO failed: {query.get('error_description', query['error'])[0]}")
            return
        state = (query.get("state") or [""])[0]
        code = (query.get("code") or [""])[0]
        cookie_state = parse_sso_state(self.cookie_value("dm_sso_state"))
        if not code or not state or cookie_state.get("state") != state:
            self.render_login("SSO failed: invalid login state")
            return
        try:
            settings["_sso_code_verifier"] = cookie_state.get("code_verifier", "")
            userinfo = fetch_sso_userinfo(settings, code, sso_redirect_uri(settings, self))
            identity = sso_identity(settings, userinfo)
            if not identity:
                raise ValueError("Provider did not return an email, username, or subject")
            if not sso_identity_allowed(settings, identity):
                raise ValueError(f"{identity} is not allowed to access Data Manager")
            role = sso_role_for_identity(settings, identity)
        except Exception as exc:
            detail = f"{exc}. Context: {sso_failure_context(settings, self)}"
            add_event("system", "error", "sso", message=f"SSO login failed: {detail}")
            self.render_login(f"SSO failed: {detail}")
            return
        add_event("system", "done", "sso", message=f"SSO login successful for {identity} as {role}")
        self.redirect("/", cookie=make_session(identity, role, "sso"), clear_sso_state=True)

    def render_dashboard(self):
        try:
            content = f"""
            <div id="dashboard-root">
              {dashboard_content(can_manage=self.is_admin())}
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
            body = json.dumps({"html": dashboard_content(can_manage=self.is_admin()), "updated_at": now_iso()}).encode("utf-8")
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
        self.page("Settings", f"""
        {user_accounts_panel(get_local_users())}
        <section class="panel">
          <div class="panel-title"><h2>Settings</h2><span class="badge completed">Database backed</span></div>
          <form method="post" action="/settings" class="settings">
            {settings_form(settings)}
            <button type="submit">Save settings</button>
          </form>
        </section>
        {sso_diagnostics(settings, self)}
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
          <div class="panel-title">
            <h2>SSO Test</h2>
            <form method="post" action="/test-sso" class="inline-form">
              <button type="submit">Test SSO Credentials</button>
            </form>
          </div>
          <p>This checks whether Authentik accepts the saved Client ID and Client Secret at the token endpoint.</p>
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
          {file_management_content(can_manage=self.is_admin())}
        </div>
        <script>{FILE_MANAGEMENT_JS}</script>
        """)

    def render_file_management_api(self):
        content = self.protect_forms(file_management_content(can_manage=self.is_admin()))
        body = json.dumps({"html": content, "updated_at": now_iso()}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def render_duplicates(self):
        self.page("Duplicate Checker", f"""
        <div id="duplicates-root">
          {duplicates_content(can_manage=self.is_admin())}
        </div>
        <script>{DUPLICATES_JS}</script>
        """)

    def render_duplicates_api(self):
        content = self.protect_forms(duplicates_content(can_manage=self.is_admin()))
        body = json.dumps({"html": content, "updated_at": now_iso()}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def render_malware(self):
        self.page("Malware Checks", f"""
        <div id="malware-root">
          {malware_content(can_manage=self.is_admin())}
        </div>
        <script>{MALWARE_JS}</script>
        """)

    def render_malware_api(self):
        content = self.protect_forms(malware_content(can_manage=self.is_admin()))
        body = json.dumps({"html": content, "updated_at": now_iso()}).encode("utf-8")
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
          {log_actions() if self.is_admin() else "<p class='refresh-note'>View-only access: log clearing controls are hidden.</p>"}
          {organized_log_table(events)}
        </section>
        """)

    def render_alerts(self):
        rows = [
            row for row in get_events(300)
            if is_critical_alert(row)
        ]
        self.page("Alerts", f"""
        <section class="panel">
          <h2>Alerts</h2>
          {organized_log_table(rows)}
        </section>
        """)

    def log_message(self, fmt, *args):
        return
