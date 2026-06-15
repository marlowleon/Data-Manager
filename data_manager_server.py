import base64
import hashlib
import hmac
import html
import json
import secrets
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from data_manager_assets import CSS, DASHBOARD_JS, DUPLICATES_JS, FILE_MANAGEMENT_JS, GLOBAL_JS, MALWARE_JS
from data_manager_config import ADMIN_PASSWORD, ADMIN_USER, APP_NAME, DEFAULT_SETTINGS, SESSION_SECRET
from data_manager_jobs import start_background_job
from data_manager_store import add_event, clear_events, export_events, get_events, get_settings, save_settings
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
)

_server_context = {}


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


class _ScanEventProxy:
    def set(self):
        return _context_call("scan_now")


scan_event = _ScanEventProxy()


def requeue_watch_files():
    return _context_call("requeue_watch_files")


def test_pushover():
    return _context_call("test_pushover")


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
        "sso_client_secret",
        "sso_authorize_url",
        "sso_token_url",
        "sso_userinfo_url",
    ]
    return setting_enabled(settings, "sso_enabled") and all(settings.get(key, "").strip() for key in required)


def sso_redirect_uri(settings, handler):
    configured = settings.get("sso_redirect_uri", "").strip()
    if configured:
        return configured
    proto = handler.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip() or "http"
    host = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host", "")
    return f"{proto}://{host}/sso/callback"


def fetch_sso_userinfo(settings, code, redirect_uri):
    token_payload = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings["sso_client_id"].strip(),
        "client_secret": settings["sso_client_secret"].strip(),
    }).encode("utf-8")
    token_request = urllib.request.Request(
        settings["sso_token_url"].strip(),
        data=token_payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(token_request, timeout=20) as response:
        token_data = json.loads(response.read().decode("utf-8"))
    access_token = token_data.get("access_token")
    if not access_token:
        raise ValueError("Provider did not return an access token")
    userinfo_request = urllib.request.Request(
        settings["sso_userinfo_url"].strip(),
        headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
    )
    with urllib.request.urlopen(userinfo_request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


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


def csv_setting(value):
    return {item.strip().lower() for item in str(value).split(",") if item.strip()}


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
            settings = get_settings()
            admin_user = settings.get("admin_user") or ADMIN_USER
            admin_password = settings.get("admin_password") or ADMIN_PASSWORD
            if form.get("username") == admin_user and form.get("password") == admin_password:
                self.redirect("/", cookie=sign(admin_user))
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
        settings = get_settings()
        admin_user = settings.get("admin_user") or ADMIN_USER
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            key, _, value = item.strip().partition("=")
            if key != "dm_session":
                continue
            session_user = verify_signed(value)
            if session_user == admin_user:
                return True
            if session_user and session_user.startswith("sso:") and setting_enabled(settings, "sso_enabled"):
                return True
        return False

    def cookie_value(self, name):
        cookies = self.headers.get("Cookie", "")
        for item in cookies.split(";"):
            key, _, value = item.strip().partition("=")
            if key == name:
                return value
        return ""

    def redirect(self, location, cookie=None, clear_cookie=False):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", f"dm_session={cookie}; HttpOnly; SameSite=Lax; Path=/")
        if clear_cookie:
            self.send_header("Set-Cookie", "dm_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
            self.send_header("Set-Cookie", "dm_sso_state=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
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
        settings = get_settings()
        sso_button = ""
        if sso_ready(settings):
            provider = html.escape(settings.get("sso_provider_name") or "SSO")
            sso_button = f"""
            <div class="sso-login">
              <a class="button-link" href="/sso/login">Continue with {provider}</a>
            </div>
            """
        self.page("Login", f"""
        <section class="login">
          <h2>Admin Login</h2>
          {message}
          {sso_button}
          <form method="post" action="/login">
            <label>Username <input name="username" autocomplete="username" required></label>
            <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
            <button type="submit">Log in</button>
          </form>
        </section>
        """)

    def start_sso_login(self):
        settings = get_settings()
        if not sso_ready(settings):
            self.render_login("SSO is not fully configured yet")
            return
        state = secrets.token_urlsafe(24)
        params = {
            "response_type": "code",
            "client_id": settings["sso_client_id"].strip(),
            "redirect_uri": sso_redirect_uri(settings, self),
            "scope": settings.get("sso_scope", "openid email profile").strip() or "openid email profile",
            "state": state,
        }
        authorize_url = settings["sso_authorize_url"].strip()
        separator = "&" if "?" in authorize_url else "?"
        location = authorize_url + separator + urllib.parse.urlencode(params)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", f"dm_sso_state={sign(state)}; HttpOnly; SameSite=Lax; Path=/")
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
        if not code or not state or verify_signed(self.cookie_value("dm_sso_state")) != state:
            self.render_login("SSO failed: invalid login state")
            return
        try:
            userinfo = fetch_sso_userinfo(settings, code, sso_redirect_uri(settings, self))
            identity = sso_identity(settings, userinfo)
            if not identity:
                raise ValueError("Provider did not return an email, username, or subject")
            if not sso_identity_allowed(settings, identity):
                raise ValueError(f"{identity} is not allowed to access Data Manager")
        except Exception as exc:
            add_event("system", "error", "sso", message=f"SSO login failed: {exc}")
            self.render_login(f"SSO failed: {exc}")
            return
        add_event("system", "done", "sso", message=f"SSO login successful for {identity}")
        self.redirect("/", cookie=sign(f"sso:{identity}"))

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
        self.page("Settings", f"""
        <section class="panel">
          <div class="panel-title"><h2>Settings</h2><span class="badge completed">Database backed</span></div>
          <form method="post" action="/settings" class="settings">
            {settings_form(settings)}
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
