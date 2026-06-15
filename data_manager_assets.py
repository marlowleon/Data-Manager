# Generated from app.py UI assets. Keep behavior-only JavaScript and CSS here.

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
:root { color-scheme: dark; --bg:#000000; --panel:#0c0c0c; --line:#6f6f6f; --text:#ffffff; --muted:#c8c8c8; --accent:#3794ff; --ok:#00ff00; --warn:#ffff00; --danger:#ff0000; }
* { box-sizing: border-box; }
body { margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }
header { display:flex; align-items:center; justify-content:space-between; gap:24px; padding:18px 28px; border-bottom:1px solid var(--line); background:#000; position:sticky; top:0; z-index:1; }
h1 { margin:0; font-size:22px; }
h2 { margin:0 0 12px; font-size:16px; }
nav { display:flex; gap:8px; flex-wrap:wrap; }
a, button { color:#000; background:var(--accent); border:1px solid #9cdcfe; border-radius:4px; padding:8px 11px; text-decoration:none; font-weight:700; cursor:pointer; font-size:13px; }
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
.system-metric { border:1px solid var(--line); border-radius:4px; padding:9px; background:#000; min-width:0; }
.system-metric strong, .system-metric span { display:block; overflow-wrap:anywhere; }
.system-metric strong { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
.system-metric span { font-size:13px; font-weight:800; margin-top:3px; }
.system-metric.ok { border-color:var(--ok); color:var(--ok); }
.system-metric.warn { border-color:var(--warn); color:var(--warn); }
.system-metric.fail { border-color:var(--danger); color:var(--danger); }
.metric-bar { height:7px; width:100%; border:1px solid var(--line); background:#111; margin-top:7px; }
.metric-bar b { display:block; height:100%; background:var(--ok); }
.system-metric.warn .metric-bar b { background:var(--warn); }
.system-metric.fail .metric-bar b { background:var(--danger); }
.stats { display:grid; grid-template-columns:repeat(4,minmax(120px,1fr)); gap:10px; margin-bottom:12px; }
.mini-stats { grid-template-columns:repeat(4,minmax(150px,1fr)); }
.stats article, .panel, .login { background:var(--panel); border:1px solid var(--line); border-radius:4px; padding:12px; }
.stats span { display:block; font-size:26px; font-weight:800; line-height:1; margin-bottom:4px; }
.stats strong, .stats small { display:block; }
.stats small, .empty, td, label, p, .logs { color:var(--muted); }
.refresh-note { margin:-4px 0 12px; font-size:12px; color:var(--muted); }
.columns { display:grid; grid-template-columns:1fr 1fr; gap:12px; align-items:start; }
.panel-title { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:10px; }
.panel-title h2 { margin:0; }
.panel-actions { display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }
.health-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:8px; }
.health-item { border:1px solid var(--line); border-radius:4px; padding:9px; background:#000; min-width:0; }
.health-item div { display:flex; align-items:center; gap:7px; margin-bottom:6px; }
.health-item strong { font-size:13px; }
.health-item p { margin:0; font-size:12px; overflow-wrap:anywhere; }
.health-item dl { display:grid; grid-template-columns:80px minmax(0,1fr); gap:4px 8px; margin:8px 0; font-size:12px; }
.health-item dt { color:var(--muted); }
.health-item dd { margin:0; overflow-wrap:anywhere; }
.health-item.ok { border-color:var(--ok); }
.health-item.warn { border-color:var(--warn); }
.health-item.fail { border-color:var(--danger); }
.health-item.ok strong, .health-item.ok .badge { color:var(--ok); border-color:var(--ok); }
.health-item.warn strong, .health-item.warn .badge { color:var(--warn); border-color:var(--warn); }
.health-item.fail strong, .health-item.fail .badge { color:var(--danger); border-color:var(--danger); }
.pipeline-focus { display:grid; grid-template-columns:minmax(160px,auto) minmax(260px,1fr); align-items:center; gap:10px; border:1px solid var(--line); border-radius:8px; padding:10px; margin-bottom:10px; background:#141b20; }
.pipeline-focus strong { overflow-wrap:anywhere; }
.pipeline-focus span:last-child { color:var(--muted); overflow-wrap:anywhere; }
.pipeline-focus.malware_check, .pipeline-focus.checking, .pipeline-focus.renaming, .pipeline-focus.folder_check, .pipeline-focus.duplicate_check, .pipeline-focus.moving, .pipeline-focus.cleanup { border-color:#7cb7ff; box-shadow:0 0 0 1px rgba(124,183,255,.15) inset; }
.pipeline-focus.queued { border-color:rgba(245,197,66,.7); }
.pipeline-focus.completed { border-color:var(--ok); }
.pipeline-focus.quarantined { border-color:var(--danger); }
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
.badge.completed { border-color:var(--ok); color:var(--ok); }
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
.activity-item { border:1px solid var(--line); border-radius:4px; padding:10px; min-width:0; background:#000; }
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
input { width:100%; color:var(--text); background:#000; border:1px solid var(--line); border-radius:4px; padding:11px 12px; }
select { width:100%; color:var(--text); background:#000; border:1px solid var(--line); border-radius:4px; padding:11px 12px; }
.settings { gap:12px; }
.settings-section { border:1px solid var(--line); border-radius:4px; padding:12px; background:#000; }
.settings-section h3 { margin:0 0 10px; font-size:14px; }
.settings-grid { display:grid; grid-template-columns:repeat(3,minmax(180px,1fr)); gap:12px; }
.schedule-grid { display:grid; grid-template-columns:repeat(2,minmax(260px,1fr)); gap:12px; }
.schedule-card { display:grid; grid-template-columns:1.2fr repeat(4,minmax(110px,.7fr)); gap:10px; align-items:start; border:1px solid var(--line); border-radius:4px; padding:12px; background:#050505; }
.schedule-card strong, .schedule-card small { display:block; }
.schedule-card strong { margin-bottom:4px; }
.schedule-card small { color:var(--muted); font-size:12px; }
code { background:#0f1418; border:1px solid var(--line); border-radius:5px; padding:2px 5px; color:var(--text); }
.error { color:var(--danger); }
.logs { padding-left:18px; margin:0; }
.logs li { margin-bottom:6px; }
@media (max-width: 1200px) { .health-grid { grid-template-columns:repeat(2,minmax(150px,1fr)); } }
@media (max-width: 900px) { header { align-items:flex-start; flex-direction:column; padding:14px 16px; } main { padding:12px; } .stats, .columns, .timeline, .health-grid, .pipeline-focus, .duplicate-files, .system-strip, .settings-grid, .schedule-grid, .schedule-card { grid-template-columns:1fr; } .actions h2 { width:100%; } }
"""
