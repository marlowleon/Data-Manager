import threading

from data_manager_utils import now_iso


job_lock = threading.Lock()
jobs = {
    "file_management": {
        "running": False,
        "kind": "Idle",
        "progress": 0,
        "processed": 0,
        "total": 0,
        "started_at": "",
        "updated_at": "",
        "stage": "Idle",
        "current_folder": "",
        "current_file": "",
        "last_success_at": "",
        "last_error": "",
        "changed": 0,
        "failed": 0,
        "workers": 0,
        "activity": [],
        "message": "No manual scan running",
    },
    "duplicate_checker": {
        "running": False,
        "kind": "Idle",
        "progress": 0,
        "processed": 0,
        "total": 0,
        "started_at": "",
        "updated_at": "",
        "stage": "Idle",
        "current_folder": "",
        "current_file": "",
        "last_success_at": "",
        "last_error": "",
        "open_count": 0,
        "resolved_count": 0,
        "workers": 0,
        "activity": [],
        "message": "No duplicate scan running",
    },
    "malware_scanner": {
        "running": False,
        "kind": "Idle",
        "progress": 0,
        "processed": 0,
        "total": 0,
        "started_at": "",
        "updated_at": "",
        "stage": "Idle",
        "current_folder": "",
        "current_file": "",
        "last_success_at": "",
        "last_error": "",
        "changed": 0,
        "failed": 0,
        "infected": 0,
        "quarantined": 0,
        "workers": 0,
        "activity": [],
        "message": "No malware scan running",
    },
}


def get_job(name):
    with job_lock:
        job = dict(jobs[name])
        job["activity"] = list(jobs[name].get("activity", []))
        return job


def update_job(name, **values):
    activity = values.pop("activity", None)
    with job_lock:
        jobs[name].update(values)
        if activity:
            items = jobs[name].setdefault("activity", [])
            items.insert(0, {"time": now_iso(), "text": str(activity)})
            del items[100:]
        jobs[name]["updated_at"] = now_iso()


def start_background_job(name, kind, target):
    with job_lock:
        if jobs[name]["running"]:
            return False
        jobs[name].update({
            "running": True,
            "kind": kind,
            "progress": 0,
            "processed": 0,
            "total": 0,
            "started_at": now_iso(),
            "updated_at": now_iso(),
            "stage": "Starting",
            "current_folder": "",
            "current_file": "",
            "last_error": "",
            "changed": 0,
            "failed": 0,
            "infected": 0,
            "quarantined": 0,
            "workers": 0,
            "open_count": 0,
            "resolved_count": 0,
            "activity": [{"time": now_iso(), "text": f"{kind} started"}],
            "message": f"{kind} starting",
        })
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return True
