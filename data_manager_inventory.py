import os
from pathlib import Path


def empty_inventory(root):
    root = Path(root)
    return {
        "path": str(root),
        "exists": root.exists(),
        "readable": os.access(root, os.R_OK | os.X_OK) if root.exists() else False,
        "total_files": 0,
        "supported_files": 0,
        "supported_bytes": 0,
        "folders": 0,
        "ignored_exts": {},
        "samples": [],
        "limited": False,
        "scanned_entries": 0,
        "cached_at_label": "Not scanned yet",
        "cache_only": True,
    }


def scan_media_files(root, extensions):
    root = Path(root)
    files = []
    inventory = empty_inventory(root)
    inventory["cache_only"] = False
    if not inventory["exists"] or not root.is_dir() or not inventory["readable"]:
        return files, inventory

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    inventory["scanned_entries"] += 1
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            inventory["folders"] += 1
                            stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue

                    path = Path(entry.path)
                    inventory["total_files"] += 1
                    suffix = path.suffix.lower() or "(none)"
                    if suffix in extensions:
                        files.append(path)
                        inventory["supported_files"] += 1
                        try:
                            inventory["supported_bytes"] += path.stat().st_size
                        except OSError:
                            pass
                        if len(inventory["samples"]) < 5:
                            inventory["samples"].append(str(path))
                    else:
                        inventory["ignored_exts"][suffix] = inventory["ignored_exts"].get(suffix, 0) + 1
        except OSError:
            continue
    return files, inventory
