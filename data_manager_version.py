from pathlib import Path
import tomllib


FALLBACK_VERSION = "1.7.0"


def app_version():
    pyproject_path = Path(__file__).resolve().with_name("pyproject.toml")
    try:
        with open(pyproject_path, "rb") as handle:
            data = tomllib.load(handle)
        return str(data.get("project", {}).get("version") or FALLBACK_VERSION)
    except Exception:
        return FALLBACK_VERSION


APP_VERSION = app_version()
