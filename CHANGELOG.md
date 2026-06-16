# Changelog

## 1.7.0

- Added `pyproject.toml` as the source of truth for app versioning.
- Added a UI version badge and Docker image version label.
- Added SQLite-backed local user accounts with admin and view-only roles.
- Added CSRF protection for authenticated write actions.
- Added SSO health checks and role mapping.
- Sanitized Docker Compose files to use `.env` values for secrets and host paths.
- Reworked README for Docker, Unraid, safe upgrades, and versioned installs.
