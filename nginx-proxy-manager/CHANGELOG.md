# Changelog

All notable changes to the Nginx Proxy Manager add-on will be documented here.

## [0.3.0] - 2026-03-13

### Added
- Let's Encrypt certificates now stored at `/ssl/nginxproxymanager`, making them
  accessible to other HA add-ons that map the `ssl` volume
- `ssl:rw` added to add-on volume map
- Buy Me a Coffee badge linking to SlopSync-Labs

### Changed
- Symlink target for `/etc/letsencrypt` changed from `/data/letsencrypt` to
  `/ssl/nginxproxymanager`

---

## [0.2.0] - 2026-03-13

### Added
- `init: false` in `config.json` — prevents HA Supervisor from injecting a Docker
  init wrapper, allowing s6-overlay to run as PID 1 (fixes startup crash)
- `webui` field in `config.json` — adds "Open Web UI" button in HA pointing to port 81
- `backup_exclude` to omit logs from HA snapshots
- Official NPM icon (`icon.png`, 256×256) with attribution
- shields.io badges: version, project stage, maintained, community forum, Buy Me a Coffee
- Patched NPM's `prepare` s6 service to accept a symlink for `/etc/letsencrypt`
  instead of requiring a Docker volume mount point
- `cont-init.d/01-ha-setup.sh` to create required `/data` subdirectories before
  NPM services start

### Fixed
- `s6-overlay-suexec: fatal: can only run as pid 1` crash on startup
- `cont-init.d` script failing with "not found" due to missing `with-contenv`
  interpreter — changed shebang to `#!/bin/sh`
- `ERROR: /etc/letsencrypt is not mounted` — patched NPM's mountpoint check

---

## [0.1.0] - 2026-03-13

### Added
- Initial scaffold for the Nginx Proxy Manager add-on
- `FROM jc21/nginx-proxy-manager:2.14.0` — uses the official upstream Docker image
  directly rather than building from source
- Ports: 80 (HTTP), 81 (admin UI), 443 (HTTPS)
- Multi-arch support: `amd64`, `aarch64`, `armv7`
