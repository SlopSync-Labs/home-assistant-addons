# Changelog

All notable changes to the NPM Export Import add-on will be documented here.

## [0.1.3] - 2026-03-15

### Added

- Interactive 2FA popup — when a 2FA-protected NPM account is detected, a modal
  automatically appears asking for the authenticator code; after verification the
  pending operation auto-retries without any further user action
- `npm_token` config option — supply a pre-generated Bearer token to bypass
  interactive auth entirely; required for scheduled exports on 2FA-protected accounts
  since scheduled runs are unattended and cannot prompt for an OTP
- Server-side JWT session cache — a successful login (interactive or password-based)
  is cached for the token's lifetime (~24h) so repeated operations do not re-authenticate
- `POST /api/auth/verify2fa` Flask endpoint — receives the challenge token and OTP
  code, completes the NPM 2FA flow, and caches the resulting JWT

---

## [0.1.2] - 2026-03-15

### Fixed

- Added `bash` to the Dockerfile via `apk add --no-cache bash` — `python:3.11-alpine`
  ships with `ash` only; HA Supervisor invokes `run.sh` with bash, causing a startup crash
- Set `SHELL ["/bin/bash", "-c"]` so subsequent `RUN` steps use bash

---

## [0.1.1] - 2026-03-15

### Added
- Flask web server with HA ingress UI — export and import are now triggered
  via buttons in the add-on panel rather than config-driven one-shot runs
- **Export Now** button writes a timestamped JSON backup to
  `/share/npm-export-import/`
- **Import** button per backup file — restores entries into NPM in
  dependency order (certs → access lists → proxy hosts → redirections → streams)
- Live log panel in the UI, polling every 2 seconds
- `schedule_enabled` / `schedule_interval_hours` config options for
  automatic background exports while the web UI stays available
- SSL certificate export: Let's Encrypt cert files (fullchain + private key)
  read directly from the shared `/ssl/nginxproxymanager/live/npm-{id}/` volume
  and stored base64-encoded in the export bundle
- SSL certificate import: certs re-uploaded to target NPM instance via the
  certificate upload API; old-to-new ID remapping applied to all referencing hosts
- Access list import with old-to-new ID remapping for proxy host references
- Mutex-guarded background thread runner — only one operation runs at a time
- `ingress: true` and `ingress_port: 8099` in `config.json`
- `map: ["share:rw", "ssl:rw"]` for export file storage and cert file access

---

## [0.1.0] - 2026-03-15

### Added
- Initial scaffold for the NPM Export Import add-on
