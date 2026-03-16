import base64
import collections
import json
import os
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify
from flask import request as flask_request

OPTIONS_PATH = "/data/options.json"
EXPORT_DIR = "/share/npm-export-import"
LE_CERT_BASE = "/ssl/nginxproxymanager/live"
INGRESS_PORT = 8099

ENTITY_ENDPOINTS = {
    "proxy_hosts": "/api/nginx/proxy-hosts",
    "redirection_hosts": "/api/nginx/redirection-hosts",
    "streams": "/api/nginx/streams",
    "access_lists": "/api/nginx/access-lists",
    "certificates": "/api/nginx/certificates",
}

# Fields assigned by NPM on creation — must be stripped before POSTing
STRIP_FIELDS = {"id", "created_on", "modified_on", "owner_user_id", "owner", "meta"}

_MASKED = "\u2022\u2022\u2022\u2022\u2022"  # sentinel: password field left unchanged by user

# --- shared state ---
_log_lines = collections.deque(maxlen=200)
_op_lock = threading.Lock()
_op_running = False
_pending_2fa = None                          # challenge_token waiting for OTP input
_session = {"token": None, "expires": None}  # cached JWT session


def _log(msg):
    print(msg, flush=True)
    _log_lines.append(msg)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

class TwoFactorRequired(Exception):
    def __init__(self, challenge_token):
        self.challenge_token = challenge_token


def _get_session_token():
    if _session["token"] and _session["expires"]:
        if datetime.now(timezone.utc) < _session["expires"]:
            return _session["token"]
    return None


def _set_session_token(token, expires_str):
    _session["token"] = token
    _session["expires"] = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))


def authenticate(cfg):
    # 1. Pre-configured static token (npm_token) — used for scheduled/headless operation
    static = (cfg.get("npm_token") or "").strip()
    if static:
        return {"Authorization": f"Bearer {static}"}

    # 2. Valid cached session token from a previous interactive login
    cached = _get_session_token()
    if cached:
        return {"Authorization": f"Bearer {cached}"}

    # 3. Username/password — may raise TwoFactorRequired for 2FA-protected accounts
    url = f"{cfg['npm_url'].rstrip('/')}/api/tokens"
    resp = requests.post(
        url,
        json={"identity": cfg["npm_username"], "secret": cfg["npm_password"], "scope": "user"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("requires_2fa"):
        raise TwoFactorRequired(data["challenge_token"])
    _set_session_token(data["token"], data["expires"])
    return {"Authorization": f"Bearer {data['token']}"}


# ---------------------------------------------------------------------------
# Core export / import logic
# ---------------------------------------------------------------------------

def load_options():
    with open(OPTIONS_PATH) as f:
        return json.load(f)


def save_options(updates):
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    resp = requests.post(
        "http://supervisor/addons/self/options",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json={"options": updates},
        timeout=10,
    )
    resp.raise_for_status()
    # The Supervisor API updates HA's config store but does not rewrite
    # /data/options.json until the add-on restarts. Write it ourselves so
    # load_options() returns fresh values immediately.
    with open(OPTIONS_PATH, "w") as f:
        json.dump(updates, f)


def _read_cert_files(cert_id):
    """Read LE cert files from the shared ssl volume. Returns dict or None."""
    cert_dir = os.path.join(LE_CERT_BASE, f"npm-{cert_id}")
    fullchain = os.path.join(cert_dir, "fullchain.pem")
    privkey = os.path.join(cert_dir, "privkey.pem")
    if not (os.path.isfile(fullchain) and os.path.isfile(privkey)):
        return None
    with open(fullchain, "rb") as f:
        fc_b64 = base64.b64encode(f.read()).decode()
    with open(privkey, "rb") as f:
        pk_b64 = base64.b64encode(f.read()).decode()
    return {"fullchain_pem": fc_b64, "privkey_pem": pk_b64}


ENTITY_EXPAND = {
    "access_lists": "items,clients",
}


def fetch_all(base_url, headers):
    base = base_url.rstrip("/")
    data = {}
    for key, path in ENTITY_ENDPOINTS.items():
        params = {"expand": ENTITY_EXPAND[key]} if key in ENTITY_EXPAND else {}
        resp = requests.get(f"{base}{path}", headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        data[key] = resp.json()

    # Augment certificate records with actual cert file contents where accessible
    for cert in data["certificates"]:
        cert_id = cert["id"]
        cert_files = _read_cert_files(cert_id)
        if cert_files:
            cert["cert_files"] = cert_files
        else:
            provider = cert.get("provider", "unknown")
            _log(
                f"[export] WARNING: cert id={cert_id} ({provider}) — cert files not "
                f"found at {LE_CERT_BASE}/npm-{cert_id}/. "
                f"Custom certs stored in /data/custom_ssl/ cannot be exported."
            )

    return data


def export_all(cfg):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    _log(f"[export] Authenticating to {cfg['npm_url']}...")
    headers = authenticate(cfg)
    _log("[export] Fetching configuration...")
    data = fetch_all(cfg["npm_url"], headers)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = os.path.join(EXPORT_DIR, f"npm-export-{timestamp}.json")
    with open(filename, "w") as f:
        json.dump({"exported_at": timestamp, "data": data}, f, indent=2)
    _log(f"[export] Done — wrote {os.path.basename(filename)}")
    return filename


def _strip(obj):
    return {k: v for k, v in obj.items() if k not in STRIP_FIELDS}


def _import_certificates(base, headers, certs):
    """Create custom cert records and upload cert+key files. Returns old->new ID map."""
    cert_id_map = {}
    for cert in certs:
        old_id = cert["id"]
        cert_files = cert.get("cert_files")
        if not cert_files:
            _log(
                f"[import] SKIP cert id={old_id} ({cert.get('provider')}) — "
                f"no cert_files in export (custom cert or missing from backup)"
            )
            continue

        nice_name = cert.get("nice_name") or f"imported-npm-{old_id}"
        create_resp = requests.post(
            f"{base}/api/nginx/certificates",
            headers=headers,
            json={"provider": "other", "nice_name": nice_name},
            timeout=15,
        )
        create_resp.raise_for_status()
        new_id = create_resp.json()["id"]

        fullchain = base64.b64decode(cert_files["fullchain_pem"])
        privkey = base64.b64decode(cert_files["privkey_pem"])
        upload_resp = requests.post(
            f"{base}/api/nginx/certificates/{new_id}/upload",
            headers={"Authorization": headers["Authorization"]},
            files={
                "certificate": ("fullchain.pem", fullchain, "application/x-pem-file"),
                "certificate_key": ("privkey.pem", privkey, "application/x-pem-file"),
            },
            timeout=30,
        )
        upload_resp.raise_for_status()
        cert_id_map[old_id] = new_id
        _log(f"[import] certificate {old_id} -> {new_id} ({nice_name})")

    return cert_id_map


def _import_access_lists(base, headers, access_lists):
    """Create access lists. Returns old->new ID map."""
    # Build a name->id map of access lists that already exist on the target
    existing_resp = requests.get(f"{base}/api/nginx/access-lists", headers=headers, timeout=15)
    if not existing_resp.ok:
        _log(f"[import] WARNING: could not fetch existing access lists ({existing_resp.status_code}) — duplicate check skipped")
        existing_by_name = {}
    else:
        existing_by_name = {al["name"]: al["id"] for al in existing_resp.json()}

    al_id_map = {}
    for al in access_lists:
        old_id = al["id"]
        name = al.get("name", "")

        if name in existing_by_name:
            new_id = existing_by_name[name]
            al_id_map[old_id] = new_id
            _log(f"[import] access_list {old_id} -> {new_id} ({name}) — already exists, skipped")
            continue

        # Only send the fields NPM's create endpoint accepts — GET returns extra
        # relation fields like proxy_hosts that cause a 400 if echoed back.
        payload = {
            "name": name,
            "satisfy_any": al.get("satisfy_any", False),
            "pass_auth": al.get("pass_auth", False),
            "items": [
                {"username": item.get("username", ""), "password": item.get("password", "")}
                for item in al.get("items", [])
            ],
            "clients": [
                {"address": c.get("address", ""), "directive": c.get("directive", "allow")}
                for c in al.get("clients", [])
            ],
        }
        _log(f"[import] access_list {old_id} ({name}) payload: {payload}")
        resp = requests.post(
            f"{base}/api/nginx/access-lists",
            headers=headers,
            json=payload,
            timeout=15,
        )
        if not _check(resp, f"access_list {old_id} ({name})"):
            continue
        new_id = resp.json()["id"]
        al_id_map[old_id] = new_id
        _log(f"[import] access_list {old_id} -> {new_id} ({name})")
    return al_id_map


def _check(resp, context=""):
    """Log and raise on HTTP error. Returns False if the entry already exists (skip),
    True on success, raises on all other errors."""
    if not resp.ok:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        if "already in use" in str(detail).lower():
            msg = ""
            if isinstance(detail, dict) and isinstance(detail.get("error"), dict):
                msg = detail["error"].get("message", "")
            _log(f"[import] SKIP {context} — already exists on target ({msg or detail})")
            return False
        # Include the sent payload in the log so field-level schema errors are diagnosable
        _log(f"[import] ERROR {resp.status_code} {context}: {detail}")
        resp.raise_for_status()
    return True


def import_all(cfg, import_file):
    path = os.path.join(EXPORT_DIR, import_file)
    _log(f"[import] Loading {import_file}...")
    with open(path) as f:
        bundle = json.load(f)

    data = bundle["data"]
    base = cfg["npm_url"].rstrip("/")
    _log(f"[import] Authenticating to {cfg['npm_url']}...")
    headers = authenticate(cfg)
    json_headers = {**headers, "Content-Type": "application/json"}

    cert_id_map = _import_certificates(base, headers, data.get("certificates", []))
    al_id_map = _import_access_lists(base, json_headers, data.get("access_lists", []))

    for ph in data.get("proxy_hosts", []):
        payload = _strip(ph)
        old_al_id = payload.get("access_list_id", 0)
        if old_al_id:
            payload["access_list_id"] = al_id_map.get(old_al_id, 0)
        old_cert_id = payload.get("certificate_id", 0)
        if old_cert_id:
            new_cert_id = cert_id_map.get(old_cert_id, 0)
            payload["certificate_id"] = new_cert_id
            if not new_cert_id:
                payload["ssl_forced"] = False
                _log(
                    f"[import] WARNING: proxy_host {ph['id']} ({ph.get('domain_names')}) "
                    f"had cert id={old_cert_id} which was not restored — SSL disabled"
                )
        resp = requests.post(
            f"{base}/api/nginx/proxy-hosts",
            headers=json_headers,
            json=payload,
            timeout=15,
        )
        if _check(resp, f"proxy_host {ph['id']} {ph.get('domain_names')}"):
            _log(f"[import] proxy_host {ph['id']} -> {resp.json()['id']} ({ph.get('domain_names')})")

    for rh in data.get("redirection_hosts", []):
        payload = _strip(rh)
        old_cert_id = payload.get("certificate_id", 0)
        if old_cert_id:
            new_cert_id = cert_id_map.get(old_cert_id, 0)
            payload["certificate_id"] = new_cert_id
            if not new_cert_id:
                payload["ssl_forced"] = False
                _log(
                    f"[import] WARNING: redirection_host {rh['id']} ({rh.get('domain_names')}) "
                    f"had cert id={old_cert_id} which was not restored — SSL disabled"
                )
        resp = requests.post(
            f"{base}/api/nginx/redirection-hosts",
            headers=json_headers,
            json=payload,
            timeout=15,
        )
        if _check(resp, f"redirection_host {rh['id']} {rh.get('domain_names')}"):
            _log(f"[import] redirection_host {rh['id']} -> {resp.json()['id']}")

    for st in data.get("streams", []):
        payload = {
            "incoming_port":   st.get("incoming_port"),
            "forwarding_host": st.get("forwarding_host", ""),
            "forwarding_port": st.get("forwarding_port"),
            "tcp_forwarding":  st.get("tcp_forwarding", True),
            "udp_forwarding":  st.get("udp_forwarding", False),
        }
        resp = requests.post(
            f"{base}/api/nginx/streams",
            headers=json_headers,
            json=payload,
            timeout=15,
        )
        if _check(resp, f"stream {st['id']} payload={payload}"):
            _log(f"[import] stream {st['id']} -> {resp.json()['id']}")

    _log("[import] Done.")


def _schedule_loop(cfg):
    interval_secs = int(cfg.get("schedule_interval_hours") or 24) * 3600
    _log(f"[schedule] Auto-export every {interval_secs // 3600}h")
    while True:
        time.sleep(interval_secs)
        if not _op_lock.acquire(blocking=False):
            _log("[schedule] Skipping scheduled export — operation already in progress")
            continue
        global _op_running
        _op_running = True
        try:
            export_all(load_options())
        except TwoFactorRequired:
            _log("[schedule] Export failed: 2FA is required — set npm_token in config for scheduled use")
        except Exception as exc:
            _log(f"[schedule] Export failed: {exc}")
        finally:
            _op_running = False
            _op_lock.release()


# ---------------------------------------------------------------------------
# Flask web app
# ---------------------------------------------------------------------------

app = Flask(__name__)

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NPM Export Import</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           background: #f0f2f5; color: #333; padding: 1.5rem; }
    h1   { font-size: 1.4rem; margin-bottom: 1.25rem; color: #111; }
    h2   { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; color: #222; }
    .card { background: #fff; border-radius: 8px; padding: 1.25rem;
            margin-bottom: 1rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    .meta { font-size: 0.85rem; color: #666; margin-bottom: 0.9rem; }
    .meta code { background: #f5f5f5; padding: 0.1rem 0.35rem;
                 border-radius: 3px; font-size: 0.8rem; }
    button { display: inline-flex; align-items: center; gap: 0.4rem;
             padding: 0.45rem 1rem; border: none; border-radius: 5px;
             font-size: 0.85rem; font-weight: 500; cursor: pointer;
             transition: background 0.15s; }
    .btn-primary   { background: #03a9f4; color: #fff; }
    .btn-primary:hover:not(:disabled) { background: #0288d1; }
    .btn-secondary { background: #e8f5e9; color: #2e7d32; }
    .btn-secondary:hover:not(:disabled) { background: #c8e6c9; }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    #op-status { font-size: 0.82rem; color: #888; margin-left: 0.6rem; }
    .file-list { display: flex; flex-direction: column; gap: 0.5rem; }
    .file-row  { display: flex; align-items: center; gap: 0.75rem;
                 padding: 0.5rem 0.6rem; background: #fafafa;
                 border-radius: 5px; border: 1px solid #eee; }
    .file-name { font-family: monospace; font-size: 0.8rem; flex: 1; }
    .file-size { font-size: 0.75rem; color: #aaa; white-space: nowrap; }
    .empty     { font-size: 0.85rem; color: #aaa; font-style: italic; }
    #log { background: #1e1e1e; color: #ccc; font-family: monospace;
           font-size: 0.77rem; line-height: 1.5; padding: 0.75rem;
           border-radius: 5px; height: 220px; overflow-y: auto;
           white-space: pre-wrap; word-break: break-all; }
    /* OTP modal */
    #otp-overlay { display: none; position: fixed; inset: 0;
                   background: rgba(0,0,0,0.45); z-index: 100;
                   align-items: center; justify-content: center; }
    #otp-overlay.active { display: flex; }
    #otp-modal { background: #fff; border-radius: 10px; padding: 1.75rem;
                 width: 320px; box-shadow: 0 8px 32px rgba(0,0,0,0.18); }
    #otp-modal h2 { font-size: 1rem; margin-bottom: 0.5rem; }
    #otp-modal p  { font-size: 0.85rem; color: #666; margin-bottom: 1rem; }
    #otp-input { width: 100%; padding: 0.6rem 0.75rem; font-size: 1.4rem;
                 letter-spacing: 0.25rem; text-align: center; border: 1px solid #ddd;
                 border-radius: 5px; margin-bottom: 0.75rem; font-family: monospace; }
    #otp-input:focus { outline: none; border-color: #03a9f4; }
    #otp-error { font-size: 0.8rem; color: #e53935; min-height: 1.2em;
                 margin-bottom: 0.5rem; }
    #otp-modal .actions { display: flex; justify-content: flex-end; }
    /* Tabs */
    .tabs { display: flex; gap: 0.25rem; margin-bottom: 1.25rem; }
    .tab  { background: #e0e0e0; color: #555; border-radius: 6px 6px 0 0;
            padding: 0.45rem 1.1rem; font-size: 0.85rem; font-weight: 500; }
    .tab.active { background: #03a9f4; color: #fff; }
    /* Settings form */
    .field-group { display: flex; flex-direction: column; gap: 0.6rem; }
    .field-group label { font-size: 0.8rem; color: #666; font-weight: 500; }
    .field-group input[type="url"],
    .field-group input[type="email"],
    .field-group input[type="password"],
    .field-group input[type="number"] {
      padding: 0.45rem 0.6rem; border: 1px solid #ddd; border-radius: 5px;
      font-size: 0.85rem; width: 100%; }
    .field-group input:focus { outline: none; border-color: #03a9f4; }
    .checkbox-label { display: flex; align-items: center; gap: 0.5rem;
                      font-size: 0.85rem; color: #333; font-weight: normal; }
    #save-status { font-size: 0.82rem; color: #888; margin-left: 0.6rem; }
  </style>
</head>
<body>
  <h1>NPM Export Import</h1>

  <div class="tabs">
    <button class="tab active" onclick="showTab('operations', this)">Operations</button>
    <button class="tab" onclick="showTab('settings', this)">Settings</button>
  </div>

  <div id="tab-operations">
    <div class="card">
      <div class="meta">Connected to: <code id="npm-url">…</code></div>
      <h2>Export</h2>
      <button class="btn-primary" id="btn-export" onclick="triggerExport()">Export Now</button>
      <span id="op-status"></span>
    </div>

    <div class="card">
      <h2>Import</h2>
      <p class="meta">Select a backup file to restore into NPM.
         Run against a fresh or cleared instance to avoid duplicates.</p>
      <div class="file-list" id="file-list"><span class="empty">Loading…</span></div>
    </div>

    <div class="card">
      <h2>Log</h2>
      <div id="log"></div>
    </div>
  </div>

  <div id="tab-settings" style="display:none">
    <div class="card">
      <h2>NPM Connection</h2>
      <div class="field-group">
        <label>NPM URL</label>
        <input type="url" id="cfg-npm-url">
        <label>Username</label>
        <input type="email" id="cfg-npm-username">
        <label>Password</label>
        <input type="password" id="cfg-npm-password" placeholder="leave blank to keep current">
        <label>Pre-generated Token (optional — for 2FA / scheduled use)</label>
        <input type="password" id="cfg-npm-token" placeholder="leave blank to keep current">
      </div>
    </div>
    <div class="card">
      <h2>Scheduled Export</h2>
      <div class="field-group">
        <label class="checkbox-label">
          <input type="checkbox" id="cfg-schedule-enabled">
          Enable automatic scheduled exports
        </label>
        <label>Interval (hours)</label>
        <input type="number" id="cfg-schedule-hours" min="1" max="168">
      </div>
      <p class="meta" style="margin-top:0.75rem">
        &#9888;&#65039; Schedule changes take effect after restarting the add-on.
      </p>
    </div>
    <button class="btn-primary" id="btn-save" onclick="saveConfig()">Save</button>
    <span id="save-status"></span>
  </div>

  <!-- 2FA modal -->
  <div id="otp-overlay">
    <div id="otp-modal">
      <h2>Two-factor authentication</h2>
      <p>Enter the 6-digit code from your authenticator app.</p>
      <input id="otp-input" type="text" inputmode="numeric" maxlength="8"
             placeholder="000000" autocomplete="one-time-code"
             onkeydown="if(event.key==='Enter') submitOtp()">
      <div id="otp-error"></div>
      <div class="actions">
        <button class="btn-primary" onclick="submitOtp()">Verify</button>
      </div>
    </div>
  </div>

  <script>
    // HA ingress strips the prefix before forwarding to Flask,
    // but the browser URL still contains it — use it as the fetch base.
    const base = window.location.pathname.replace(/\/+$/, '');
    let _pendingOp = null;       // {type:'export'} or {type:'import', filename:'...'}
    let _challengeToken = null;

    function showTab(name, btn) {
      document.getElementById('tab-operations').style.display =
        name === 'operations' ? '' : 'none';
      document.getElementById('tab-settings').style.display =
        name === 'settings' ? '' : 'none';
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      if (name === 'settings') loadConfig();
    }

    async function loadConfig() {
      try {
        const d = await (await fetch(base + '/api/config')).json();
        document.getElementById('cfg-npm-url').value      = d.npm_url;
        document.getElementById('cfg-npm-username').value = d.npm_username;
        document.getElementById('cfg-npm-password').value = '';
        document.getElementById('cfg-npm-token').value    = '';
        document.getElementById('cfg-npm-password').placeholder =
          d.npm_password ? 'leave blank to keep current' : 'not set';
        document.getElementById('cfg-npm-token').placeholder =
          d.npm_token ? 'leave blank to keep current' : 'not set';
        document.getElementById('cfg-schedule-enabled').checked = d.schedule_enabled;
        document.getElementById('cfg-schedule-hours').value     = d.schedule_interval_hours;
      } catch (_) {}
    }

    async function saveConfig() {
      document.getElementById('btn-save').disabled = true;
      document.getElementById('save-status').textContent = '';
      const pwdVal   = document.getElementById('cfg-npm-password').value;
      const tokenVal = document.getElementById('cfg-npm-token').value;
      const body = {
        npm_url:                 document.getElementById('cfg-npm-url').value,
        npm_username:            document.getElementById('cfg-npm-username').value,
        npm_password:            pwdVal   || '\u2022\u2022\u2022\u2022\u2022',
        npm_token:               tokenVal || '\u2022\u2022\u2022\u2022\u2022',
        schedule_enabled:        document.getElementById('cfg-schedule-enabled').checked,
        schedule_interval_hours: parseInt(document.getElementById('cfg-schedule-hours').value) || 24,
      };
      const r = await fetch(base + '/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      document.getElementById('btn-save').disabled = false;
      document.getElementById('save-status').textContent = r.ok ? '\u2713 Saved' : '\u2717 Save failed';
      if (r.ok) setTimeout(() => document.getElementById('save-status').textContent = '', 3000);
    }

    async function loadStatus() {
      try {
        const d = await (await fetch(base + '/api/status')).json();
        document.getElementById('npm-url').textContent = d.npm_url;
        const busy = d.running || !!d.pending_2fa;
        document.getElementById('btn-export').disabled = busy;
        document.querySelectorAll('.btn-import').forEach(b => b.disabled = busy);
        document.getElementById('op-status').textContent =
          d.running ? '\u23f3 Operation in progress\u2026' : '';

        if (d.pending_2fa && !_challengeToken) {
          _challengeToken = d.pending_2fa;
          document.getElementById('otp-error').textContent = '';
          document.getElementById('otp-input').value = '';
          document.getElementById('otp-overlay').classList.add('active');
          document.getElementById('otp-input').focus();
        }
        if (!d.pending_2fa && _challengeToken) {
          _challengeToken = null;
          document.getElementById('otp-overlay').classList.remove('active');
        }
      } catch (_) {}
    }

    async function loadFiles() {
      try {
        const files = await (await fetch(base + '/api/files')).json();
        const el = document.getElementById('file-list');
        if (!files.length) {
          el.innerHTML = '<span class="empty">No export files found.</span>';
          return;
        }
        el.innerHTML = files.map(f =>
          `<div class="file-row">
            <span class="file-name">${f.name}</span>
            <span class="file-size">${f.size_kb} KB</span>
            <button class="btn-secondary btn-import"
                    onclick="triggerImport('${f.name}')">Import</button>
          </div>`
        ).join('');
      } catch (_) {}
    }

    async function loadLogs() {
      try {
        const d = await (await fetch(base + '/api/logs')).json();
        const el = document.getElementById('log');
        const atBottom = el.scrollHeight - el.scrollTop <= el.clientHeight + 10;
        el.textContent = d.lines.join('\n');
        if (atBottom) el.scrollTop = el.scrollHeight;
      } catch (_) {}
    }

    async function triggerExport() {
      _pendingOp = { type: 'export' };
      document.getElementById('btn-export').disabled = true;
      document.getElementById('op-status').textContent = '\u23f3 Starting\u2026';
      await fetch(base + '/api/export', { method: 'POST' });
    }

    let _importArmed = null;   // filename armed for confirm, or null
    let _importArmTimer = null;

    function triggerImport(filename) {
      if (_importArmed !== filename) {
        // First click — arm the button
        _importArmed = filename;
        const btn = event.target.closest('button');
        const original = btn.textContent;
        btn.textContent = 'Confirm?';
        btn.style.background = '#e53935';
        clearTimeout(_importArmTimer);
        _importArmTimer = setTimeout(() => {
          _importArmed = null;
          btn.textContent = original;
          btn.style.background = '';
        }, 3000);
        return;
      }
      // Second click — fire
      clearTimeout(_importArmTimer);
      _importArmed = null;
      _pendingOp = { type: 'import', filename };
      document.querySelectorAll('.btn-import').forEach(b => { b.disabled = true; b.style.background = ''; b.textContent = 'Import'; });
      document.getElementById('op-status').textContent = '\u23f3 Starting\u2026';
      fetch(base + '/api/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename })
      });
    }

    async function submitOtp() {
      const code = document.getElementById('otp-input').value.trim();
      if (!code) return;
      document.getElementById('otp-error').textContent = '';
      const r = await fetch(base + '/api/auth/verify2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge_token: _challengeToken, code })
      });
      if (!r.ok) {
        const d = await r.json();
        document.getElementById('otp-error').textContent = d.error || 'Verification failed';
        document.getElementById('otp-input').select();
        return;
      }
      // Auth succeeded — hide modal and auto-retry the pending operation
      document.getElementById('otp-overlay').classList.remove('active');
      _challengeToken = null;
      document.getElementById('op-status').textContent = '\u2713 Authenticated';
      if (_pendingOp) {
        const op = _pendingOp;
        _pendingOp = null;
        if (op.type === 'export') triggerExport();
        else if (op.type === 'import') triggerImport(op.filename);
      }
    }

    loadStatus(); loadFiles(); loadLogs();
    setInterval(() => Promise.all([loadStatus(), loadLogs()]), 2000);
    setInterval(loadFiles, 8000);
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    return _HTML


@app.route("/api/status")
def api_status():
    cfg = load_options()
    return jsonify({
        "npm_url": cfg.get("npm_url", ""),
        "running": _op_running,
        "pending_2fa": _pending_2fa,
    })


@app.route("/api/files")
def api_files():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    files = []
    for name in sorted(os.listdir(EXPORT_DIR), reverse=True):
        if name.endswith(".json"):
            path = os.path.join(EXPORT_DIR, name)
            size_kb = round(os.path.getsize(path) / 1024, 1)
            files.append({"name": name, "size_kb": size_kb})
    return jsonify(files)


@app.route("/api/logs")
def api_logs():
    return jsonify({"lines": list(_log_lines)})


@app.route("/api/auth/verify2fa", methods=["POST"])
def api_verify2fa():
    global _pending_2fa
    body = flask_request.get_json() or {}
    challenge_token = body.get("challenge_token", "").strip()
    code = body.get("code", "").strip()
    if not challenge_token or not code:
        return jsonify({"error": "challenge_token and code required"}), 400
    cfg = load_options()
    url = f"{cfg['npm_url'].rstrip('/')}/api/tokens/2fa"
    resp = requests.post(
        url,
        json={"challenge_token": challenge_token, "code": code},
        timeout=15,
    )
    if resp.status_code == 401:
        return jsonify({"error": "Invalid OTP code — check your authenticator app"}), 401
    resp.raise_for_status()
    data = resp.json()
    _set_session_token(data["token"], data["expires"])
    _pending_2fa = None
    _log("[auth] 2FA verified — session token cached")
    return jsonify({"status": "authenticated"})


@app.route("/api/config")
def api_config_get():
    cfg = load_options()
    def mask(val):
        return _MASKED if val else ""
    return jsonify({
        "npm_url":                 cfg.get("npm_url", ""),
        "npm_username":            cfg.get("npm_username", ""),
        "npm_password":            mask(cfg.get("npm_password", "")),
        "npm_token":               mask(cfg.get("npm_token", "")),
        "schedule_enabled":        cfg.get("schedule_enabled", False),
        "schedule_interval_hours": cfg.get("schedule_interval_hours", 24),
    })


@app.route("/api/config", methods=["POST"])
def api_config_post():
    body = flask_request.get_json() or {}
    current = load_options()
    updates = {}
    for key in ("npm_url", "npm_username", "schedule_enabled", "schedule_interval_hours"):
        if key in body:
            updates[key] = body[key]
    for key in ("npm_password", "npm_token"):
        val = body.get(key, _MASKED)
        if val != _MASKED:
            updates[key] = val
        else:
            updates[key] = current.get(key, "")
    save_options(updates)
    return jsonify({"status": "saved"})


@app.route("/api/export", methods=["POST"])
def api_export():
    global _op_running, _pending_2fa
    if not _op_lock.acquire(blocking=False):
        return jsonify({"error": "Operation already in progress"}), 409
    _op_running = True

    def run():
        global _op_running, _pending_2fa
        try:
            export_all(load_options())
        except TwoFactorRequired as exc:
            _pending_2fa = exc.challenge_token
            _log("[auth] 2FA required — enter your code in the prompt")
        except Exception as exc:
            _log(f"[export] ERROR: {exc}")
        finally:
            _op_running = False
            _op_lock.release()

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/import", methods=["POST"])
def api_import():
    global _op_running, _pending_2fa
    body = flask_request.get_json() or {}
    filename = body.get("filename", "").strip()
    if not filename:
        return jsonify({"error": "filename required"}), 400
    if not _op_lock.acquire(blocking=False):
        return jsonify({"error": "Operation already in progress"}), 409
    _op_running = True

    def run():
        global _op_running, _pending_2fa
        try:
            import_all(load_options(), filename)
        except TwoFactorRequired as exc:
            _pending_2fa = exc.challenge_token
            _log("[auth] 2FA required — enter your code in the prompt")
        except Exception as exc:
            _log(f"[import] ERROR: {exc}")
        finally:
            _op_running = False
            _op_lock.release()

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


def main():
    cfg = load_options()
    if cfg.get("schedule_enabled"):
        threading.Thread(target=_schedule_loop, args=(cfg,), daemon=True).start()

    _log(f"[server] Starting on port {INGRESS_PORT}")
    app.run(host="0.0.0.0", port=INGRESS_PORT, threaded=True)


if __name__ == "__main__":
    main()
