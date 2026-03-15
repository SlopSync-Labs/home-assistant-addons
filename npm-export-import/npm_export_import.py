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

# --- shared state ---
_log_lines = collections.deque(maxlen=200)
_op_lock = threading.Lock()
_op_running = False


def _log(msg):
    print(msg, flush=True)
    _log_lines.append(msg)


# ---------------------------------------------------------------------------
# Core export / import logic
# ---------------------------------------------------------------------------

def load_options():
    with open(OPTIONS_PATH) as f:
        return json.load(f)


def authenticate(base_url, username, password):
    url = f"{base_url.rstrip('/')}/api/tokens"
    resp = requests.post(
        url,
        json={"identity": username, "secret": password},
        timeout=15,
    )
    resp.raise_for_status()
    token = resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}


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


def fetch_all(base_url, headers):
    base = base_url.rstrip("/")
    data = {}
    for key, path in ENTITY_ENDPOINTS.items():
        resp = requests.get(f"{base}{path}", headers=headers, timeout=15)
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
    headers = authenticate(cfg["npm_url"], cfg["npm_username"], cfg["npm_password"])
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
    al_id_map = {}
    for al in access_lists:
        old_id = al["id"]
        payload = _strip(al)
        resp = requests.post(
            f"{base}/api/nginx/access-lists",
            headers=headers,
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        new_id = resp.json()["id"]
        al_id_map[old_id] = new_id
        _log(f"[import] access_list {old_id} -> {new_id} ({al.get('name', '')})")
    return al_id_map


def import_all(cfg, import_file):
    path = os.path.join(EXPORT_DIR, import_file)
    _log(f"[import] Loading {import_file}...")
    with open(path) as f:
        bundle = json.load(f)

    data = bundle["data"]
    base = cfg["npm_url"].rstrip("/")
    _log(f"[import] Authenticating to {cfg['npm_url']}...")
    headers = authenticate(cfg["npm_url"], cfg["npm_username"], cfg["npm_password"])
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
        resp.raise_for_status()
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
        resp.raise_for_status()
        _log(f"[import] redirection_host {rh['id']} -> {resp.json()['id']}")

    for st in data.get("streams", []):
        payload = _strip(st)
        resp = requests.post(
            f"{base}/api/nginx/streams",
            headers=json_headers,
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
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
  </style>
</head>
<body>
  <h1>NPM Export Import</h1>

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

  <script>
    // HA ingress strips the prefix before forwarding to Flask,
    // but the browser URL still contains it — use it as the fetch base.
    const base = window.location.pathname.replace(/\/+$/, '');

    async function loadStatus() {
      try {
        const d = await (await fetch(base + '/api/status')).json();
        document.getElementById('npm-url').textContent = d.npm_url;
        const busy = d.running;
        document.getElementById('btn-export').disabled = busy;
        document.querySelectorAll('.btn-import').forEach(b => b.disabled = busy);
        document.getElementById('op-status').textContent =
          busy ? '⏳ Operation in progress…' : '';
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
      document.getElementById('btn-export').disabled = true;
      document.getElementById('op-status').textContent = '⏳ Starting…';
      await fetch(base + '/api/export', { method: 'POST' });
    }

    async function triggerImport(filename) {
      if (!confirm(`Import from:\n${filename}\n\nThis will create new entries in NPM.`)) return;
      document.querySelectorAll('.btn-import').forEach(b => b.disabled = true);
      document.getElementById('op-status').textContent = '⏳ Starting…';
      await fetch(base + '/api/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename })
      });
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
    return jsonify({"npm_url": cfg.get("npm_url", ""), "running": _op_running})


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


@app.route("/api/export", methods=["POST"])
def api_export():
    global _op_running
    if not _op_lock.acquire(blocking=False):
        return jsonify({"error": "Operation already in progress"}), 409
    _op_running = True

    def run():
        global _op_running
        try:
            export_all(load_options())
        except Exception as exc:
            _log(f"[export] ERROR: {exc}")
        finally:
            _op_running = False
            _op_lock.release()

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/import", methods=["POST"])
def api_import():
    global _op_running
    body = flask_request.get_json() or {}
    filename = body.get("filename", "").strip()
    if not filename:
        return jsonify({"error": "filename required"}), 400
    if not _op_lock.acquire(blocking=False):
        return jsonify({"error": "Operation already in progress"}), 409
    _op_running = True

    def run():
        global _op_running
        try:
            import_all(load_options(), filename)
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
