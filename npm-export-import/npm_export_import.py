import base64
import collections
import json
import os
import threading
import uuid
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify
from flask import request as flask_request

OPTIONS_PATH = "/data/options.json"
SERVERS_PATH = "/data/servers.json"
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
_pending_2fa = None
_sessions: dict = {}  # server_id -> {"token": ..., "expires": ...}


def _log(msg):
    print(msg, flush=True)
    _log_lines.append(msg)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

class TwoFactorRequired(Exception):
    def __init__(self, challenge_token):
        self.challenge_token = challenge_token


def _get_session_token(server_id):
    s = _sessions.get(server_id, {})
    if s.get("token") and s.get("expires"):
        if datetime.now(timezone.utc) < s["expires"]:
            return s["token"]
    return None


def _set_session_token(server_id, token, expires_str):
    _sessions[server_id] = {
        "token": token,
        "expires": datetime.fromisoformat(expires_str.replace("Z", "+00:00")),
    }


def authenticate(server):
    cached = _get_session_token(server["id"])
    if cached:
        return {"Authorization": f"Bearer {cached}"}

    url = f"{server['npm_url'].rstrip('/')}/api/tokens"
    resp = requests.post(
        url,
        json={"identity": server["npm_username"], "secret": server["npm_password"], "scope": "user"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("requires_2fa"):
        raise TwoFactorRequired(data["challenge_token"])
    _set_session_token(server["id"], data["token"], data["expires"])
    return {"Authorization": f"Bearer {data['token']}"}


# ---------------------------------------------------------------------------
# Core export / import logic
# ---------------------------------------------------------------------------

def load_options():
    with open(OPTIONS_PATH) as f:
        return json.load(f)


def load_servers():
    try:
        with open(SERVERS_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_servers(servers):
    with open(SERVERS_PATH, "w") as f:
        json.dump(servers, f, indent=2)


def _get_server(server_id):
    for s in load_servers():
        if s["id"] == server_id:
            return s
    return None


def _migrate_legacy_config():
    """If servers.json does not exist but options.json has npm_url, create an initial server entry."""
    if os.path.isfile(SERVERS_PATH):
        return
    try:
        cfg = load_options()
        url = cfg.get("npm_url", "").strip()
        username = cfg.get("npm_username", "").strip()
        password = cfg.get("npm_password", "")
        if url and username:
            servers = [{
                "id": uuid.uuid4().hex[:8],
                "name": "Default",
                "npm_url": url,
                "npm_username": username,
                "npm_password": password,
            }]
            save_servers(servers)
            _log("[server] Migrated legacy config to servers list")
    except Exception:
        pass



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

        if name in existing_by_name:
            # Update the existing entry so clients/items are always in sync
            new_id = existing_by_name[name]
            resp = requests.put(
                f"{base}/api/nginx/access-lists/{new_id}",
                headers=headers,
                json=payload,
                timeout=15,
            )
            if not _check(resp, f"access_list {old_id} ({name}) update"):
                continue
            al_id_map[old_id] = new_id
            result = resp.json()
            client_count = len(result.get("clients", []))
            _log(f"[import] access_list {old_id} -> {new_id} ({name}) — updated ({client_count} client rules)")
        else:
            resp = requests.post(
                f"{base}/api/nginx/access-lists",
                headers=headers,
                json=payload,
                timeout=15,
            )
            if not _check(resp, f"access_list {old_id} ({name})"):
                continue
            result = resp.json()
            new_id = result["id"]
            al_id_map[old_id] = new_id
            client_count = len(result.get("clients", []))
            _log(f"[import] access_list {old_id} -> {new_id} ({name}) ({client_count} client rules)")
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

    # Build domain -> id map of proxy hosts already on the target so we can
    # PUT (update) rather than POST (duplicate) when a host already exists.
    existing_ph_resp = requests.get(f"{base}/api/nginx/proxy-hosts", headers=json_headers, timeout=15)
    existing_ph_by_domain = {}
    if existing_ph_resp.ok:
        for existing in existing_ph_resp.json():
            for domain in existing.get("domain_names", []):
                existing_ph_by_domain[domain] = existing["id"]
    else:
        _log(f"[import] WARNING: could not fetch existing proxy hosts ({existing_ph_resp.status_code}) — duplicate check skipped")

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

        domains = ph.get("domain_names", [])
        existing_id = next((existing_ph_by_domain[d] for d in domains if d in existing_ph_by_domain), None)

        if existing_id:
            resp = requests.put(
                f"{base}/api/nginx/proxy-hosts/{existing_id}",
                headers=json_headers,
                json=payload,
                timeout=15,
            )
            if _check(resp, f"proxy_host {ph['id']} {domains} update"):
                _log(f"[import] proxy_host {ph['id']} -> {existing_id} ({domains}) — updated existing")
        else:
            resp = requests.post(
                f"{base}/api/nginx/proxy-hosts",
                headers=json_headers,
                json=payload,
                timeout=15,
            )
            if _check(resp, f"proxy_host {ph['id']} {domains}"):
                _log(f"[import] proxy_host {ph['id']} -> {resp.json()['id']} ({domains})")

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

    existing_streams_resp = requests.get(f"{base}/api/nginx/streams", headers=json_headers, timeout=15)
    existing_ports = set()
    if existing_streams_resp.ok:
        existing_ports = {s.get("incoming_port") for s in existing_streams_resp.json()}
    else:
        _log(f"[import] WARNING: could not fetch existing streams ({existing_streams_resp.status_code}) — duplicate check skipped")

    for st in data.get("streams", []):
        port = st.get("incoming_port")
        if port in existing_ports:
            _log(f"[import] SKIP stream {st['id']} (port {port}) — already exists on target")
            continue
        payload = {
            "incoming_port":   port,
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
        if _check(resp, f"stream {st['id']} port {port}"):
            _log(f"[import] stream {st['id']} -> {resp.json()['id']} (port {port})")

    _log("[import] Done.")


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
    :root {
      --bg:               #f0f2f5;
      --surface:          #fff;
      --surface-alt:      #fafafa;
      --border:           #eee;
      --text:             #333;
      --text-h1:          #111;
      --text-h2:          #222;
      --text-muted:       #666;
      --text-dim:         #aaa;
      --code-bg:          #f5f5f5;
      --shadow:           0 1px 4px rgba(0,0,0,.08);
      --row-hover-bg:     #f0f7ff;
      --row-hover-border: #b3d9f7;
      --row-sel-bg:       #e3f2fd;
      --tab-bg:           #e0e0e0;
      --tab-fg:           #555;
      --input-bg:         #fff;
      --input-border:     #ddd;
      --input-color:      #333;
      --overlay-bg:       rgba(0,0,0,0.45);
      --btn-danger-bg:    #fbe9e7;
      --btn-danger-fg:    #c62828;
      --btn-danger-hov:   #ffccbc;
    }
    [data-theme="dark"] {
      --bg:               #0f1117;
      --surface:          #1c1c28;
      --surface-alt:      #252535;
      --border:           #2e2e40;
      --text:             #dde1e7;
      --text-h1:          #f0f0f0;
      --text-h2:          #d0d4df;
      --text-muted:       #8a8fa8;
      --text-dim:         #555770;
      --code-bg:          #252535;
      --shadow:           0 1px 6px rgba(0,0,0,.45);
      --row-hover-bg:     #1e2a3a;
      --row-hover-border: #2a5070;
      --row-sel-bg:       #0d3350;
      --tab-bg:           #252535;
      --tab-fg:           #8a8fa8;
      --input-bg:         #252535;
      --input-border:     #3a3a50;
      --input-color:      #dde1e7;
      --overlay-bg:       rgba(0,0,0,0.65);
      --btn-danger-bg:    #3a1515;
      --btn-danger-fg:    #ef9a9a;
      --btn-danger-hov:   #4a2020;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           background: var(--bg); color: var(--text); padding: 1.5rem;
           transition: background 0.2s, color 0.2s; }
    .container { max-width: 640px; margin: 0 auto; }
    h1   { font-size: 1.4rem; color: var(--text-h1); }
    h2   { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; color: var(--text-h2); }
    .card { background: var(--surface); border-radius: 8px; padding: 1.25rem;
            margin-bottom: 1rem; box-shadow: var(--shadow); }
    .meta { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.9rem; }
    .meta code { background: var(--code-bg); padding: 0.1rem 0.35rem;
                 border-radius: 3px; font-size: 0.8rem; }
    button { display: inline-flex; align-items: center; gap: 0.4rem;
             padding: 0.45rem 1rem; border: none; border-radius: 5px;
             font-size: 0.85rem; font-weight: 500; cursor: pointer;
             transition: background 0.15s; }
    .btn-primary   { background: #03a9f4; color: #fff; }
    .btn-primary:hover:not(:disabled) { background: #0288d1; }
    .btn-secondary { background: #e8f5e9; color: #2e7d32; }
    .btn-secondary:hover:not(:disabled) { background: #c8e6c9; }
    .btn-danger    { background: var(--btn-danger-bg); color: var(--btn-danger-fg); }
    .btn-danger:hover:not(:disabled)    { background: var(--btn-danger-hov); }
    .btn-theme     { background: var(--tab-bg); color: var(--tab-fg);
                     padding: 0.3rem 0.65rem; font-size: 1rem; line-height: 1; }
    .btn-theme:hover { background: var(--row-hover-bg); }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    .page-header { display: flex; align-items: center; justify-content: space-between;
                   margin-bottom: 1.25rem; }
    .page-title  { display: flex; align-items: center; gap: 0.6rem; }
    .app-icon    { width: 36px; height: 36px; border-radius: 8px; display: block; }
    #op-status-bar { min-height: 1.6rem; display: flex; align-items: center;
                     font-size: 0.82rem; color: var(--text-muted);
                     margin-bottom: 0.5rem; padding: 0 0.1rem; }
    .file-list { display: flex; flex-direction: column; gap: 0.5rem;
                 max-height: 248px; overflow-y: auto; }
    .file-row  { display: flex; align-items: center; gap: 0.75rem;
                 padding: 0.5rem 0.6rem; background: var(--surface-alt);
                 border-radius: 5px; border: 1px solid var(--border); cursor: pointer; }
    .file-row:hover   { background: var(--row-hover-bg); border-color: var(--row-hover-border); }
    .file-row.selected { background: var(--row-sel-bg); border-color: #03a9f4; }
    .file-name { font-family: monospace; font-size: 0.8rem; flex: 1; }
    .file-size { font-size: 0.75rem; color: var(--text-dim); white-space: nowrap; }
    .import-actions { display: flex; gap: 0.5rem; }
    .empty     { font-size: 0.85rem; color: var(--text-dim); font-style: italic; }
    #log { background: #1e1e1e; color: #ccc; font-family: monospace;
           font-size: 0.77rem; line-height: 1.5; padding: 0.75rem;
           border-radius: 5px; height: 220px; overflow-y: auto;
           white-space: pre-wrap; word-break: break-all; }
    .server-select { padding: 0.42rem 0.6rem; border: 1px solid var(--input-border);
                     border-radius: 5px; font-size: 0.85rem; width: 100%;
                     background: var(--input-bg); color: var(--input-color);
                     margin-bottom: 0.75rem; }
    .server-row { display: flex; align-items: center; justify-content: space-between;
                  padding: 0.5rem 0.65rem; background: var(--surface-alt);
                  border-radius: 5px; border: 1px solid var(--border);
                  margin-bottom: 0.5rem; }
    .server-info { display: flex; flex-direction: column; gap: 0.15rem; min-width: 0;
                   overflow: hidden; }
    .server-name { font-size: 0.85rem; font-weight: 600; color: var(--text); }
    .server-url  { font-size: 0.75rem; color: var(--text-muted); font-family: monospace;
                   white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .server-actions { display: flex; gap: 0.35rem; flex-shrink: 0; margin-left: 0.5rem; }
    .btn-sm { padding: 0.28rem 0.6rem; font-size: 0.78rem; }
    #sf-error { font-size: 0.8rem; color: #e53935; min-height: 1.1em; }
    /* OTP modal */
    #otp-overlay { display: none; position: fixed; inset: 0;
                   background: var(--overlay-bg); z-index: 100;
                   align-items: center; justify-content: center; }
    #otp-overlay.active { display: flex; }
    #otp-modal { background: var(--surface); border-radius: 10px; padding: 1.75rem;
                 width: 320px; box-shadow: 0 8px 32px rgba(0,0,0,0.25); }
    #otp-modal h2 { font-size: 1rem; margin-bottom: 0.5rem; color: var(--text-h2); }
    #otp-modal p  { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem; }
    #otp-input { width: 100%; padding: 0.6rem 0.75rem; font-size: 1.4rem;
                 letter-spacing: 0.25rem; text-align: center;
                 border: 1px solid var(--input-border); border-radius: 5px;
                 margin-bottom: 0.75rem; font-family: monospace;
                 background: var(--input-bg); color: var(--input-color); }
    #otp-input:focus { outline: none; border-color: #03a9f4; }
    #otp-error { font-size: 0.8rem; color: #e53935; min-height: 1.2em; margin-bottom: 0.5rem; }
    #otp-modal .actions { display: flex; justify-content: flex-end; }
    /* Tabs */
    .tabs { display: flex; gap: 0.25rem; margin-bottom: 1.25rem; justify-content: center; }
    .tab  { background: var(--tab-bg); color: var(--tab-fg); border-radius: 6px 6px 0 0;
            padding: 0.45rem 1.1rem; font-size: 0.85rem; font-weight: 500; }
    .tab.active { background: #03a9f4; color: #fff; }
    /* Settings form */
    .field-group { display: flex; flex-direction: column; gap: 0.6rem; }
    .field-group label { font-size: 0.8rem; color: var(--text-muted); font-weight: 500; }
    .field-group input[type="text"],
    .field-group input[type="url"],
    .field-group input[type="email"],
    .field-group input[type="password"],
    .field-group input[type="number"] {
      padding: 0.45rem 0.6rem; border: 1px solid var(--input-border); border-radius: 5px;
      font-size: 0.85rem; width: 100%;
      background: var(--input-bg); color: var(--input-color); }
    .field-group input:focus { outline: none; border-color: #03a9f4; }
    .checkbox-label { display: flex; align-items: center; gap: 0.5rem;
                      font-size: 0.85rem; color: var(--text); font-weight: normal; }
    #save-status { font-size: 0.82rem; color: var(--text-muted); margin-left: 0.6rem; }
  </style>
</head>
<body>
<div class="container">
  <div class="page-header">
    <div class="page-title">
      <img src="__ICON_URI__" class="app-icon" alt="">
      <h1>NPM Export Import</h1>
    </div>
    <button class="btn-theme" id="btn-theme" onclick="toggleTheme()" title="Toggle dark mode"></button>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('operations', this)">Operations</button>
    <button class="tab" onclick="showTab('settings', this)">Settings</button>
  </div>

  <div id="tab-operations">
    <div id="op-status-bar"></div>

    <div class="card">
      <h2>Export</h2>
      <label style="font-size:0.8rem;color:var(--text-muted);font-weight:500;display:block;margin-bottom:0.4rem">Source Server</label>
      <select id="sel-export-server" class="server-select" onchange="saveServerPref('export',this.value)"></select>
      <button class="btn-primary" id="btn-export" onclick="triggerExport()">Export Now</button>
    </div>

    <div class="card">
      <h2>Import</h2>
      <label style="font-size:0.8rem;color:var(--text-muted);font-weight:500;display:block;margin-bottom:0.4rem">Target Server</label>
      <select id="sel-import-server" class="server-select" onchange="saveServerPref('import',this.value)"></select>
      <div class="import-actions">
        <button class="btn-primary" id="btn-import" onclick="triggerImport()" disabled>Import Selected</button>
        <button class="btn-danger" id="btn-delete" onclick="triggerDelete()" disabled>Delete</button>
      </div>
      <p class="meta" style="margin-top:0.75rem">Select a backup file to restore into NPM.</p>
      <div class="file-list" id="file-list"><span class="empty">Loading…</span></div>
    </div>

    <div class="card">
      <h2>Log</h2>
      <div id="log"></div>
    </div>
  </div>

  <div id="tab-settings" style="display:none">
    <div class="card">
      <h2>NPM Servers</h2>
      <div id="server-list"><span class="empty">No servers configured.</span></div>
      <button class="btn-primary" style="margin-top:0.75rem" onclick="showServerForm(null)">+ Add Server</button>
    </div>
    <div class="card" id="server-form-card" style="display:none">
      <h2 id="server-form-title">Add Server</h2>
      <div class="field-group">
        <label>Name</label>
        <input type="text" id="sf-name" placeholder="e.g. Production">
        <label>NPM URL</label>
        <input type="url" id="sf-url" placeholder="http://homeassistant.local:81">
        <label>Username</label>
        <input type="email" id="sf-username" placeholder="admin@example.com">
        <label>Password</label>
        <input type="password" id="sf-password" placeholder="NPM password">
      </div>
      <div id="sf-error"></div>
      <div style="display:flex;gap:0.5rem;margin-top:0.75rem">
        <button class="btn-primary" onclick="saveServer()">Save Server</button>
        <button class="btn-secondary" onclick="cancelServerForm()">Cancel</button>
      </div>
    </div>
  </div>

</div><!-- .container -->

  <div id="otp-overlay">
    <div id="otp-modal">
      <h2>Two-factor authentication</h2>
      <p>Enter the 6-digit code from your authenticator app.</p>
      <input id="otp-input" type="text" inputmode="numeric" maxlength="8"
             placeholder="000000" autocomplete="one-time-code"
             onkeydown="if(event.key==='Enter') submitOtp()">
      <div id="otp-error"></div>
      <div class="actions" style="gap:0.5rem">
        <button class="btn-secondary" onclick="dismissOtp()">Cancel</button>
        <button class="btn-primary" onclick="submitOtp()">Verify</button>
      </div>
    </div>
  </div>

  <script>
    // Theme
    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      document.getElementById('btn-theme').textContent = theme === 'dark' ? '\u2600\ufe0f' : '\ud83c\udf19';
    }
    function toggleTheme() {
      const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      localStorage.setItem('npm-ei-theme', next);
      applyTheme(next);
    }
    (function() {
      const saved = localStorage.getItem('npm-ei-theme');
      const sys = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      applyTheme(saved || sys);
    })();

    const base = window.location.pathname.replace(/\/+$/, '');
    let _selectedFile = null;
    let _importArmed = false;
    let _importArmTimer = null;
    let _deleteArmed = false;
    let _deleteArmTimer = null;
    let _servers = [];
    let _editingServerId = null;
    let _deleteServerArmed = null;
    let _deleteServerBtn = null;
    let _deleteServerTimer = null;
    let _op_running_client = false;
    let _pendingOp = null;
    let _challengeToken = null;

    function showTab(name, btn) {
      document.getElementById('tab-operations').style.display = name === 'operations' ? '' : 'none';
      document.getElementById('tab-settings').style.display   = name === 'settings'   ? '' : 'none';
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      if (name === 'settings') loadServers();
    }

    // --- Servers ---
    async function loadServers() {
      try {
        const r = await fetch(base + '/api/servers');
        _servers = await r.json();
        renderServerList();
        renderServerDropdowns();
      } catch (_) {}
    }

    function renderServerList() {
      const el = document.getElementById('server-list');
      if (!el) return;
      if (!_servers.length) {
        el.innerHTML = '<span class="empty">No servers configured.</span>';
        return;
      }
      el.innerHTML = _servers.map(s =>
        `<div class="server-row">
          <div class="server-info">
            <span class="server-name">${s.name}</span>
            <span class="server-url">${s.npm_url}</span>
          </div>
          <div class="server-actions">
            <button class="btn-secondary btn-sm" onclick="showServerForm('${s.id}')">Edit</button>
            <button class="btn-danger btn-sm" onclick="deleteServer('${s.id}', this)">Delete</button>
          </div>
        </div>`
      ).join('');
    }

    function renderServerDropdowns() {
      const savedExport = localStorage.getItem('npm-ei-export-server');
      const savedImport = localStorage.getItem('npm-ei-import-server');
      ['sel-export-server', 'sel-import-server'].forEach((id, i) => {
        const sel = document.getElementById(id);
        if (!sel) return;
        const saved = i === 0 ? savedExport : savedImport;
        sel.innerHTML = _servers.length
          ? _servers.map(s => `<option value="${s.id}"${s.id === saved ? ' selected' : ''}>${s.name}</option>`).join('')
          : '<option value="">\u2014 No servers configured \u2014</option>';
      });
      document.getElementById('btn-export').disabled = _op_running_client || !_servers.length;
    }

    function saveServerPref(type, value) {
      localStorage.setItem(`npm-ei-${type}-server`, value);
    }

    function showServerForm(id) {
      _editingServerId = id;
      document.getElementById('server-form-title').textContent = id ? 'Edit Server' : 'Add Server';
      document.getElementById('sf-error').textContent = '';
      if (id) {
        const s = _servers.find(x => x.id === id);
        document.getElementById('sf-name').value     = s.name;
        document.getElementById('sf-url').value      = s.npm_url;
        document.getElementById('sf-username').value = s.npm_username;
        document.getElementById('sf-password').value = '';
        document.getElementById('sf-password').placeholder = s.has_password ? 'leave blank to keep current' : 'not set';
      } else {
        ['sf-name','sf-url','sf-username','sf-password'].forEach(fid => document.getElementById(fid).value = '');
        document.getElementById('sf-password').placeholder = 'NPM password';
      }
      document.getElementById('server-form-card').style.display = '';
      document.getElementById('sf-name').focus();
    }

    function cancelServerForm() {
      document.getElementById('server-form-card').style.display = 'none';
      _editingServerId = null;
    }

    async function saveServer() {
      const name     = document.getElementById('sf-name').value.trim();
      const npm_url  = document.getElementById('sf-url').value.trim();
      const username = document.getElementById('sf-username').value.trim();
      const pwd      = document.getElementById('sf-password').value;
      const errEl    = document.getElementById('sf-error');
      if (!name || !npm_url || !username) {
        errEl.textContent = 'Name, URL, and Username are required.';
        return;
      }
      if (!_editingServerId && !pwd) {
        errEl.textContent = 'Password is required for new servers.';
        return;
      }
      errEl.textContent = '';
      const body = {
        name, npm_url, npm_username: username,
        npm_password: pwd || '\u2022\u2022\u2022\u2022\u2022',
      };
      const method = _editingServerId ? 'PUT' : 'POST';
      const url    = _editingServerId ? `${base}/api/servers/${_editingServerId}` : `${base}/api/servers`;
      const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) { errEl.textContent = 'Save failed.'; return; }
      cancelServerForm();
      await loadServers();
    }

    function deleteServer(id, btn) {
      if (_deleteServerArmed !== id) {
        if (_deleteServerBtn) { _deleteServerBtn.textContent = 'Delete'; _deleteServerBtn.style.cssText = ''; }
        clearTimeout(_deleteServerTimer);
        _deleteServerArmed = id;
        _deleteServerBtn = btn;
        btn.textContent = 'Confirm?';
        btn.style.background = '#e53935';
        btn.style.color = '#fff';
        _deleteServerTimer = setTimeout(() => {
          if (_deleteServerBtn) { _deleteServerBtn.textContent = 'Delete'; _deleteServerBtn.style.cssText = ''; }
          _deleteServerArmed = null; _deleteServerBtn = null;
        }, 3000);
        return;
      }
      clearTimeout(_deleteServerTimer);
      _deleteServerArmed = null; _deleteServerBtn = null;
      fetch(`${base}/api/servers/${id}`, { method: 'DELETE' }).then(() => loadServers());
    }

    // --- Status / Operations ---
    async function loadStatus() {
      try {
        const d = await (await fetch(base + '/api/status')).json();
        _op_running_client = d.running;
        const busy = d.running || !!d.pending_2fa;
        document.getElementById('btn-export').disabled = busy || !_servers.length;
        document.getElementById('btn-import').disabled = busy || !_selectedFile;
        document.getElementById('btn-delete').disabled = busy || !_selectedFile;
        document.getElementById('op-status-bar').textContent =
          d.running ? '\u23f3 Operation in progress\u2026' : '';

        if (d.pending_2fa && !_challengeToken) {
          _challengeToken = d.pending_2fa.challenge_token;
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

    function selectFile(filename, row) {
      _selectedFile = filename;
      document.querySelectorAll('.file-row').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');
      if (!_op_running_client) {
        document.getElementById('btn-import').disabled = false;
        document.getElementById('btn-delete').disabled = false;
      }
    }

    async function loadFiles() {
      try {
        const files = await (await fetch(base + '/api/files')).json();
        const el = document.getElementById('file-list');
        if (!files.length) {
          el.innerHTML = '<span class="empty">No export files found.</span>';
          _selectedFile = null;
          document.getElementById('btn-import').disabled = true;
          document.getElementById('btn-delete').disabled = true;
          return;
        }
        el.innerHTML = files.map(f =>
          `<div class="file-row${f.name === _selectedFile ? ' selected' : ''}"
                onclick="selectFile('${f.name}', this)">
            <span class="file-name">${f.name}</span>
            <span class="file-size">${f.size_kb} KB</span>
          </div>`
        ).join('');
        document.getElementById('btn-import').disabled = _op_running_client || !_selectedFile;
        document.getElementById('btn-delete').disabled = _op_running_client || !_selectedFile;
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
      const serverId = document.getElementById('sel-export-server').value;
      if (!serverId) return;
      saveServerPref('export', serverId);
      _pendingOp = { type: 'export', serverId };
      document.getElementById('btn-export').disabled = true;
      document.getElementById('btn-import').disabled = true;
      document.getElementById('op-status-bar').textContent = '\u23f3 Starting export\u2026';
      await fetch(base + '/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId })
      });
    }

    function triggerImport() {
      if (!_selectedFile) return;
      const btn = document.getElementById('btn-import');
      if (!_importArmed) {
        _importArmed = true;
        btn.textContent = 'Confirm?';
        btn.style.background = '#e53935';
        clearTimeout(_importArmTimer);
        _importArmTimer = setTimeout(() => {
          _importArmed = false;
          btn.textContent = 'Import Selected';
          btn.style.background = '';
        }, 3000);
        return;
      }
      clearTimeout(_importArmTimer);
      _importArmed = false;
      btn.textContent = 'Import Selected';
      btn.style.background = '';
      const serverId = document.getElementById('sel-import-server').value;
      if (!serverId) return;
      saveServerPref('import', serverId);
      _pendingOp = { type: 'import', serverId, filename: _selectedFile };
      btn.disabled = true;
      document.getElementById('btn-export').disabled = true;
      document.getElementById('op-status-bar').textContent = '\u23f3 Starting import\u2026';
      fetch(base + '/api/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId, filename: _selectedFile })
      });
    }

    function triggerDelete() {
      if (!_selectedFile) return;
      const btn = document.getElementById('btn-delete');
      if (!_deleteArmed) {
        _deleteArmed = true;
        btn.textContent = 'Confirm?';
        btn.style.background = '#e53935';
        btn.style.color = '#fff';
        clearTimeout(_deleteArmTimer);
        _deleteArmTimer = setTimeout(() => {
          _deleteArmed = false;
          btn.textContent = 'Delete';
          btn.style.background = '';
          btn.style.color = '';
        }, 3000);
        return;
      }
      clearTimeout(_deleteArmTimer);
      _deleteArmed = false;
      btn.textContent = 'Delete';
      btn.style.background = '';
      btn.style.color = '';
      const filename = _selectedFile;
      _selectedFile = null;
      document.getElementById('btn-import').disabled = true;
      document.getElementById('btn-delete').disabled = true;
      fetch(base + '/api/files/' + encodeURIComponent(filename), { method: 'DELETE' })
        .then(() => loadFiles());
    }

    async function submitOtp() {
      const code = document.getElementById('otp-input').value.trim();
      if (!code || !_challengeToken) return;
      document.getElementById('otp-error').textContent = '';
      const r = await fetch(base + '/api/auth/verify2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      if (!r.ok) {
        const d = await r.json();
        document.getElementById('otp-error').textContent = d.error || 'Verification failed';
        document.getElementById('otp-input').select();
        return;
      }
      _challengeToken = null;
      document.getElementById('otp-overlay').classList.remove('active');
      const op = _pendingOp;
      _pendingOp = null;
      if (!op) {
        document.getElementById('op-status-bar').textContent = '\u2713 Authenticated \u2014 retry your operation';
        return;
      }
      if (op.type === 'export') {
        document.getElementById('btn-export').disabled = true;
        document.getElementById('op-status-bar').textContent = '\u23f3 Starting export\u2026';
        const er = await fetch(base + '/api/export', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ server_id: op.serverId })
        });
        if (!er.ok) {
          const ed = await er.json().catch(() => ({}));
          document.getElementById('op-status-bar').textContent =
            '\u2717 ' + (ed.error || 'Failed to start export');
          document.getElementById('btn-export').disabled = false;
        }
      } else if (op.type === 'import') {
        document.getElementById('btn-import').disabled = true;
        document.getElementById('btn-export').disabled = true;
        document.getElementById('op-status-bar').textContent = '\u23f3 Starting import\u2026';
        const ir = await fetch(base + '/api/import', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ server_id: op.serverId, filename: op.filename })
        });
        if (!ir.ok) {
          const id2 = await ir.json().catch(() => ({}));
          document.getElementById('op-status-bar').textContent =
            '\u2717 ' + (id2.error || 'Failed to start import');
          document.getElementById('btn-export').disabled = false;
          document.getElementById('btn-import').disabled = false;
        }
      }
    }

    async function dismissOtp() {
      await fetch(base + '/api/auth/dismiss2fa', { method: 'POST' });
      _challengeToken = null;
      _pendingOp = null;
      document.getElementById('otp-overlay').classList.remove('active');
    }

    loadServers(); loadStatus(); loadFiles(); loadLogs();
    setInterval(() => Promise.all([loadStatus(), loadLogs()]), 2000);
    setInterval(loadFiles, 8000);
  </script>
</body>
</html>
"""


def _icon_data_uri():
    try:
        with open("/app/icon.png", "rb") as f:
            return "data:image/png;base64," + base64.b64encode(f.read()).decode()
    except Exception:
        return ""


@app.route("/")
def index():
    return _HTML.replace("__ICON_URI__", _icon_data_uri())


@app.route("/api/status")
def api_status():
    return jsonify({"running": _op_running, "pending_2fa": _pending_2fa})


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


@app.route("/api/servers")
def api_servers_list():
    servers = sorted(load_servers(), key=lambda s: s.get("name", "").lower())
    return jsonify([{
        "id": s["id"],
        "name": s["name"],
        "npm_url": s["npm_url"],
        "npm_username": s["npm_username"],
        "has_password": bool(s.get("npm_password")),
    } for s in servers])


@app.route("/api/servers", methods=["POST"])
def api_servers_create():
    body = flask_request.get_json() or {}
    name = body.get("name", "").strip()
    npm_url = body.get("npm_url", "").strip()
    npm_username = body.get("npm_username", "").strip()
    npm_password = body.get("npm_password", "")
    if not name or not npm_url or not npm_username or not npm_password:
        return jsonify({"error": "name, npm_url, npm_username, npm_password required"}), 400
    server = {
        "id": uuid.uuid4().hex[:8],
        "name": name,
        "npm_url": npm_url,
        "npm_username": npm_username,
        "npm_password": npm_password,
    }
    servers = load_servers()
    servers.append(server)
    save_servers(servers)
    return jsonify({"id": server["id"]}), 201


@app.route("/api/servers/<server_id>", methods=["PUT"])
def api_servers_update(server_id):
    body = flask_request.get_json() or {}
    servers = load_servers()
    for s in servers:
        if s["id"] == server_id:
            s["name"] = body.get("name", s["name"]).strip() or s["name"]
            s["npm_url"] = body.get("npm_url", s["npm_url"]).strip() or s["npm_url"]
            s["npm_username"] = body.get("npm_username", s["npm_username"]).strip() or s["npm_username"]
            pwd = body.get("npm_password", _MASKED)
            if pwd != _MASKED:
                s["npm_password"] = pwd
            save_servers(servers)
            return jsonify({"status": "updated"})
    return jsonify({"error": "not found"}), 404


@app.route("/api/servers/<server_id>", methods=["DELETE"])
def api_servers_delete(server_id):
    servers = [s for s in load_servers() if s["id"] != server_id]
    save_servers(servers)
    return jsonify({"status": "deleted"})


@app.route("/api/files/<path:filename>", methods=["DELETE"])
def api_file_delete(filename):
    if not filename.endswith(".json") or "/" in filename or ".." in filename:
        return jsonify({"error": "invalid filename"}), 400
    path = os.path.join(EXPORT_DIR, filename)
    if not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    os.remove(path)
    _log(f"[files] Deleted {filename}")
    return jsonify({"status": "deleted"})


@app.route("/api/logs")
def api_logs():
    return jsonify({"lines": list(_log_lines)})


@app.route("/api/auth/verify2fa", methods=["POST"])
def api_verify2fa():
    global _pending_2fa
    if not _pending_2fa:
        return jsonify({"error": "no pending 2FA challenge"}), 400
    body = flask_request.get_json() or {}
    code = body.get("code", "").strip()
    if not code:
        return jsonify({"error": "code required"}), 400
    server_id = _pending_2fa["server_id"]
    challenge_token = _pending_2fa["challenge_token"]
    server = _get_server(server_id)
    if not server:
        return jsonify({"error": "server not found"}), 404
    url = f"{server['npm_url'].rstrip('/')}/api/tokens/2fa"
    resp = requests.post(
        url,
        json={"challenge_token": challenge_token, "code": code},
        timeout=15,
    )
    if resp.status_code == 401:
        return jsonify({"error": "Invalid OTP code — check your authenticator app"}), 401
    resp.raise_for_status()
    data = resp.json()
    _set_session_token(server_id, data["token"], data["expires"])
    _pending_2fa = None
    _log("[auth] 2FA verified — session token cached")
    return jsonify({"status": "authenticated", "server_id": server_id})


@app.route("/api/auth/dismiss2fa", methods=["POST"])
def api_dismiss2fa():
    global _pending_2fa
    _pending_2fa = None
    return jsonify({"status": "dismissed"})


@app.route("/api/export", methods=["POST"])
def api_export():
    global _op_running
    body = flask_request.get_json() or {}
    server_id = body.get("server_id", "").strip()
    server = _get_server(server_id)
    if not server:
        return jsonify({"error": "server not found"}), 404
    if not _op_lock.acquire(blocking=False):
        return jsonify({"error": "Operation already in progress"}), 409
    _op_running = True

    def run():
        global _op_running, _pending_2fa
        try:
            export_all(server)
        except TwoFactorRequired as exc:
            _pending_2fa = {"challenge_token": exc.challenge_token, "server_id": server["id"]}
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
    global _op_running
    body = flask_request.get_json() or {}
    server_id = body.get("server_id", "").strip()
    filename = body.get("filename", "").strip()
    if not filename:
        return jsonify({"error": "filename required"}), 400
    server = _get_server(server_id)
    if not server:
        return jsonify({"error": "server not found"}), 404
    if not _op_lock.acquire(blocking=False):
        return jsonify({"error": "Operation already in progress"}), 409
    _op_running = True

    def run():
        global _op_running, _pending_2fa
        try:
            import_all(server, filename)
        except TwoFactorRequired as exc:
            _pending_2fa = {"challenge_token": exc.challenge_token, "server_id": server["id"]}
            _log("[auth] 2FA required — enter your code in the prompt")
        except Exception as exc:
            _log(f"[import] ERROR: {exc}")
        finally:
            _op_running = False
            _op_lock.release()

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


def main():
    _migrate_legacy_config()
    _log(f"[server] Starting on port {INGRESS_PORT}")
    app.run(host="0.0.0.0", port=INGRESS_PORT, threaded=True)


if __name__ == "__main__":
    main()
