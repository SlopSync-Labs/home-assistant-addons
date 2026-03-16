<!-- markdownlint-disable MD041 -->
![Version][version-shield]
![Project Stage][project-stage-shield]
![Maintained][maintenance-shield]

[![Community Forum][forum-shield]][forum]
[![Buy me a coffee][buymeacoffee-shield]][buymeacoffee]

# NPM Export Import

Back up and restore your [Nginx Proxy Manager](https://nginxproxymanager.com/) configuration via a built-in web UI. Export files are stored as JSON in Home Assistant's shared `/share/npm-export-import/` folder.

## What Gets Exported / Imported

| Entity | Exported | Imported | Notes |
| --- | --- | --- | --- |
| Proxy Hosts | Yes | Yes | Full config including custom Nginx |
| Redirection Hosts | Yes | Yes | |
| TCP/UDP Streams | Yes | Yes | |
| Access Lists | Yes | Yes | HTTP Basic Auth + IP rules |
| SSL Certificates (Let's Encrypt) | Yes | Yes | Restored as custom certs — see note below |
| SSL Certificates (custom/uploaded) | No | No | Stored outside the shared volume |
| Users | No | No | NPM API does not support creating users with known passwords |

## Configuration

NPM server connections are managed in the add-on web UI under the **Settings** tab.
Each server entry requires a name, URL, username, and password. Multiple servers can
be added — use the **Source Server** and **Target Server** dropdowns on the
Operations tab to select which NPM instance to export from or import into.

## Usage

Open the add-on web UI from the Home Assistant sidebar or the add-on page.

### Export

Click **Export Now**. The add-on authenticates to NPM, fetches all configuration, and writes a timestamped JSON file:

```text
/share/npm-export-import/npm-export-20260101T120000Z.json
```

### Import

Previously exported files appear in the **Import** section of the UI. Click **Import** next to the file you want to restore.

The import runs in this order to preserve references:

1. SSL certificates (from exported cert files)
2. Access lists
3. Proxy hosts (with remapped access list and certificate IDs)
4. Redirection hosts
5. Streams

**Important:** Import creates new entries — it does not check for duplicates. Run against a fresh NPM instance or one you have already cleared.

## SSL Certificate Notes

This add-on and the `nginx-proxy-manager` add-on both map HA's shared `/ssl/` volume. The NPM add-on stores Let's Encrypt certificate files (including private keys) at `/ssl/nginxproxymanager/live/npm-{id}/`, making them accessible to this add-on for backup.

On import, Let's Encrypt certificates are restored as **custom (uploaded) certificates**. This means:

- The cert and private key are fully restored and functional immediately
- **Auto-renewal via Let's Encrypt will not work** for the restored cert entry
- After migration, it is recommended to delete the restored cert entry and re-request a fresh Let's Encrypt certificate for each domain in the NPM UI

Custom certificates (uploaded manually to NPM) are stored in the NPM add-on's private data volume, which is not accessible to other add-ons. These cannot be exported and must be re-uploaded manually after migration.

## File Location

Export files land in `/share/npm-export-import/` on the HA host, accessible via:

- **Samba add-on** — browse to the `share` folder
- **SSH add-on** — `/share/npm-export-import/`

[version-shield]: https://img.shields.io/badge/version-0.1.22-blue.svg
[project-stage-shield]: https://img.shields.io/badge/project%20stage-experimental-yellow.svg
[maintenance-shield]: https://img.shields.io/maintenance/yes/2026.svg
[forum-shield]: https://img.shields.io/badge/community-forum-brightgreen.svg
[forum]: https://community.home-assistant.io
[buymeacoffee-shield]: https://img.shields.io/badge/buy%20me%20a%20coffee-donate-yellow.svg
[buymeacoffee]: https://www.buymeacoffee.com/slopsynclabs
