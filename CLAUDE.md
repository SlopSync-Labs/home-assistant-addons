# CLAUDE.md — Home Assistant Apps

This file gives Claude Code context for working in this repository.

## What This Repo Is

A Home Assistant (HA) third-party app repository maintained by **SlopSync-Labs**.
Each top-level directory (except hidden dirs and root-level scripts) is a self-contained
HA app. The repo is installable directly from HA's app store via its
GitHub URL.

## Repository Layout

```text
/
├── repository.yaml          # HA repository manifest (name, url, maintainer)
├── build_scaffold.sh        # Interactive script to scaffold new apps
├── LICENSE                  # MIT, copyright SlopSync-Labs
├── README.md
├── CLAUDE.md                # This file
└── <app-slug>/              # One directory per app
  ├── config.json          # HA app manifest (required)
    ├── Dockerfile           # Container definition (required)
    ├── run.sh               # Entrypoint script (required)
    └── README.md            # App documentation
```

## Creating a New App

Always use the scaffold script — do not create app directories by hand:

```bash
./build_scaffold.sh [optional-slug]
```

After scaffolding, the typical implementation workflow is:

1. Edit `config.json` — set name, version, description, ports, options/schema
2. Implement `run.sh` — replace the stub with real startup logic
3. Adjust `Dockerfile` — swap base image if needed, add dependencies
4. Write `README.md` — document what the app does, how to configure it

## App Manifest (`config.json`) Key Fields

| Field | Notes |
| --- | --- |
| `name` | Human-readable display name |
| `slug` | Machine identifier — must match directory name |
| `version` | Semver string, start at `0.1.0` |
| `arch` | Always include `["amd64", "armv7", "aarch64"]` at minimum |
| `ports` | Map of `"container_port/proto": host_port` |
| `options` / `schema` | User-configurable values and their types |
| `startup` | `"services"` for long-running apps |
| `boot` | `"auto"` to start on HA boot |

## Conventions

- **Slugs**: lowercase, alphanumeric, hyphens or underscores only —
  validated by the scaffold script
- **Base images**: `python:3.x-alpine` for Python workloads;
  `ghcr.io/home-assistant/<arch>-base` for shell-only apps
- **Ports**: document every exposed port in both `config.json` and the app README
- **Scripts**: `run.sh` must be executable (`chmod +x`)
- **Versioning**: semver — bump patch for fixes, minor for new features,
  major for breaking changes
- **Multi-arch**: prefer images and base containers that support amd64, armv7,
  and aarch64

## What NOT to Do

- Do not create app directories by hand — use `build_scaffold.sh`
- Do not edit `repository.yaml` URL or maintainer fields without also
  updating the GitHub remote
- Do not hardcode architecture-specific paths in `run.sh` — keep scripts portable
- Do not skip updating `config.json` when adding options —
  HA will reject undeclared options at runtime

## Key External References

- [Home Assistant App Development Docs](https://developers.home-assistant.io/docs/add-ons)
- [HA App Config Reference](https://developers.home-assistant.io/docs/add-ons/configuration)
- [Base Images (ghcr.io/home-assistant)](https://github.com/home-assistant/docker-base)
