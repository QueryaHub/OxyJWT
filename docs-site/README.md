# OxyJWT Documentation

This directory is a standalone MkDocs documentation site for OxyJWT.

## Local development

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip -r requirements.txt
.venv/bin/mkdocs serve -f mkdocs.yml
```

`mkdocs serve` listens on **http://127.0.0.1:8001** (set in `mkdocs.yml` as `dev_addr`).

## Static build

```bash
.venv/bin/mkdocs build --strict
```

The generated files are written to `site/`.

## Docker (static site on port 8001)

The Compose file exposes Nginx on the host at **127.0.0.1:8001** (overridable with `OXYJWT_DOCS_PORT`):

```bash
docker compose up -d --build
```

The site is at **http://127.0.0.1:8001/**. Use a **reverse proxy** you already run on the host (Nginx, Caddy, Traefik, etc.) to terminate TLS and forward to that upstream, for example:

- `http://127.0.0.1:8001` with the appropriate `Host` header, or
- the same port if the proxy runs on the same machine.

There is no bundled ACME or second proxy in this repo: configure HTTPS and certificates in your existing stack.

**Optional:** to listen on all interfaces (e.g. for LAN testing), change `ports` in `docker-compose.yml` from `127.0.0.1:...` to `0.0.0.0:...`.

## Production (example)

1. Point DNS for your docs hostname at the server.
2. Run the docs container: `docker compose up -d --build` in this directory.
3. In your reverse proxy, add a `server` / route for the hostname and `proxy_pass` to `http://127.0.0.1:8001` (or the port you set).

## Copy

See also the [project README](../README.md) for a quick intro and links to key pages.
