# OxyJWT Documentation

This directory is a standalone MkDocs documentation site for OxyJWT.

## Local Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip -r requirements.txt
.venv/bin/mkdocs serve
```

The site is available at `http://localhost:8000`.

## Static Build

```bash
.venv/bin/mkdocs build --strict
```

The generated files are written to `site/`.

## Docker Compose

```bash
docker compose up -d --build
```

Override the host port with:

```bash
OXYJWT_DOCS_PORT=8001 docker compose up -d --build
```

Without an override, Docker Compose serves the static docs at `http://localhost:8001`.

## Production Domain

Point `oxyjwt.queryahub.com` to your server:

```text
oxyjwt.queryahub.com.  A     YOUR_SERVER_IPV4
oxyjwt.queryahub.com.  AAAA  YOUR_SERVER_IPV6
```

Then start the production stack with Caddy. Caddy listens on ports `80` and `443` and automatically issues a Let's Encrypt certificate:

```bash
cp .env.example .env
docker compose -f docker-compose.prod.yml --env-file .env up -d --build
```

The site will be available at `https://oxyjwt.queryahub.com`.

Server requirements:

- DNS for `oxyjwt.queryahub.com` points to this server.
- Ports `80` and `443` are open.
- No other service is already using ports `80` or `443`.
