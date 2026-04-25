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
OXYJWT_DOCS_PORT=8080 docker compose up -d --build
```
