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
- Ports `80` and `443` are open to the public internet (or HTTP-01 certificate issuance can fail).
- **Nothing else** should bind the **same** host ports that Caddy uses for this stack.

### “Bind for 0.0.0.0:80 failed: port is already allocated”

Port `80` (or `443`) on the machine is already used — often by another reverse proxy, OpenLiteSpeed, or a second Docker Compose project.

1. **Preferred if you already have a reverse proxy on 80/443**  
   Do not publish Caddy on the host. Run only the static site, or add an upstream in your **existing** proxy for `Host: oxyjwt.queryahub.com` to the Nginx in the `docs` service. Example: expose the docs container on `127.0.0.1:9080` and configure your main proxy to `proxy_pass` there with TLS. This stack is then a single `docs` service without the bundled `caddy` service, or Caddy is internal-only (no `ports:` on `caddy`).

2. **If this server should be the only listener on 80/443**  
   Stop or rebind the other service (for example, move it behind the same Caddy) so **this** Caddy can bind `80:80` and `443:443`.

3. **Temporary / non-standard host ports (not for public HTTPS on default ports)**  
   In `.env` you can set host ports, for example:
   `CADDY_HTTP_PORT=18080` and `CADDY_HTTPS_PORT=18443`.  
   Let’s Encrypt **HTTP-01** validation still expects port **80** on your **public** IP. If the world still hits another process on 80, certificates will not issue correctly unless you use a DNS challenge (not configured in the bundled `Caddyfile`) or terminate TLS in front of this Caddy.
