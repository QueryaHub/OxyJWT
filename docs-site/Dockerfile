FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt mkdocs.yml README.md ./
COPY docs ./docs

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && mkdocs build --strict --site-dir /site

FROM nginx:1.27-alpine

COPY --from=builder /site /usr/share/nginx/html

EXPOSE 80
