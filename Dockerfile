FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Runtime deps only (includes better-sqlite3 native module)
COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/public ./dist/public

# Persistent data and backup volumes
VOLUME ["/app/data", "/app/backups"]

ENV NODE_ENV=production
ENV VAULT_DATA_DIR=/app/data
ENV PORT=3900

EXPOSE 3900

# Run migrations then start the server
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run as non-root
RUN addgroup -S vault && adduser -S vault -G vault
RUN chown -R vault:vault /app
USER vault

# Healthcheck uses readiness endpoint so draining instances are marked unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
	CMD wget -qO- http://localhost:${PORT:-3900}/api/ready || exit 1

ENTRYPOINT ["sh", "/usr/local/bin/docker-entrypoint.sh"]
