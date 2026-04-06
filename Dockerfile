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

# Persistent data volume
VOLUME ["/app/data"]

ENV NODE_ENV=production
ENV VAULT_DATA_DIR=/app/data
ENV PORT=3900

EXPOSE 3900

# Run as non-root
RUN addgroup -S vault && adduser -S vault -G vault
RUN chown -R vault:vault /app
USER vault

CMD ["node", "dist/index.js"]
