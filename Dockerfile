# ── Stage 1: deps ──────────────────────────────────────────────────────────────
FROM node:20-slim AS deps

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

# ── Stage 2: runtime ───────────────────────────────────────────────────────────
FROM node:20-slim

# node-tls-client bundles a Go shared library — needs basic C runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy deps from stage 1
COPY --from=deps /app/node_modules ./node_modules

# Copy source
COPY . .

# Ensure logs dir exists
RUN mkdir -p logs

# Drop root — run as node user
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', r => process.exit(r.statusCode === 200 || r.statusCode === 503 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
