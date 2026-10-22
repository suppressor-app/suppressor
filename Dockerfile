# Pinned to a patched release: Node 22.23.4 fixes the October 21, 2026 security issues (Brotli RCE,
# TLS hostname-check bypasses, DNS truncation) and drops the compromised eMudhra intermediate CA.
FROM node:22.23.4-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
# On-device voice typing: fetch the speech model + runtime so we host them ourselves (non-fatal).
RUN node scripts/fetch-voice.mjs || true
# Room data lives here. Mount a persistent volume at /data in production.
ENV DATA_DIR=/data
RUN mkdir -p /data
# Runs as root so it can write to platform volumes (Railway mounts /data as root).
EXPOSE 4021
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://localhost:'+(process.env.PORT||4021)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
