# ═══════════════════════════════════════════════════════
# NCMSoft Website — Dockerfile
# Node.js Express uygulaması (ncmteknoloji.com)
# ═══════════════════════════════════════════════════════

FROM node:22-alpine

WORKDIR /app

# Bağımlılıkları kopyala ve yükle
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Uygulama dosyalarını kopyala
COPY . .

# Data dizinini oluştur (SQLite için)
RUN mkdir -p /app/data

# Production ortamı
ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

# Sağlık kontrolü
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/ || exit 1

CMD ["node", "server.js"]

